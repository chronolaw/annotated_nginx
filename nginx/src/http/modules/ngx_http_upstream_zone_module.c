// annotated by chrono since 2016
//
// * ngx_http_upstream_init_zone

/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_http_upstream_rr_peers_t *ngx_http_upstream_zone_copy_peers(
    ngx_slab_pool_t *shpool, ngx_http_upstream_srv_conf_t *uscf);
static ngx_http_upstream_rr_peer_t *ngx_http_upstream_zone_copy_peer(
    ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peer_t *src);


// 定义在upstream{}里的zone指令
// 声明一块共享内存
static ngx_command_t  ngx_http_upstream_zone_commands[] = {

    { ngx_string("zone"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_zone,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_zone_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_zone_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_zone_module_ctx,    /* module context */
    ngx_http_upstream_zone_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 在upstream{}里的zone指令
// 声明一块共享内存
static char *
ngx_http_upstream_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                         size;
    ngx_str_t                      *value;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_http_upstream_main_conf_t  *umcf;

    // 本upstream{}块的配置结构体，存储server信息
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    // upstream模块的主配置，存储所有的upstream{}配置
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    // 参数数组
    value = cf->args->elts;

    // 第0个值是指令名字
    // 第一个参数是zone名字
    if (!value[1].len) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    // 三个数组元素，后两个参数是名字和大小
    if (cf->args->nelts == 3) {
        size = ngx_parse_size(&value[2]);

        if (size == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        // 大小至少是8*4k=64k
        if (size < (ssize_t) (8 * ngx_pagesize)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "zone \"%V\" is too small", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {
        // 可以只有名字，没有大小
        // 这样会查找之前定义的zone，共用一块内存
        size = 0;
    }

    // 添加共享内存
    // 如果size==0,则查找之前定义的zone，共用一块内存
    // 在配置结构体里保存该指针
    uscf->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
                                           &ngx_http_upstream_module);
    if (uscf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    // 指定创建共享内存后调用的初始化函数
    uscf->shm_zone->init = ngx_http_upstream_init_zone;

    // 初始化函数使用main conf
    uscf->shm_zone->data = umcf;

    // 不允许重用，即重启后共享内存清空重建
    uscf->shm_zone->noreuse = 1;

    return NGX_CONF_OK;
}


// 创建共享内存后调用的初始化函数
static ngx_int_t
ngx_http_upstream_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                          len;
    ngx_uint_t                      i;
    ngx_slab_pool_t                *shpool;
    ngx_http_upstream_rr_peers_t   *peers, **peersp;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    // 取slab内存池
    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    // 初始化函数使用main conf
    umcf = shm_zone->data;

    // 取upstream{}数组
    uscfp = umcf->upstreams.elts;

    // 数据存在则重用
    // 可能是多个zone共用一块内存
    // 依据nginx官方文档，此字段仅用于windows
    // 在linux下可以不用考虑
    if (shm_zone->shm.exists) {
        peers = shpool->data;

        // 遍历所有的peers数组
        for (i = 0; i < umcf->upstreams.nelts; i++) {
            uscf = uscfp[i];

            // 如果不是自己则跳过
            if (uscf->shm_zone != shm_zone) {
                continue;
            }

            // 找到自己的peers

            // 更改upstream指针，指向共享内存地址
            // data指向ngx_http_upstream_rr_peers_t
            // backup/非backup服务器IP列表
            uscf->peer.data = peers;

            // 在共享内存里的下一组服务器列表
            peers = peers->zone_next;
        }

        return NGX_OK;
    }

    // 新建共享内存数据结构

    // 共享内存记录日志使用的ctx字符串
    len = sizeof(" in upstream zone \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in upstream zone \"%V\"%Z",
                &shm_zone->shm.name);


    /* copy peers to shared memory */

    // 共享内存池的data指针强制转换
    // 存储本配置块的的peers
    peersp = (ngx_http_upstream_rr_peers_t **) (void *) &shpool->data;

    // 遍历所有的peers数组
    // uscfp是upstream{}数组
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        // 取一个upstream{}
        uscf = uscfp[i];

        // 如果不是自己配置的共享内存则跳过
        // 即查找需要在本共享内存存储的upstream{}
        if (uscf->shm_zone != shm_zone) {
            continue;
        }

        // 找到需要存储的peers

        // 拷贝peers到共享内存
        // 实现“深”拷贝，里面的指针内容也拷贝
        peers = ngx_http_upstream_zone_copy_peers(shpool, uscf);
        if (peers == NULL) {
            return NGX_ERROR;
        }

        // 串起了多个peers
        *peersp = peers;
        peersp = &peers->zone_next;
    }

    return NGX_OK;
}


// 拷贝peers到共享内存
// 实现“深”拷贝，里面的指针内容也拷贝
static ngx_http_upstream_rr_peers_t *
ngx_http_upstream_zone_copy_peers(ngx_slab_pool_t *shpool,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_str_t                     *name;
    ngx_http_upstream_rr_peer_t   *peer, **peerp;
    ngx_http_upstream_rr_peers_t  *peers, *backup;

    // backup/非backup服务器IP列表
    peers = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
    if (peers == NULL) {
        return NULL;
    }

    // 拷贝整个结构体
    ngx_memcpy(peers, uscf->peer.data, sizeof(ngx_http_upstream_rr_peers_t));

    // upstream块的名字
    name = ngx_slab_alloc(shpool, sizeof(ngx_str_t));
    if (name == NULL) {
        return NULL;
    }

    // upstream块的名字
    name->data = ngx_slab_alloc(shpool, peers->name->len);
    if (name->data == NULL) {
        return NULL;
    }

    // upstream块的名字
    ngx_memcpy(name->data, peers->name->data, peers->name->len);
    name->len = peers->name->len;

    peers->name = name;

    // 关联到共享内存池
    peers->shpool = shpool;

    // 深拷贝非backup服务器IP列表
    for (peerp = &peers->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_http_upstream_zone_copy_peer(peers, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    // 没有backup服务器则结束
    if (peers->next == NULL) {
        goto done;
    }

    // 拷贝backup服务器IP列表
    backup = ngx_slab_alloc(shpool, sizeof(ngx_http_upstream_rr_peers_t));
    if (backup == NULL) {
        return NULL;
    }

    // 拷贝backup服务器IP列表
    ngx_memcpy(backup, peers->next, sizeof(ngx_http_upstream_rr_peers_t));

    backup->name = name;

    backup->shpool = shpool;

    // 深拷贝backup服务器IP列表
    for (peerp = &backup->peer; *peerp; peerp = &peer->next) {
        /* pool is unlocked */
        peer = ngx_http_upstream_zone_copy_peer(backup, *peerp);
        if (peer == NULL) {
            return NULL;
        }

        *peerp = peer;
    }

    peers->next = backup;

done:

    // 更改upstream指针，指向共享内存地址
    uscf->peer.data = peers;

    return peers;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_zone_copy_peer(ngx_http_upstream_rr_peers_t *peers,
    ngx_http_upstream_rr_peer_t *src)
{
    ngx_slab_pool_t              *pool;
    ngx_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;

    dst = ngx_slab_calloc_locked(pool, sizeof(ngx_http_upstream_rr_peer_t));
    if (dst == NULL) {
        return NULL;
    }

    if (src) {
        ngx_memcpy(dst, src, sizeof(ngx_http_upstream_rr_peer_t));
        dst->sockaddr = NULL;
        dst->name.data = NULL;
        dst->server.data = NULL;
    }

    dst->sockaddr = ngx_slab_calloc_locked(pool, sizeof(ngx_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = ngx_slab_calloc_locked(pool, NGX_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }

    if (src) {
        ngx_memcpy(dst->sockaddr, src->sockaddr, src->socklen);
        ngx_memcpy(dst->name.data, src->name.data, src->name.len);

        dst->server.data = ngx_slab_alloc_locked(pool, src->server.len);
        if (dst->server.data == NULL) {
            goto failed;
        }

        ngx_memcpy(dst->server.data, src->server.data, src->server.len);
    }

    return dst;

failed:

    if (dst->server.data) {
        ngx_slab_free_locked(pool, dst->server.data);
    }

    if (dst->name.data) {
        ngx_slab_free_locked(pool, dst->name.data);
    }

    if (dst->sockaddr) {
        ngx_slab_free_locked(pool, dst->sockaddr);
    }

    ngx_slab_free_locked(pool, dst);

    return NULL;
}
