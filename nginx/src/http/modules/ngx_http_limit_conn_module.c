// annotated by chrono since 2018
//
// * ngx_http_limit_conn_zone
// * ngx_http_limit_conn_cleanup
// * ngx_http_limit_conn_handler

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_LIMIT_CONN_PASSED            1
#define NGX_HTTP_LIMIT_CONN_REJECTED          2
#define NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN  3


// 第一个成员与ngx_rbtree_node_t的color相同
// 拼接在node后面，实现共用内存
typedef struct {
    // rbtree的最后一个成员
    u_char                        color;

    // 下面是自己的数据

    // key的长度，对应最后的data[1]
    u_char                        len;

    // 连接数，不会超过2^16=65535
    u_short                       conn;

    // 用来存放字符串，1只是示意
    // 之后会分配足够的内存，len大小
    u_char                        data[1];
} ngx_http_limit_conn_node_t;


// 内存池清理函数
// 减少连接数
// 不能用log阶段，因为log只是请求结束
typedef struct {
    // 关联的共享内存
    ngx_shm_zone_t               *shm_zone;

    // 关联的红黑树节点
    ngx_rbtree_node_t            *node;
} ngx_http_limit_conn_cleanup_t;


// 一个共享内存限制连接的基本信息
// 红黑树
// 存放在共享内存里
// ctx = limit->shm_zone->data;
// 与limit_req不同，没有用队列
// 因为不需要lru管理，在断连时减数
typedef struct {
    ngx_rbtree_t                  rbtree;

    // 存储在红黑树里区分请求的key
    // 例如$binary_remote_addr
    ngx_http_complex_value_t   key;
    ngx_rbtree_node_t             sentinel;
} ngx_http_limit_conn_shctx_t;


typedef struct {
    ngx_http_limit_conn_shctx_t  *sh;
    ngx_slab_pool_t              *shpool;
    ngx_http_complex_value_t      key;
} ngx_http_limit_conn_ctx_t;


// 限流的信息，关联到各个共享内存
typedef struct {
    // 对应的共享内存
    // 取共享内存里的限速信息
    // ctx = limit->shm_zone->data;
    ngx_shm_zone_t               *shm_zone;

    // 限连数
    ngx_uint_t                    conn;
} ngx_http_limit_conn_limit_t;


// 配置结构体
typedef struct {
    // 限流信息的多个数组
    // 元素类型是ngx_http_limit_conn_limit_t
    ngx_array_t                   limits;

    // 日志级别
    ngx_uint_t                    log_level;

    // 返回的状态码
    ngx_uint_t                    status_code;
    ngx_flag_t                    dry_run;
} ngx_http_limit_conn_conf_t;


// 共享内存红黑树里查找
static ngx_rbtree_node_t *ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree,
    ngx_str_t *key, uint32_t hash);

// 清理函数，减少连接数
static void ngx_http_limit_conn_cleanup(void *data);

// 运行本模块的清理函数
static ngx_inline void ngx_http_limit_conn_cleanup_all(ngx_pool_t *pool);

static ngx_int_t ngx_http_limit_conn_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_limit_conn_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

// 解析共享内存指令
// 配置共享内存，使用的key等
static char *ngx_http_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_conn_add_variables(ngx_conf_t *cf);

// 在preaccess阶段，rewrite之后
static ngx_int_t ngx_http_limit_conn_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_conn_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_limit_conn_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_limit_conn_commands[] = {

    { ngx_string("limit_conn_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_conn"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_limit_conn,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_conn_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, log_level),
      &ngx_http_limit_conn_log_levels },

    { ngx_string("limit_conn_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, status_code),
      &ngx_http_limit_conn_status_bounds },

    { ngx_string("limit_conn_dry_run"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_conn_conf_t, dry_run),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_conn_module_ctx = {
    ngx_http_limit_conn_add_variables,     /* preconfiguration */

    // 在preaccess阶段，rewrite之后
    ngx_http_limit_conn_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_conn_create_conf,       /* create location configuration */
    ngx_http_limit_conn_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_limit_conn_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_conn_module_ctx,       /* module context */
    ngx_http_limit_conn_commands,          /* module directives */
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


static ngx_http_variable_t  ngx_http_limit_conn_vars[] = {

    { ngx_string("limit_conn_status"), NULL,
      ngx_http_limit_conn_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_limit_conn_status[] = {
    ngx_string("PASSED"),
    ngx_string("REJECTED"),
    ngx_string("REJECTED_DRY_RUN")
};


// preaccess阶段执行，检查共享内存，限速
static ngx_int_t
ngx_http_limit_conn_handler(ngx_http_request_t *r)
{
    size_t                          n;
    uint32_t                        hash;
    ngx_str_t                       key;
    ngx_uint_t                      i;
    ngx_rbtree_node_t              *node;
    ngx_pool_cleanup_t             *cln;
    ngx_http_limit_conn_ctx_t      *ctx;
    ngx_http_limit_conn_node_t     *lc;
    ngx_http_limit_conn_conf_t     *lccf;
    ngx_http_limit_conn_limit_t    *limits;
    ngx_http_limit_conn_cleanup_t  *lccln;

    // 置标志位，本模块不再处理
    // 标记了主请求，限制子请求
    if (r->main->limit_conn_status) {
        // preaccess阶段此值表示继续处理
        // 不会拒绝请求
        return NGX_DECLINED;
    }

    // 取当前配置
    lccf = ngx_http_get_module_loc_conf(r, ngx_http_limit_conn_module);

    // 取限速信息数组
    limits = lccf->limits.elts;

    // 逐个检查之前设置的共享内存
    for (i = 0; i < lccf->limits.nelts; i++) {

        // 取共享内存里的限速信息
        ctx = limits[i].shm_zone->data;

        // 计算key
        // 例如$binary_remote_addr
        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        // 置标志位，本模块不再处理
        // 标记了主请求，限制子请求
        r->main->limit_conn_status = NGX_HTTP_LIMIT_CONN_PASSED;

        // crc32作为红黑树key
        hash = ngx_crc32_short(key.data, key.len);

        // 取内存池指针
        // 互斥锁
        ngx_shmtx_lock(&ctx->shpool->mutex);

        // 共享内存红黑树里查找
        node = ngx_http_limit_conn_lookup(&ctx->sh->rbtree, &key, hash);

        // 红黑树里没找到，需要创建新节点
        if (node == NULL) {

            // 需要新建一个节点
            // 先是rbtree_node
            // 然后是conn_node
            // 最后是字符串
            n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(ngx_http_limit_conn_node_t, data)
                + key.len;

            // 在共享内存里分配内存
            node = ngx_slab_alloc_locked(ctx->shpool, n);

            // 无法创建节点就需要清理
            if (node == NULL) {
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                ngx_http_limit_conn_cleanup_all(r->pool);

                if (lccf->dry_run) {
                    r->main->limit_conn_status =
                                          NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN;
                    return NGX_DECLINED;
                }

                r->main->limit_conn_status = NGX_HTTP_LIMIT_CONN_REJECTED;

                return lccf->status_code;
            }

            // 指针转化，红黑树节点后面是自己的数据
            lc = (ngx_http_limit_conn_node_t *) &node->color;

            // 红黑树的key，之前计算的crc32
            node->key = hash;

            // key的长度
            lc->len = (u_char) key.len;

            // 新连接，值是1
            lc->conn = 1;

            // 拷贝key字符串
            ngx_memcpy(lc->data, key.data, key.len);

            // 插入红黑树
            ngx_rbtree_insert(&ctx->sh->rbtree, node);

        } else {
            // 找到

            // 指针转化，红黑树节点后面是自己的数据
            lc = (ngx_http_limit_conn_node_t *) &node->color;

            // 比较当前的连接数是否超过
            if ((ngx_uint_t) lc->conn >= limits[i].conn) {

                // 超过就解锁，不需要再用共享内存了
                ngx_shmtx_unlock(&ctx->shpool->mutex);

                ngx_log_error(lccf->log_level, r->connection->log, 0,
                              "limiting connections%s by zone \"%V\"",
                              lccf->dry_run ? ", dry run," : "",
                              &limits[i].shm_zone->shm.name);

                // 清理，然后拒绝连接
                ngx_http_limit_conn_cleanup_all(r->pool);

                if (lccf->dry_run) {
                    r->main->limit_conn_status =
                                          NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN;
                    return NGX_DECLINED;
                }

                r->main->limit_conn_status = NGX_HTTP_LIMIT_CONN_REJECTED;

                return lccf->status_code;
            }

            // 没超过，加1
            lc->conn++;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        // 解锁共享内存
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        // 加入连接关闭的清理动作
        cln = ngx_pool_cleanup_add(r->pool,
                                   sizeof(ngx_http_limit_conn_cleanup_t));
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // 清理函数，减少连接数
        cln->handler = ngx_http_limit_conn_cleanup;
        lccln = cln->data;

        // 记录要操作的节点
        lccln->shm_zone = limits[i].shm_zone;
        lccln->node = node;
    }

    return NGX_DECLINED;
}


static void
ngx_http_limit_conn_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_limit_conn_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (ngx_http_limit_conn_node_t *) &node->color;
            lcnt = (ngx_http_limit_conn_node_t *) &temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


// 共享内存红黑树里查找
static ngx_rbtree_node_t *
ngx_http_limit_conn_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_limit_conn_node_t  *lcn;

    // 取共享内存里的红黑树
    node = rbtree->root;
    sentinel = rbtree->sentinel;

    // 红黑树查找
    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        // key相同，但还要判断字符串

        // 指针转化，红黑树节点后面是自己的数据
        lcn = (ngx_http_limit_conn_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        // key相同就找到
        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    // 遍历完未找到
    return NULL;
}


// 清理函数，减少连接数
static void
ngx_http_limit_conn_cleanup(void *data)
{
    ngx_http_limit_conn_cleanup_t  *lccln = data;

    ngx_rbtree_node_t           *node;
    ngx_http_limit_conn_ctx_t   *ctx;
    ngx_http_limit_conn_node_t  *lc;

    // 取红黑树
    ctx = lccln->shm_zone->data;

    // 关联的计数节点
    node = lccln->node;

    // 指针转化，红黑树节点后面是自己的数据
    lc = (ngx_http_limit_conn_node_t *) &node->color;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, lccln->shm_zone->shm.log, 0,
                   "limit conn cleanup: %08Xi %d", node->key, lc->conn);

    // 减少连接数
    lc->conn--;

    // 无连接删除节点，节约内存
    if (lc->conn == 0) {
        ngx_rbtree_delete(&ctx->sh->rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}


// 运行本模块的清理函数
static ngx_inline void
ngx_http_limit_conn_cleanup_all(ngx_pool_t *pool)
{
    ngx_pool_cleanup_t  *cln;

    cln = pool->cleanup;

    while (cln && cln->handler == ngx_http_limit_conn_cleanup) {
        ngx_http_limit_conn_cleanup(cln->data);
        cln = cln->next;
    }

    pool->cleanup = cln;
}


// 模块自己的初始化共享内存
// 红黑树放进共享内存池对象里，方便使用
// 拼共享内存的名字
// 作为共享内存池的日志记录用
static ngx_int_t
ngx_http_limit_conn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    // 一个共享内存限制连接的基本信息
    ngx_http_limit_conn_ctx_t  *octx = data;

    size_t                      len;
    ngx_http_limit_conn_ctx_t  *ctx;

    // 共享内存限制请求的基本信息
    ctx = shm_zone->data;

    // 旧数据处理
    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    // slab内存池
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    // 已存在则复用旧数据
    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    // 创建红黑树结构体
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_conn_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    // 关联到共享内存池
    ctx->shpool->data = ctx->sh;

    // 初始化红黑树
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_limit_conn_rbtree_insert_value);

    // 拼共享内存的名字
    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    // 作为共享内存池的日志记录用
    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    // 作为共享内存池的日志记录用
    ngx_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_conn_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_conn_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_limit_conn_status[r->main->limit_conn_status - 1].len;
    v->data = ngx_http_limit_conn_status[r->main->limit_conn_status - 1].data;

    return NGX_OK;
}


static void *
ngx_http_limit_conn_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_conn_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;
    conf->dry_run = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_limit_conn_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_conn_conf_t *prev = parent;
    ngx_http_limit_conn_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->log_level, prev->log_level, NGX_LOG_ERR);
    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);

    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NGX_CONF_OK;
}


// 解析共享内存指令
// 配置共享内存，使用的key等
static char *
ngx_http_limit_conn_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_conn_ctx_t         *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    // 一个共享内存限制连接的基本信息
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_conn_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    // 编译key变量
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    // 解析各个参数
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    // 添加共享内存
    // 之后在init_cycle里创建并初始化
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_conn_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    // 有data，就是初始化过了
    if (shm_zone->data) {
        ctx = shm_zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NGX_CONF_ERROR;
    }

    // 模块自己的初始化函数
    // 红黑树放进共享内存池对象里，方便使用
    // 拼共享内存的名字
    // 作为共享内存池的日志记录用
    shm_zone->init = ngx_http_limit_conn_init_zone;

    // 设置data
    // 共享内存限制连接的基本信息
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


// 设置location使用的共享内存
static char *
ngx_http_limit_conn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_shm_zone_t               *shm_zone;
    ngx_http_limit_conn_conf_t   *lccf = conf;
    ngx_http_limit_conn_limit_t  *limit, *limits;

    ngx_str_t  *value;
    ngx_int_t   n;
    ngx_uint_t  i;

    value = cf->args->elts;

    // 根据名字找到之前添加的共享内存
    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_limit_conn_module);

    // 必须根据名字找到已经定义的共享内存
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    // 可以添加多个共享内存限制
    limits = lccf->limits.elts;

    // 没有则创建动态数组
    if (limits == NULL) {
        if (ngx_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(ngx_http_limit_conn_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    // 不能重复添加
    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    // 第二个参数是限制连接的数量
    n = ngx_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    // 必须用u_short
    if (n > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NGX_CONF_ERROR;
    }

    // 数组增加一个元素
    limit = ngx_array_push(&lccf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    // 加入共享内存等信息
    // 之后请求的preaccess时使用
    limit->conn = n;

    // 共享内存限制请求的基本信息
    // 注意 ctx = shm_zone->data;
    // 通过它就可以获取限制信息
    limit->shm_zone = shm_zone;

    return NGX_CONF_OK;
}


// 在preaccess阶段，rewrite之后
static ngx_int_t
ngx_http_limit_conn_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_limit_conn_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_conn_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_conn_handler;

    return NGX_OK;
}
