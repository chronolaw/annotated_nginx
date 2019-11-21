// annotated by chrono since 2018
//
// * ngx_http_limit_req_init_zone
// * ngx_http_limit_req_delay
// * ngx_http_limit_req_lookup
// * ngx_http_limit_req_handler

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_LIMIT_REQ_PASSED            1
#define NGX_HTTP_LIMIT_REQ_DELAYED           2
#define NGX_HTTP_LIMIT_REQ_REJECTED          3
#define NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN   4
#define NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN  5


// 第一个成员与ngx_rbtree_node_t的color相同
// 拼接在node后面，实现共用内存
// nginx里常用的手法，类似继承
// 红黑树按字符串key查找
// 队列时间序，即lru，最后的可以过期释放
typedef struct {
    // rbtree的最后一个成员
    u_char                       color;

    // 下面是自己的数据

    // 对应ngx_rbtree_node_t的data[1]
    u_char                       dummy;

    // key的长度，对应最后的data[1]
    u_short                      len;

    // 节点也串成一个lru队列
    ngx_queue_t                  queue;

    // 最后一次访问的时间
    ngx_msec_t                   last;

    /* integer value, 1 corresponds to 0.001 r/s */
    // 放大了1000倍，方便计算
    ngx_uint_t                   excess;

    // 引用计数
    ngx_uint_t                   count;

    // 用来存放字符串，1只是示意
    // 之后会分配足够的内存，len大小
    u_char                       data[1];
} ngx_http_limit_req_node_t;


// 红黑树，同时用队列
// 存放在共享内存里
// ctx = limit->shm_zone->data;
// 红黑树按字符串key查找
// 队列时间序，即lru，最后的可以过期释放
typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
} ngx_http_limit_req_shctx_t;


// 一个共享内存限制请求的基本信息
typedef struct {
    // 共享内存里的红黑树
    ngx_http_limit_req_shctx_t  *sh;

    // 共享内存池
    ngx_slab_pool_t             *shpool;

    /* integer value, 1 corresponds to 0.001 r/s */
    // 放大了1000倍，方便计算
    ngx_uint_t                   rate;

    // 存储在红黑树里区分请求的key
    // 例如$binary_remote_addr
    ngx_http_complex_value_t     key;

    ngx_http_limit_req_node_t   *node;
} ngx_http_limit_req_ctx_t;


// 限流的信息，关联到各个共享内存
typedef struct {
    // 对应的共享内存
    // 取共享内存里的限速信息
    // ctx = limit->shm_zone->data;
    ngx_shm_zone_t              *shm_zone;

    /* integer value, 1 corresponds to 0.001 r/s */

    // 超过限速值的容忍值，即允许处理的突发流量
    // 配置文件里的值，放大了1000倍，方便计算
    ngx_uint_t                   burst;

    // 是否延迟
    // 0表示burst数量的请求仍然立即处理
    // 1表示burst数量的请求需要延迟处理，保证限速
    // 1.15.7之前是ngx_uint_t                   nodelay; /* unsigned  nodelay:1 */
    ngx_uint_t                   delay;
} ngx_http_limit_req_limit_t;


// 配置结构体
typedef struct {
    // 限流信息的多个数组
    ngx_array_t                  limits;

    // 日志级别
    ngx_uint_t                   limit_log_level;
    ngx_uint_t                   delay_log_level;

    // 返回的状态码
    ngx_uint_t                   status_code;

    // 1.17.1，空运行模式
    ngx_flag_t                   dry_run;
} ngx_http_limit_req_conf_t;


// 写事件加入定时器，稍后被触发
// 重新注册读写事件
// 可写时继续走处理流程，各个模块处理
static void ngx_http_limit_req_delay(ngx_http_request_t *r);

// 取共享内存里的红黑树
// 计算上次访问的时间间隔计算超出值
static ngx_int_t ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit,
    ngx_uint_t hash, ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account);

static ngx_msec_t ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits,
    ngx_uint_t n, ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit);

static void ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx,
    ngx_uint_t n);

static ngx_int_t ngx_http_limit_req_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_limit_req_create_conf(ngx_conf_t *cf);
static char *ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

// 解析共享内存指令
static char *ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 设置使用的共享内存
static char *ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_limit_req_add_variables(ngx_conf_t *cf);

// 在preaccess阶段，rewrite之后
static ngx_int_t ngx_http_limit_req_init(ngx_conf_t *cf);


static ngx_conf_enum_t  ngx_http_limit_req_log_levels[] = {
    { ngx_string("info"), NGX_LOG_INFO },
    { ngx_string("notice"), NGX_LOG_NOTICE },
    { ngx_string("warn"), NGX_LOG_WARN },
    { ngx_string("error"), NGX_LOG_ERR },
    { ngx_null_string, 0 }
};


static ngx_conf_num_bounds_t  ngx_http_limit_req_status_bounds = {
    ngx_conf_check_num_bounds, 400, 599
};


static ngx_command_t  ngx_http_limit_req_commands[] = {

    // 解析共享内存指令
    // 配置共享内存，使用的key等
    { ngx_string("limit_req_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_limit_req_zone,
      0,
      0,
      NULL },

    { ngx_string("limit_req"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_limit_req,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_req_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, limit_log_level),
      &ngx_http_limit_req_log_levels },

    { ngx_string("limit_req_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, status_code),
      &ngx_http_limit_req_status_bounds },

    { ngx_string("limit_req_dry_run"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_limit_req_conf_t, dry_run),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_req_module_ctx = {
    ngx_http_limit_req_add_variables,      /* preconfiguration */

    // 在preaccess阶段，rewrite之后
    ngx_http_limit_req_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_limit_req_create_conf,        /* create location configuration */
    ngx_http_limit_req_merge_conf          /* merge location configuration */
};


ngx_module_t  ngx_http_limit_req_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_req_module_ctx,        /* module context */
    ngx_http_limit_req_commands,           /* module directives */
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


static ngx_http_variable_t  ngx_http_limit_req_vars[] = {

    { ngx_string("limit_req_status"), NULL,
      ngx_http_limit_req_status_variable, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

      ngx_http_null_variable
};


static ngx_str_t  ngx_http_limit_req_status[] = {
    ngx_string("PASSED"),
    ngx_string("DELAYED"),
    ngx_string("REJECTED"),
    ngx_string("DELAYED_DRY_RUN"),
    ngx_string("REJECTED_DRY_RUN")
};


// preaccess阶段执行，检查共享内存，限速
static ngx_int_t
ngx_http_limit_req_handler(ngx_http_request_t *r)
{
    uint32_t                     hash;
    ngx_str_t                    key;
    ngx_int_t                    rc;
    ngx_uint_t                   n, excess;
    ngx_msec_t                   delay;
    ngx_http_limit_req_ctx_t    *ctx;
    ngx_http_limit_req_conf_t   *lrcf;
    ngx_http_limit_req_limit_t  *limit, *limits;

    // 置标志位，本模块不再处理
    // 标记了主请求，限制子请求
    if (r->main->limit_req_status) {
        // preaccess阶段此值表示继续处理
        // 不会拒绝请求
        return NGX_DECLINED;
    }

    // 取当前配置
    lrcf = ngx_http_get_module_loc_conf(r, ngx_http_limit_req_module);

    // 取限速信息数组
    limits = lrcf->limits.elts;

    excess = 0;

    // preaccess阶段此值表示继续处理
    // 不会拒绝请求
    rc = NGX_DECLINED;

#if (NGX_SUPPRESS_WARN)
    limit = NULL;
#endif

    // 逐个检查之前设置的共享内存
    for (n = 0; n < lrcf->limits.nelts; n++) {

        // 数组里的第n个元素
        limit = &limits[n];

        // 取共享内存里的限速信息
        ctx = limit->shm_zone->data;

        // 计算key
        // 例如$binary_remote_addr
        if (ngx_http_complex_value(r, &ctx->key, &key) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 65535) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 65535 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }

        // crc32作为红黑树key
        hash = ngx_crc32_short(key.data, key.len);

        // 锁定共享内存再操作
        ngx_shmtx_lock(&ctx->shpool->mutex);

        // 共享内存红黑树里查找
        // 数组的最后一个元素才会做记录操作
        rc = ngx_http_limit_req_lookup(limit, hash, &key, &excess,
                                       (n == lrcf->limits.nelts - 1));

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit_req[%ui]: %i %ui.%03ui",
                       n, rc, excess / 1000, excess % 1000);

        // again要继续循环，看其他的共享内存限制
        // 最后一个数组会返回ok
        // 返回busy就拒绝请求
        if (rc != NGX_AGAIN) {
            break;
        }
    }

    // preaccess节点此值表示继续处理
    // 不会拒绝请求
    // ngx_http_limit_req_lookup不会返回decline
    // 只有空数组才会不执行循环，rc不变
    if (rc == NGX_DECLINED) {
        // 让下一个模块继续处理
        return NGX_DECLINED;
    }

    // 置标志位，本模块不再处理
    // 标记了主请求，限制子请求

    // BUSY/ERROR则拒绝请求
    // 返回指定的状态码
    if (rc == NGX_BUSY || rc == NGX_ERROR) {

        if (rc == NGX_BUSY) {
            ngx_log_error(lrcf->limit_log_level, r->connection->log, 0,
                        "limiting requests%s, excess: %ui.%03ui by zone \"%V\"",
                        lrcf->dry_run ? ", dry run" : "",
                        excess / 1000, excess % 1000,
                        &limit->shm_zone->shm.name);
        }

        // 找是哪个共享内存设置了限速
        while (n--) {
            // 取共享内存里的限速信息
            ctx = limits[n].shm_zone->data;

            if (ctx->node == NULL) {
                continue;
            }

            ngx_shmtx_lock(&ctx->shpool->mutex);

            ctx->node->count--;

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            ctx->node = NULL;
        }

        // new in 1.17.1
        // 不会限速
        if (lrcf->dry_run) {
            r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN;
            // 让下一个模块继续处理
            return NGX_DECLINED;
        }

        // 返回指定的状态码
        // 之后走finalize_request
        r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_REJECTED;

        return lrcf->status_code;
    }

    /* rc == NGX_AGAIN || rc == NGX_OK */

    if (rc == NGX_AGAIN) {
        excess = 0;
    }

    // 计算延迟的毫秒
    // 如果设置了nodelay参数，那么就是0
    delay = ngx_http_limit_req_account(limits, n, &excess, &limit);

    // 不延迟，流程继续处理
    if (!delay) {
        r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_PASSED;
        return NGX_DECLINED;
    }

    // 延迟delay毫秒，使用定时器

    ngx_log_error(lrcf->delay_log_level, r->connection->log, 0,
                  "delaying request%s, excess: %ui.%03ui, by zone \"%V\"",
                  lrcf->dry_run ? ", dry run" : "",
                  excess / 1000, excess % 1000, &limit->shm_zone->shm.name);

    // new in 1.17.1
    if (lrcf->dry_run) {
        r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN;
        // dry run不会限速
        return NGX_DECLINED;
    }

    r->main->limit_req_status = NGX_HTTP_LIMIT_REQ_DELAYED;

    // epoll添加读事件
    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 有事件发生时执行的函数
    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_limit_req_delay;

    // 加入定时器，稍后再处理
    r->connection->write->delayed = 1;

    // 写事件加入定时器，稍后被触发
    // 会执行ngx_http_limit_req_delay
    // 重新注册读写事件
    // 可写时继续走处理流程，各个模块处理
    ngx_add_timer(r->connection->write, delay);

    return NGX_AGAIN;
}


// 写事件加入定时器，稍后被触发
// 重新注册读写事件
// 可写时继续走处理流程，各个模块处理
static void
ngx_http_limit_req_delay(ngx_http_request_t *r)
{
    ngx_event_t  *wev;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "limit_req delay");

    // 取写事件
    wev = r->connection->write;

    // 应该是被延迟的
    if (wev->delayed) {

        // 重新注册写事件
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    // 重新注册读事件
    if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    // 可读时不再读取
    r->read_event_handler = ngx_http_block_reading;

    // 可写时继续走处理流程，各个模块处理
    r->write_event_handler = ngx_http_core_run_phases;

    // 走流程
    ngx_http_core_run_phases(r);
}


static void
ngx_http_limit_req_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_http_limit_req_node_t *) &node->color;
            lrnt = (ngx_http_limit_req_node_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
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


// 取共享内存里的红黑树
// 计算上次访问的时间间隔计算超出值
static ngx_int_t
ngx_http_limit_req_lookup(ngx_http_limit_req_limit_t *limit, ngx_uint_t hash,
    ngx_str_t *key, ngx_uint_t *ep, ngx_uint_t account)
{
    size_t                      size;
    ngx_int_t                   rc, excess;
    ngx_msec_t                  now;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lr;

    // 当前毫秒
    now = ngx_current_msec;

    // 限流的信息，关联到各个共享内存
    ctx = limit->shm_zone->data;

    // 取共享内存里的红黑树
    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    // 红黑树查找
    while (node != sentinel) {

        // 左子树
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        // 右子树
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        // key相同，但还要判断字符串

        // 指针转化，红黑树节点后面是自己的数据
        lr = (ngx_http_limit_req_node_t *) &node->color;

        // 比较长度和内容
        rc = ngx_memn2cmp(key->data, lr->data, key->len, (size_t) lr->len);

        // 找到
        if (rc == 0) {
            // 移出队列
            ngx_queue_remove(&lr->queue);

            // 插到队列头
            ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

            // 计算上次访问的时间间隔
            ms = (ngx_msec_int_t) (now - lr->last);

            // 1.15.0
            if (ms < -60000) {
                ms = 1;

            } else if (ms < 0) {
                ms = 0;
            }

            // 计算超出值
            excess = lr->excess - ctx->rate * ms / 1000 + 1000;

            if (excess < 0) {
                excess = 0;
            }

            // 输出excess
            *ep = excess;

            // 超出了容忍的突发数量，返回busy，拒绝请求
            if ((ngx_uint_t) excess > limit->burst) {
                return NGX_BUSY;
            }

            // 数组的最后一个元素才会做记录操作
            // 避免多个查找重复操作
            if (account) {
                // 记录本次的请求信息
                lr->excess = excess;

                if (ms) {
                    lr->last = now;
                }

                // ok不会拒绝请求
                return NGX_OK;
            }

            // 该节点计数增加
            lr->count++;

            // 记录在ctx里，之后再操作
            ctx->node = lr;

            // again表示不会拒绝请求，需要再次检查
            return NGX_AGAIN;
        }

        // key相同但字符串不同，需要继续找
        node = (rc < 0) ? node->left : node->right;
    }

    // 红黑树里没找到，需要创建新节点

    *ep = 0;

    // 需要新建一个节点
    // 先是rbtree_node
    // 然后是req_node
    // 最后是字符串
    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_limit_req_node_t, data)
           + key->len;

    // 清理一下内存
    ngx_http_limit_req_expire(ctx, 1);

    // 在共享内存里分配内存
    node = ngx_slab_alloc_locked(ctx->shpool, size);

    // 分配内存失败则过期内存，尝试再分配
    if (node == NULL) {
        ngx_http_limit_req_expire(ctx, 0);

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "could not allocate node%s", ctx->shpool->log_ctx);
            return NGX_ERROR;
        }
    }

    // 红黑树的key，之前计算的crc32
    node->key = hash;

    // 指针转化，红黑树节点后面是自己的数据
    lr = (ngx_http_limit_req_node_t *) &node->color;

    // key的长度
    lr->len = (u_short) key->len;

    // 超出数0
    lr->excess = 0;

    // 拷贝key字符串
    ngx_memcpy(lr->data, key->data, key->len);

    // 插入红黑树
    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    // 插入队列
    ngx_queue_insert_head(&ctx->sh->queue, &lr->queue);

    // 数组的最后一个元素才会做记录操作
    // 避免多个查找重复操作
    if (account) {
        lr->last = now;
        lr->count = 0;

        // ok不会拒绝请求
        return NGX_OK;
    }

    lr->last = 0;
    lr->count = 1;

    ctx->node = lr;

    return NGX_AGAIN;
}


static ngx_msec_t
ngx_http_limit_req_account(ngx_http_limit_req_limit_t *limits, ngx_uint_t n,
    ngx_uint_t *ep, ngx_http_limit_req_limit_t **limit)
{
    ngx_int_t                   excess;
    ngx_msec_t                  now, delay, max_delay;
    ngx_msec_int_t              ms;
    ngx_http_limit_req_ctx_t   *ctx;
    ngx_http_limit_req_node_t  *lr;

    excess = *ep;

    if ((ngx_uint_t) excess <= (*limit)->delay) {
        max_delay = 0;

    } else {
        ctx = (*limit)->shm_zone->data;
        max_delay = (excess - (*limit)->delay) * 1000 / ctx->rate;
    }

    while (n--) {
        ctx = limits[n].shm_zone->data;
        lr = ctx->node;

        if (lr == NULL) {
            continue;
        }

        ngx_shmtx_lock(&ctx->shpool->mutex);

        now = ngx_current_msec;
        ms = (ngx_msec_int_t) (now - lr->last);

        if (ms < -60000) {
            ms = 1;

        } else if (ms < 0) {
            ms = 0;
        }

        excess = lr->excess - ctx->rate * ms / 1000 + 1000;

        if (excess < 0) {
            excess = 0;
        }

        if (ms) {
            lr->last = now;
        }

        lr->excess = excess;
        lr->count--;

        ngx_shmtx_unlock(&ctx->shpool->mutex);

        ctx->node = NULL;

        if ((ngx_uint_t) excess <= limits[n].delay) {
            continue;
        }

        delay = (excess - limits[n].delay) * 1000 / ctx->rate;

        if (delay > max_delay) {
            max_delay = delay;
            *ep = excess;
            *limit = &limits[n];
        }
    }

    return max_delay;
}


// 清理一下内存
static void
ngx_http_limit_req_expire(ngx_http_limit_req_ctx_t *ctx, ngx_uint_t n)
{
    ngx_int_t                   excess;
    ngx_msec_t                  now;
    ngx_queue_t                *q;
    ngx_msec_int_t              ms;
    ngx_rbtree_node_t          *node;
    ngx_http_limit_req_node_t  *lr;

    now = ngx_current_msec;

    /*
     * n == 1 deletes one or two zero rate entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    // 就清三次
    // 不按红黑树，按lru队列
    while (n < 3) {

        // 空队列无需操作
        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        // 队列尾，即最少使用的那个
        q = ngx_queue_last(&ctx->sh->queue);

        // 取节点
        lr = ngx_queue_data(q, ngx_http_limit_req_node_t, queue);

        // 此操作无用
        // 引用计数防止删除
        if (lr->count) {

            /*
             * There is not much sense in looking further,
             * because we bump nodes on the lookup stage.
             */

            return;
        }

        // n=0不执行，强制删除
        if (n++ != 0) {

            // 计算时间
            ms = (ngx_msec_int_t) (now - lr->last);
            ms = ngx_abs(ms);

            // 一分钟内访问过就不删除
            if (ms < 60000) {
                return;
            }

            excess = lr->excess - ctx->rate * ms / 1000;

            if (excess > 0) {
                return;
            }
        }

        // n=0强制删除

        ngx_queue_remove(q);

        // 偏移运算得到红黑树节点
        node = (ngx_rbtree_node_t *)
                   ((u_char *) lr - offsetof(ngx_rbtree_node_t, color));

        // 红黑树删除节点
        ngx_rbtree_delete(&ctx->sh->rbtree, node);

        // 释放共享内存
        ngx_slab_free_locked(ctx->shpool, node);

        // 循环继续释放
    }
}


// 模块自己的初始化共享内存
// 红黑树放进共享内存池对象里，方便使用
// 拼共享内存的名字
// 作为共享内存池的日志记录用
static ngx_int_t
ngx_http_limit_req_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    ngx_http_limit_req_ctx_t  *ctx;

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
                          "limit_req \"%V\" uses the \"%V\" key "
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
    // 存放进ctx
    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    // 已存在就复用
    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    // 共享内存里的红黑树指针
    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    // 红黑树放进共享内存池对象里，方便使用
    ctx->shpool->data = ctx->sh;

    // 初始化红黑树
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_limit_req_rbtree_insert_value);

    // 初始化队列
    ngx_queue_init(&ctx->sh->queue);

    // 拼共享内存的名字
    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    // 作为共享内存池的日志记录用
    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    // 作为共享内存池的日志记录用
    ngx_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    // 无内存时不记日志
    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_req_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->limit_req_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_limit_req_status[r->main->limit_req_status - 1].len;
    v->data = ngx_http_limit_req_status[r->main->limit_req_status - 1].data;

    return NGX_OK;
}


static void *
ngx_http_limit_req_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_req_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->limits.elts = NULL;
     */

    conf->limit_log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;
    conf->dry_run = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_limit_req_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_req_conf_t *prev = parent;
    ngx_http_limit_req_conf_t *conf = child;

    if (conf->limits.elts == NULL) {
        conf->limits = prev->limits;
    }

    ngx_conf_merge_uint_value(conf->limit_log_level, prev->limit_log_level,
                              NGX_LOG_ERR);

    conf->delay_log_level = (conf->limit_log_level == NGX_LOG_INFO) ?
                                NGX_LOG_INFO : conf->limit_log_level + 1;

    ngx_conf_merge_uint_value(conf->status_code, prev->status_code,
                              NGX_HTTP_SERVICE_UNAVAILABLE);

    ngx_conf_merge_value(conf->dry_run, prev->dry_run, 0);

    return NGX_CONF_OK;
}


// 解析共享内存指令
// 配置共享内存，使用的key等
static char *
ngx_http_limit_req_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    ngx_str_t                         *value, name, s;
    ngx_int_t                          rate, scale;
    ngx_uint_t                         i;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_req_ctx_t          *ctx;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    // 一个共享内存限制请求的基本信息
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_ctx_t));
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
    rate = 1;
    scale = 1;
    name.len = 0;

    // 解析各个参数
    // zone,size,rate,scale
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

        if (ngx_strncmp(value[i].data, "rate=", 5) == 0) {

            len = value[i].len;
            p = value[i].data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (ngx_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = ngx_atoi(value[i].data + 5, len - 5);
            if (rate <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rate \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    // zone,size,rate

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    ctx->rate = rate * 1000 / scale;

    // 添加共享内存
    // 之后在init_cycle里创建并初始化
    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_limit_req_module);
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
    shm_zone->init = ngx_http_limit_req_init_zone;

    // 设置data
    // 共享内存限制请求的基本信息
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


// 设置location使用的共享内存
static char *
ngx_http_limit_req(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_limit_req_conf_t  *lrcf = conf;

    ngx_int_t                    burst, delay;
    ngx_str_t                   *value, s;
    ngx_uint_t                   i;
    ngx_shm_zone_t              *shm_zone;
    ngx_http_limit_req_limit_t  *limit, *limits;

    value = cf->args->elts;

    shm_zone = NULL;
    burst = 0;
    delay = 0;

    // 解析各个参数
    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            // 根据名字找到之前添加的共享内存
            shm_zone = ngx_shared_memory_add(cf, &s, 0,
                                             &ngx_http_limit_req_module);
            if (shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "burst=", 6) == 0) {

            burst = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (burst <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid burst value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "delay=", 6) == 0) {

            delay = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (delay <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid delay value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "nodelay") == 0) {
            delay = NGX_MAX_INT_T_VALUE / 1000;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    // 必须根据名字找到已经定义的共享内存
    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    // 可以添加多个共享内存限制
    limits = lrcf->limits.elts;

    // 没有则创建动态数组
    if (limits == NULL) {
        if (ngx_array_init(&lrcf->limits, cf->pool, 1,
                           sizeof(ngx_http_limit_req_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    // 不能重复添加
    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    // 数组增加一个元素
    limit = ngx_array_push(&lrcf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    // 加入共享内存等信息
    // 之后请求的preaccess时使用
    // 共享内存限制请求的基本信息
    // 注意 ctx = shm_zone->data;
    // 通过它就可以获取限制信息
    limit->shm_zone = shm_zone;

    limit->burst = burst * 1000;
    limit->delay = delay * 1000;

    return NGX_CONF_OK;
}


// 在preaccess阶段，rewrite之后
static ngx_int_t
ngx_http_limit_req_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_limit_req_vars; v->name.len; v++) {
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
ngx_http_limit_req_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_req_handler;

    return NGX_OK;
}
