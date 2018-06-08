// annotated by chrono since 2016
//
// 官方的服务降级模块，检查系统内存
// * ngx_http_degradation_handler

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 主配置
typedef struct {
    size_t      sbrk_size;
} ngx_http_degradation_main_conf_t;


// location配置
typedef struct {
    ngx_uint_t  degrade;
} ngx_http_degradation_loc_conf_t;


// 降级返回的状态码
static ngx_conf_enum_t  ngx_http_degrade[] = {
    { ngx_string("204"), 204 },
    { ngx_string("444"), 444 },
    { ngx_null_string, 0 }
};


static void *ngx_http_degradation_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_degradation_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_degradation_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_degradation(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 在preaccess阶段处理
static ngx_int_t ngx_http_degradation_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_degradation_commands[] = {

    // 在http{}里配置 sbrk=size
    // 超过内存限制则降级拒绝服务
    { ngx_string("degradation"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_degradation,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    // 降级返回的状态码
    { ngx_string("degrade"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_degradation_loc_conf_t, degrade),
      &ngx_http_degrade },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_degradation_module_ctx = {
    NULL,                                  /* preconfiguration */

    // 在preaccess阶段处理
    ngx_http_degradation_init,             /* postconfiguration */

    ngx_http_degradation_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_degradation_create_loc_conf,  /* create location configuration */
    ngx_http_degradation_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_degradation_module = {
    NGX_MODULE_V1,
    &ngx_http_degradation_module_ctx,      /* module context */
    ngx_http_degradation_commands,         /* module directives */
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


// 在preaccess阶段处理
// 设置了降级的状态码，即要求服务降级
static ngx_int_t
ngx_http_degradation_handler(ngx_http_request_t *r)
{
    ngx_http_degradation_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_degradation_module);

    // 设置了降级的状态码，即要求服务降级
    if (dlcf->degrade && ngx_http_degraded(r)) {
        return dlcf->degrade;
    }

    return NGX_DECLINED;
}


ngx_uint_t
ngx_http_degraded(ngx_http_request_t *r)
{
    time_t                             now;
    ngx_uint_t                         log;

    // 上次检查的sbrk_size
    static size_t                      sbrk_size;

    // 上次检查的时间
    // 静态，再次调用是上次的值
    static time_t                      sbrk_time;

    ngx_http_degradation_main_conf_t  *dmcf;

    // 取配置的sbrk_size
    dmcf = ngx_http_get_module_main_conf(r, ngx_http_degradation_module);

    // 必须配置了sbrk_size
    if (dmcf->sbrk_size) {

        log = 0;

        // 当前的时间
        now = ngx_time();

        /* lock mutex */

        // 暂时还没有mutex操作

        // 避免大并发时每个请求都检查
        if (now != sbrk_time) {

            /*
             * ELF/i386 is loaded at 0x08000000, 128M
             * ELF/amd64 is loaded at 0x00400000, 4M
             *
             * use a function address to subtract the loading address
             */

            // sbrk(0)活动当前进程堆的上限值，pragram break
            // ngx_palloc是代码段里的一个函数地址
            // 相减计算得到当前占用的内存
            sbrk_size = (size_t) sbrk(0) - ((uintptr_t) ngx_palloc & ~0x3FFFFF);

            // 修改检查的时间
            sbrk_time = now;

            // 要求记录日志
            log = 1;
        }

        // 多个“同时”的请求只调用一次sbrk，也只记录一次日志

        /* unlock mutex */

        // 检查是否超过了预定的内存设置
        // 超过则返回true，降级
        if (sbrk_size >= dmcf->sbrk_size) {
            if (log) {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                              "degradation sbrk:%uzM",
                              sbrk_size / (1024 * 1024));
            }

            return 1;
        }
    }

    return 0;
}


static void *
ngx_http_degradation_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_degradation_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_degradation_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    return dmcf;
}


static void *
ngx_http_degradation_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_degradation_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_degradation_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->degrade = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_degradation_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_degradation_loc_conf_t  *prev = parent;
    ngx_http_degradation_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->degrade, prev->degrade, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_degradation(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // 只有一个主配置
    ngx_http_degradation_main_conf_t  *dmcf = conf;

    ngx_str_t  *value, s;

    value = cf->args->elts;

    if (ngx_strncmp(value[1].data, "sbrk=", 5) == 0) {

        s.len = value[1].len - 5;
        s.data = value[1].data + 5;

        // 解析大小，填写字段
        dmcf->sbrk_size = ngx_parse_size(&s);
        if (dmcf->sbrk_size == (size_t) NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid sbrk size \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


// 在preaccess阶段处理
static ngx_int_t
ngx_http_degradation_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_degradation_handler;

    return NGX_OK;
}
