// annotated by chrono since 2018
//
// * ngx_http_mirror_handler
// * ngx_http_mirror_handler_internal

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 镜像流量的配置
typedef struct {
    // 保存多个流量镜像的目的uri
    ngx_array_t  *mirror;

    // 标志位，默认值是1
    // 即默认转发body数据
    // 由指令mirror_request_body配置
    ngx_flag_t    request_body;
} ngx_http_mirror_loc_conf_t;


// 本模块存储在请求里的ctx数据
typedef struct {
    ngx_int_t     status;
} ngx_http_mirror_ctx_t;


// 工作在PRECONTENT阶段
// 即access之后，content之前，原来的try_files
static ngx_int_t ngx_http_mirror_handler(ngx_http_request_t *r);

// 读取完请求体数据后被调用继续处理请求
// 镜像流量到内部的location
static void ngx_http_mirror_body_handler(ngx_http_request_t *r);

// 镜像流量到内部的location
static ngx_int_t ngx_http_mirror_handler_internal(ngx_http_request_t *r);

// 创建配置结构体
static void *ngx_http_mirror_create_loc_conf(ngx_conf_t *cf);

// 初始化配置
static char *ngx_http_mirror_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

// 解析mirror指令
static char *ngx_http_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 配置解析结束后调用，工作在PRECONTENT阶段
// 即access之后，content之前，原来的try_files
static ngx_int_t ngx_http_mirror_init(ngx_conf_t *cf);


// 镜像流量的配置指令
static ngx_command_t  ngx_http_mirror_commands[] = {

    // 解析mirror指令，只有一个参数
    // 但可以多次使用指令，配置多个目的uri
    { ngx_string("mirror"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_mirror,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    // 配置request_body标志位
    { ngx_string("mirror_request_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_mirror_loc_conf_t, request_body),
      NULL },

      ngx_null_command
};


// 注意函数指针，只有loc配置
static ngx_http_module_t  ngx_http_mirror_module_ctx = {
    NULL,                                  /* preconfiguration */

    // 配置解析结束后调用，工作在PRECONTENT阶段
    // 即access之后，content之前，原来的try_files
    ngx_http_mirror_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    // 创建配置结构体
    ngx_http_mirror_create_loc_conf,       /* create location configuration */
    ngx_http_mirror_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_mirror_module = {
    NGX_MODULE_V1,
    &ngx_http_mirror_module_ctx,           /* module context */
    ngx_http_mirror_commands,              /* module directives */
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


// 工作在PRECONTENT阶段
// 即access之后，content之前，原来的try_files
static ngx_int_t
ngx_http_mirror_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_mirror_ctx_t       *ctx;
    ngx_http_mirror_loc_conf_t  *mlcf;

    // 只处理主请求，即客户端的真实请求
    // 避免子请求造成的错误流量
    if (r != r->main) {
        return NGX_DECLINED;
    }

    // 取配置
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mirror_module);

    // 没有目的uri则不处理
    if (mlcf->mirror == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "mirror handler");

    // 默认是转发body数据
    if (mlcf->request_body) {
        // 取本模块的ctx
        ctx = ngx_http_get_module_ctx(r, ngx_http_mirror_module);

        // 返回ctx里的值，通常是done
        if (ctx) {
            return ctx->status;
        }

        // 没有则创建ctx
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mirror_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        // 状态为done
        ctx->status = NGX_DONE;

        ngx_http_set_ctx(r, ctx, ngx_http_mirror_module);

        // 要求读取body数据，读取完成后回调ngx_http_mirror_body_handler
        rc = ngx_http_read_client_request_body(r, ngx_http_mirror_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        // 使用done结束请求
        // 实际上只是减少引用计数
        // 之后还会继续处理请求
        ngx_http_finalize_request(r, NGX_DONE);

        return NGX_DONE;
    }

    // 不转发body，执行ngx_http_mirror_handler_internal
    return ngx_http_mirror_handler_internal(r);
}


// 读取完请求体数据后被调用继续处理请求
// 镜像流量到内部的location
static void
ngx_http_mirror_body_handler(ngx_http_request_t *r)
{
    ngx_http_mirror_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_mirror_module);

    // 镜像流量到内部的location
    ctx->status = ngx_http_mirror_handler_internal(r);

    r->preserve_body = 1;

    // 完成镜像流量，继续正常的请求处理
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}


// 镜像流量到内部的location
static ngx_int_t
ngx_http_mirror_handler_internal(ngx_http_request_t *r)
{
    ngx_str_t                   *name;
    ngx_uint_t                   i;
    ngx_http_request_t          *sr;
    ngx_http_mirror_loc_conf_t  *mlcf;

    // 取镜像目的uri数组
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_mirror_module);

    name = mlcf->mirror->elts;

    // 逐个发送子请求
    // 转发args，注意标志位是background
    // 回调函数是null，即子请求完成后无操作
    for (i = 0; i < mlcf->mirror->nelts; i++) {
        if (ngx_http_subrequest(r, &name[i], &r->args, &sr, NULL,
                                NGX_HTTP_SUBREQUEST_BACKGROUND)
            != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // 创建子请求完成，但还没有开始运行
        // 修改子请求的参数
        sr->header_only = 1;
        sr->method = r->method;
        sr->method_name = r->method_name;
    }

    // declined，即模块已经完成操作，不是done状态
    return NGX_DECLINED;
}


// 创建配置结构体
static void *
ngx_http_mirror_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mirror_loc_conf_t  *mlcf;

    mlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mirror_loc_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    // 注意这里的指针是unset，不是null
    mlcf->mirror = NGX_CONF_UNSET_PTR;
    mlcf->request_body = NGX_CONF_UNSET;

    return mlcf;
}


// 初始化配置
static char *
ngx_http_mirror_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mirror_loc_conf_t *prev = parent;
    ngx_http_mirror_loc_conf_t *conf = child;

    // 指针是null，即无目的uri，不镜像流量
    ngx_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL);

    // 默认转发body
    ngx_conf_merge_value(conf->request_body, prev->request_body, 1);

    return NGX_CONF_OK;
}


// 解析mirror指令，只有一个参数
// 但可以多次使用指令，配置多个目的uri
static char *
ngx_http_mirror(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_mirror_loc_conf_t *mlcf = conf;

    ngx_str_t  *value, *s;

    value = cf->args->elts;

    // 检查是否是off
    if (ngx_strcmp(value[1].data, "off") == 0) {
        // 之前已经设置过，则不允许重复
        if (mlcf->mirror != NGX_CONF_UNSET_PTR) {
            return "is duplicate";
        }

        // 指针清空
        mlcf->mirror = NULL;
        return NGX_CONF_OK;
    }

    // null表示用off设置过了，重复
    if (mlcf->mirror == NULL) {
        return "is duplicate";
    }

    // 正常情况指针是unset，需要创建数组
    if (mlcf->mirror == NGX_CONF_UNSET_PTR) {
        mlcf->mirror = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (mlcf->mirror == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    // 添加一个元素
    s = ngx_array_push(mlcf->mirror);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    *s = value[1];

    return NGX_CONF_OK;
}


// 配置解析结束后调用，工作在PRECONTENT阶段
// 即access之后，content之前，原来的try_files
static ngx_int_t
ngx_http_mirror_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_mirror_handler;

    return NGX_OK;
}
