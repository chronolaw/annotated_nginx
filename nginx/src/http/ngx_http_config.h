// annotated by chrono since 2016
//
// * ngx_http_conf_ctx_t
// * ngx_http_module_t

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 有三个void*数组，存储三个层次的模块配置
// 所有http模块的配置都存储在这里
// main配置只有一个，即http{}
// srv有多个，每个server{}有一个
typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;
} ngx_http_conf_ctx_t;

// http模块的函数表，在配置解析阶段被框架调用
typedef struct {
    // ngx_http_block里，创建配置结构体后，开始解析之前调用
    // 常用于添加变量定义
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);

    // ngx_http_block里，解析、合并完配置后调用
    // 常用于初始化模块的phases handler
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

    // 创建模块的main配置，只有一个，在http main域
    void       *(*create_main_conf)(ngx_conf_t *cf);

    // 初始化模块的main配置，只有一个，在http main域
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    // 创建、合并模块的srv配置
    void       *(*create_srv_conf)(ngx_conf_t *cf);
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

    // 创建、合并模块的location配置
    void       *(*create_loc_conf)(ngx_conf_t *cf);
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

// 标志指令的类型，出现的位置
// 常用的是前三个
#define NGX_HTTP_MAIN_CONF        0x02000000
#define NGX_HTTP_SRV_CONF         0x04000000
#define NGX_HTTP_LOC_CONF         0x08000000

// 用于在upsteam{}里出现的指令
#define NGX_HTTP_UPS_CONF         0x10000000

#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000


// 因为三个配置数组都是一样的，所以需要用这几个宏来区分位置
// 模块配置结构体在ngx_http_conf_ctx_t里存储的位置
// 实际指向了ngx_http_conf_ctx_t里的数组指针
// 应该与NGX_HTTP_SRV_CONF等指令对应
#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)


// 从请求的ctx数组里获取模块的配置，三个层次
#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


// 从配置的ctx数组里获取模块的配置，三个层次
#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
