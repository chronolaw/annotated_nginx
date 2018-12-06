// annotated by chrono since 2016
//
// * ngx_http_get_variable

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_VARIABLES_H_INCLUDED_
#define _NGX_HTTP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 与ngx_str_t类似，表示一个内存里的字符串空间
// 在http模块里重定义
//
// typedef struct {
//     unsigned    len:28;             //字符串长度，只有28位，剩下4位留给标志位
//
//     unsigned    valid:1;            //变量值是否有效
//     unsigned    no_cacheable:1;     //变量值是否允许缓存，默认允许
//     unsigned    not_found:1;        //变量未找到
//     unsigned    escape:1;
//
//     u_char     *data;               //字符串的地址，同ngx_str_t::data
// } ngx_variable_value_t;
typedef ngx_variable_value_t  ngx_http_variable_value_t;

// 初始化变量结构体
#define ngx_http_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_http_variable_s  ngx_http_variable_t;

// get/set函数指针
typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);


// 变量的一些属性，是否可修改
#define NGX_HTTP_VAR_CHANGEABLE   1
#define NGX_HTTP_VAR_NOCACHEABLE  2
#define NGX_HTTP_VAR_INDEXED      4
#define NGX_HTTP_VAR_NOHASH       8

// 1.11.10新增的属性
#define NGX_HTTP_VAR_WEAK         16
#define NGX_HTTP_VAR_PREFIX       32


// 为变量值的读写增加了一个间接层
// 它表示真正的Nginx变量
// 使用get/set函数而不是简单的字符串来访问变量值
struct ngx_http_variable_s {
    // 变量的名字
    ngx_str_t                     name;   /* must be first to build the hash */

    // 设置变量值函数
    // typedef void (*ngx_http_set_variable_pt) (ngx_http_request_t *r,
    //  ngx_http_variable_value_t *v, uintptr_t data);
    ngx_http_set_variable_pt      set_handler;

    // 获取变量值函数
    // typedef ngx_int_t (*ngx_http_get_variable_pt) (ngx_http_request_t *r,
    //  ngx_http_variable_value_t *v, uintptr_t data);
    ngx_http_get_variable_pt      get_handler;

    // set/get函数使用的辅助参数
    uintptr_t                     data;

    // 变量属性标志位
    ngx_uint_t                    flags;

    // 变量所在的数组序号
    ngx_uint_t                    index;
};

// 简化变量数组结尾的null
#define ngx_http_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }


// Nginx变量机制的核心函数，创建一个命名的变量访问对象
ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);

ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_http_variable_value_t *ngx_http_get_indexed_variable(ngx_http_request_t *r,
    ngx_uint_t index);
ngx_http_variable_value_t *ngx_http_get_flushed_variable(ngx_http_request_t *r,
    ngx_uint_t index);

// 访问Nginx变量值
// 使用变量名和hash key在ngx_http_core_module里查找已经添加的变量
// 再调用get_handler获取变量值
ngx_http_variable_value_t *ngx_http_get_variable(ngx_http_request_t *r,
    ngx_str_t *name, ngx_uint_t key);

ngx_int_t ngx_http_variable_unknown_header(ngx_http_variable_value_t *v,
    ngx_str_t *var, ngx_list_part_t *part, size_t prefix);


#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_http_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_http_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_http_regex_t;


typedef struct {
    ngx_http_regex_t             *regex;
    void                         *value;
} ngx_http_map_regex_t;


ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re,
    ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_http_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_http_map_t;


void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map,
    ngx_str_t *match);


ngx_int_t ngx_http_variables_add_core_vars(ngx_conf_t *cf);

// 在配置解析结束时调用
// 对变量数组建立hash，加速查找
ngx_int_t ngx_http_variables_init_vars(ngx_conf_t *cf);


extern ngx_http_variable_value_t  ngx_http_variable_null_value;

extern ngx_http_variable_value_t  ngx_http_variable_true_value;


#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
