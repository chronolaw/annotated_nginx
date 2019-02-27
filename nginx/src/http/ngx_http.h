// annotated by chrono since 2016
//
// * ngx_http_get_module_ctx
// * ngx_http_set_ctx
// * ngx_http_top_header_filter
// * ngx_http_top_body_filter

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_H_INCLUDED_
#define _NGX_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 包含了http请求处理所有信息的重要结构体
// 里面有内存池、各模块的配置、ctx、请求头等等
typedef struct ngx_http_request_s     ngx_http_request_t;

// 连接上游web server，转发http请求
typedef struct ngx_http_upstream_s    ngx_http_upstream_t;

typedef struct ngx_http_cache_s       ngx_http_cache_t;
typedef struct ngx_http_file_cache_s  ngx_http_file_cache_t;

// 记录日志相关的信息
typedef struct ngx_http_log_ctx_s     ngx_http_log_ctx_t;

typedef struct ngx_http_chunked_s     ngx_http_chunked_t;
typedef struct ngx_http_v2_stream_s   ngx_http_v2_stream_t;

typedef ngx_int_t (*ngx_http_header_handler_pt)(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
typedef u_char *(*ngx_http_log_handler_pt)(ngx_http_request_t *r,
    ngx_http_request_t *sr, u_char *buf, size_t len);


#include <ngx_http_variables.h>
#include <ngx_http_config.h>
#include <ngx_http_request.h>
#include <ngx_http_script.h>
#include <ngx_http_upstream.h>
#include <ngx_http_upstream_round_robin.h>
#include <ngx_http_core_module.h>

#if (NGX_HTTP_V2)
#include <ngx_http_v2.h>
#endif
#if (NGX_HTTP_CACHE)
#include <ngx_http_cache.h>
#endif
#if (NGX_HTTP_SSI)
#include <ngx_http_ssi_filter_module.h>
#endif
#if (NGX_HTTP_SSL)
#include <ngx_http_ssl_module.h>
#endif


// 记录日志相关的信息
struct ngx_http_log_ctx_s {
    ngx_connection_t    *connection;
    ngx_http_request_t  *request;
    ngx_http_request_t  *current_request;
};


// 读取chunk数据的结构体，用于ngx_http_parse_chunked()
struct ngx_http_chunked_s {
    // 状态机解析的状态
    ngx_uint_t           state;

    // 当前chunk的大小
    off_t                size;

    off_t                length;
};


// 记录解析http头的状态
typedef struct {
    ngx_uint_t           http_version;
    ngx_uint_t           code;
    ngx_uint_t           count;
    u_char              *start;
    u_char              *end;
} ngx_http_status_t;


// 获取模块存储在ngx_http_request_t里的ctx数据
// ctx可以用来存储在处理过程中任意的数据，作为暂存
// 因为nginx是事件驱动的，处理不可能一次完成，所以ctx就起到了断点的作用
#define ngx_http_get_module_ctx(r, module)  (r)->ctx[module.ctx_index]

// 设置模块存储在ngx_http_request_t里的ctx数据
#define ngx_http_set_ctx(r, c, module)      r->ctx[module.ctx_index] = c;


ngx_int_t ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
    ngx_http_core_loc_conf_t *clcf);
ngx_int_t ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_listen_opt_t *lsopt);


// 当epoll检测到连接事件，会调用event_accept，最后会调用此函数，开始处理http请求
// 在ngx_http_optimize_servers->ngx_http_add_listening里设置有连接发生时的回调函数
// 调用发生在ngx_event_accept.c:ngx_event_accept()
// 把读事件加入epoll，当socket有数据可读时就调用ngx_http_wait_request_handler
void ngx_http_init_connection(ngx_connection_t *c);

// 关闭http连接
// 调用ngx_close_connection
// 释放连接，加入空闲链表，可以再次使用
// 销毁连接的内存池
void ngx_http_close_connection(ngx_connection_t *c);

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
int ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg);
#endif
#if (NGX_HTTP_SSL && defined SSL_R_CERT_CB_ERROR)
int ngx_http_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg);
#endif


// 解析http请求行，即get xxx http/1.1 \r\n
ngx_int_t ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b);

ngx_int_t ngx_http_parse_uri(ngx_http_request_t *r);
ngx_int_t ngx_http_parse_complex_uri(ngx_http_request_t *r,
    ngx_uint_t merge_slashes);
ngx_int_t ngx_http_parse_status_line(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_status_t *status);
ngx_int_t ngx_http_parse_unsafe_uri(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, ngx_uint_t *flags);
ngx_int_t ngx_http_parse_header_line(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_uint_t allow_underscores);
ngx_int_t ngx_http_parse_multi_header_lines(ngx_array_t *headers,
    ngx_str_t *name, ngx_str_t *value);
ngx_int_t ngx_http_parse_set_cookie_lines(ngx_array_t *headers,
    ngx_str_t *name, ngx_str_t *value);
ngx_int_t ngx_http_arg(ngx_http_request_t *r, u_char *name, size_t len,
    ngx_str_t *value);
void ngx_http_split_args(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args);
ngx_int_t ngx_http_parse_chunked(ngx_http_request_t *r, ngx_buf_t *b,
    ngx_http_chunked_t *ctx);


// 创建ngx_http_request_t对象，准备开始真正的处理请求
// 连接对象里获取配置数组， 在ngx_http_init_connection里设置的
// 创建请求内存池，创建请求对象
// 为所有http模块分配存储ctx数据的空间，即一个大数组
// 为所有变量创建数组
ngx_http_request_t *ngx_http_create_request(ngx_connection_t *c);

ngx_int_t ngx_http_process_request_uri(ngx_http_request_t *r);

// 检查收到的http请求头
// http1.1不允许没有host头
// content_length不能是非数字
// 不支持trace方法
// 如果是chunked编码那么长度头无意义
// 设置keep_alive头信息
ngx_int_t ngx_http_process_request_header(ngx_http_request_t *r);

// 此时已经读取了完整的http请求头，可以开始处理请求了
// 如果还在定时器红黑树里，那么就删除，不需要检查超时
// 连接的读写事件handler都设置为ngx_http_request_handler
// 请求的读事件设置为ngx_http_block_reading
// 启动引擎数组，即r->write_event_handler = ngx_http_core_run_phases
// 从phase_handler的位置开始调用模块处理
// 如果有子请求，那么都要处理
void ngx_http_process_request(ngx_http_request_t *r);

// 把location里的配置拷贝到请求结构体里
// 重点是r->content_handler = clcf->handler;
void ngx_http_update_location_config(ngx_http_request_t *r);

// 读取了完整的http请求头，开始处理请求
// 在ngx_http_request.c:ngx_http_process_request里调用
// 启动引擎数组，即r->write_event_handler = ngx_http_core_run_phases
// 外部请求的引擎数组起始序号是0，从头执行引擎数组,即先从Post read开始
// 内部请求，即子请求.跳过post read，直接从server rewrite开始执行，即查找server
// 启动引擎数组处理请求，调用ngx_http_core_run_phases
void ngx_http_handler(ngx_http_request_t *r);

// 处理主请求里延后处理的请求链表，直至处理完毕
// r->main->posted_requests
// 调用请求里的write_event_handler
// 通常就是ngx_http_core_run_phases引擎数组处理请求
void ngx_http_run_posted_requests(ngx_connection_t *c);

// 把请求r加入到pr的延后处理链表末尾
ngx_int_t ngx_http_post_request(ngx_http_request_t *r,
    ngx_http_posted_request_t *pr);

// 重要函数，以“适当”的方式“结束”请求
// 并不一定会真正结束，大部分情况下只是暂时停止处理，等待epoll事件发生
// 参数rc决定了函数的逻辑，在content阶段就是handler的返回值
// 调用ngx_http_finalize_connection，检查请求相关的异步事件，尝试关闭请求
void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

// 释放请求相关的资源，调用cleanup链表，相当于析构
// 此时请求已经结束，调用log模块记录日志
// 销毁请求的内存池
// 但连接的内存池还在，可以用于长连接继续使用
void ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc);

// 用于忽略读写事件，即不处理
void ngx_http_empty_handler(ngx_event_t *wev);

// 用于忽略写事件，即不处理
// r->write_event_handler = ngx_http_request_empty_handler;
void ngx_http_request_empty_handler(ngx_http_request_t *r);


// ngx_http_send_special支持的参数
#define NGX_HTTP_LAST   1
#define NGX_HTTP_FLUSH  2

// 发送特殊的http响应数据，即flush和eof
ngx_int_t ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags);


// 要求nginx读取请求体，传入一个post_handler
// 引用计数器增加，表示此请求还有关联的操作，不能直接销毁
// 所以post_handler里需要调用ngx_http_finalize_request来结束请求
ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler);

ngx_int_t ngx_http_read_unbuffered_request_body(ngx_http_request_t *r);

// 发送http头，调用过滤链表
// 发送头，调用ngx_http_top_header_filter
// 如果请求处理有错误，修改输出的状态码
// 状态行同时清空
// 走过整个header过滤链表
ngx_int_t ngx_http_send_header(ngx_http_request_t *r);

ngx_int_t ngx_http_special_response_handler(ngx_http_request_t *r,
    ngx_int_t error);
ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r,
    ngx_module_t *m, ngx_int_t error);
void ngx_http_clean_header(ngx_http_request_t *r);


// 这两个函数在1.10已不存在
// time_t ngx_http_parse_time(u_char *value, size_t len);
// size_t ngx_http_get_time(char *buf, time_t t);


// 丢弃http请求体，对于get等请求是必须的
// 子请求不与客户端直接通信，不会有请求体的读取
// 已经设置了discard_body标志，表示已经调用了此函数
// request_body指针不空，表示已经调用了此函数
// 这三种情况就无需再启动读取handler，故直接返回成功
// 因为要丢弃数据，所以不需要检查超时，也就是说即使超时也不算是错误
// 如果头里的长度是0且不是chunked
// 说明没有请求体数据，那么就无需再读，直接返回成功
// *一直*读数据并解析，检查content_length_n,如果无数据可读就返回NGX_AGAIN
// 因为使用的是et模式，所以必须把数据读完
// 调用ngx_http_discard_request_body_filter检查收到的数据
// 使用回调ngx_http_discarded_request_body_handler读取数据
ngx_int_t ngx_http_discard_request_body(ngx_http_request_t *r);

// 丢弃请求体读事件处理，在epoll里加入读事件和handler
// 这时epoll通知socket上有数据可以读取
// ngx_http_read_discarded_request_body ok表示数据已经读完
// 传递done给ngx_http_finalize_request，并不是真正结束请求
// 因为有引用计数器r->count，所以在ngx_http_close_request里只是减1的效果
void ngx_http_discarded_request_body_handler(ngx_http_request_t *r);

// 仅打印日志，不从socket读数据，故客户端发送将阻塞
void ngx_http_block_reading(ngx_http_request_t *r);

void ngx_http_test_reading(ngx_http_request_t *r);


char *ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t **keys,
    ngx_hash_t *types_hash, ngx_array_t **prev_keys,
    ngx_hash_t *prev_types_hash, ngx_str_t *default_types);
ngx_int_t ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
    ngx_str_t *default_type);

#if (NGX_HTTP_DEGRADATION)
ngx_uint_t  ngx_http_degraded(ngx_http_request_t *);
#endif


extern ngx_module_t  ngx_http_module;

extern ngx_str_t  ngx_http_html_default_types[];


// 过滤链表头指针，过滤header
// 每个过滤模块都需要内部实现一个函数指针，链接为单向链表
// 在modules数组里位置在前的是链表末尾，后面的是链表前面
// 链表的最后一个模块是ngx_http_header_filter_module
extern ngx_http_output_header_filter_pt  ngx_http_top_header_filter;

// 过滤链表头指针，过滤body
// 每个过滤模块都需要内部实现一个函数指针，链接为单向链表
// 在modules数组里位置在前的是链表末尾，后面的是链表前面
// 链表的最后一个模块是ngx_http_write_filter_module
extern ngx_http_output_body_filter_pt    ngx_http_top_body_filter;

// 过滤链表头指针，过滤请求body，1.8.x新增
extern ngx_http_request_body_filter_pt   ngx_http_top_request_body_filter;


#endif /* _NGX_HTTP_H_INCLUDED_ */
