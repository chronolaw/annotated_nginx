// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


// nginx作为客户端发起的主动连接，连接上游服务器
typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

// 从连接池里获取一个主动连接
typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);

// 释放主动连接，归还连接池
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
#if (NGX_SSL)

typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
#endif


// nginx作为客户端发起的主动连接，连接上游服务器
struct ngx_peer_connection_s {
    // cycle里的连接对象，实际上使用了装饰模式
    ngx_connection_t                *connection;

    // 上游服务器的sockaddr
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                       *name;

    // 最大重试次数
    ngx_uint_t                       tries;

    // 连接开始的时间
    ngx_msec_t                       start_time;

    // 从连接池里获取一个主动连接
    ngx_event_get_peer_pt            get;

    // 释放主动连接，归还连接池
    ngx_event_free_peer_pt           free;

    // get/free函数所需的参数
    void                            *data;

#if (NGX_SSL)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

    // 本地地址
    ngx_addr_t                      *local;

    // 接收缓冲区大小
    int                              rcvbuf;

    // 日志对象
    ngx_log_t                       *log;

    // 连接是否已经缓存
    unsigned                         cached:1;

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;
};


// 使用ngx_peer_connection_t连接上游服务器
// 可对比ngx_event_accept建立被动连接
ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);

// 空函数，无任何操作
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
