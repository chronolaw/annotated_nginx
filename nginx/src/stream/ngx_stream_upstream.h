
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_UPSTREAM_H_INCLUDED_
#define _NGX_STREAM_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_event_connect.h>


#define NGX_STREAM_UPSTREAM_CREATE        0x0001
#define NGX_STREAM_UPSTREAM_WEIGHT        0x0002
#define NGX_STREAM_UPSTREAM_MAX_FAILS     0x0004
#define NGX_STREAM_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_STREAM_UPSTREAM_DOWN          0x0010
#define NGX_STREAM_UPSTREAM_BACKUP        0x0020
#define NGX_STREAM_UPSTREAM_MAX_CONNS     0x0100


#define NGX_STREAM_UPSTREAM_NOTIFY_CONNECT     0x1


// upstream{}的配置结构体，只有一个数组
// 用来存储每个上游upstream{}的信息
typedef struct {
    ngx_array_t                        upstreams;
                                           /* ngx_stream_upstream_srv_conf_t */
} ngx_stream_upstream_main_conf_t;


typedef struct ngx_stream_upstream_srv_conf_s  ngx_stream_upstream_srv_conf_t;


typedef ngx_int_t (*ngx_stream_upstream_init_pt)(ngx_conf_t *cf,
    ngx_stream_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_stream_upstream_init_peer_pt)(ngx_stream_session_t *s,
    ngx_stream_upstream_srv_conf_t *us);


// load balance模块入口
typedef struct {
    // 配置解析时初始化
    ngx_stream_upstream_init_pt        init_upstream;

    // 发生请求时初始化
    ngx_stream_upstream_init_peer_pt   init;

    // 上游服务器列表指针
    void                              *data;
} ngx_stream_upstream_peer_t;


// 描述一个上游服务器的基本信息
// 包括权重、失败次数等
typedef struct {
    ngx_str_t                          name;
    ngx_addr_t                        *addrs;
    ngx_uint_t                         naddrs;
    ngx_uint_t                         weight;
    ngx_uint_t                         max_conns;
    ngx_uint_t                         max_fails;
    time_t                             fail_timeout;
    ngx_msec_t                         slow_start;
    ngx_uint_t                         down;

    unsigned                           backup:1;

    NGX_COMPAT_BEGIN(4)
    NGX_COMPAT_END
} ngx_stream_upstream_server_t;


// upstream{}块的配置，包含负载均衡算法和上游集群里的server信息
struct ngx_stream_upstream_srv_conf_s {
    // load balance算法入口，用于初始化
    // 在ngx_stream_upstream_init_main_conf里调用
    // 每个upstream{}只能使用一种负载均衡算法
    ngx_stream_upstream_peer_t         peer;

    // 保存本upstream{}的配置数组
    // 里面用srv_conf[ngx_stream_upstream_module.ctx_index]可以获取
    void                             **srv_conf;

    // 存储上游集群里的server信息
    ngx_array_t                       *servers;
                                              /* ngx_stream_upstream_server_t */

    // upstream{}的标志位
    // 通常有NGX_STREAM_UPSTREAM_CREATE|NGX_STREAM_UPSTREAM_CREATE等
    ngx_uint_t                         flags;

    // url的主机名
    ngx_str_t                          host;

    // upstream{}所在的配置文件
    u_char                            *file_name;

    // upstream{}所在的行号
    ngx_uint_t                         line;

    // 端口号
    in_port_t                          port;

    // 无端口号的标志位
    ngx_uint_t                         no_port;  /* unsigned no_port:1 */

    // 给商业版模块使用的共享内存
#if (NGX_STREAM_UPSTREAM_ZONE)
    ngx_shm_zone_t                    *shm_zone;
#endif
};


typedef struct {
    ngx_msec_t                         response_time;

    // 与后端服务器建立连接的时间，注意是毫秒
    ngx_msec_t                         connect_time;

    // 收到后端服务器数据的时间，注意是毫秒
    ngx_msec_t                         first_byte_time;


    // 收发的字节数，与ngx_stream_upstream_t.peer.connection->sent相同
    off_t                              bytes_sent;

    // 收发的字节数，与ngx_stream_upstream_t里的received相同
    off_t                              bytes_received;

    ngx_str_t                         *peer;
} ngx_stream_upstream_state_t;


typedef struct {
    ngx_str_t                          host;
    in_port_t                          port;
    ngx_uint_t                         no_port; /* unsigned no_port:1 */

    ngx_uint_t                         naddrs;
    ngx_resolver_addr_t               *addrs;

    struct sockaddr                   *sockaddr;
    socklen_t                          socklen;
    ngx_str_t                          name;

    ngx_resolver_ctx_t                *ctx;
} ngx_stream_upstream_resolved_t;


// 处理转发上游请求时的结构体
typedef struct {
    // 从upstream{}里获取一个上游server
    ngx_peer_connection_t              peer;

    // 上行下行使用的缓冲区
    ngx_buf_t                          downstream_buf;
    ngx_buf_t                          upstream_buf;

    ngx_chain_t                       *free;
    ngx_chain_t                       *upstream_out;
    ngx_chain_t                       *upstream_busy;
    ngx_chain_t                       *downstream_out;
    ngx_chain_t                       *downstream_busy;

    // 收到的字节数
    off_t                              received;

    // 开始的时间，只是秒数
    time_t                             start_sec;

    // 1.15新增,上行的包数
    ngx_uint_t                         requests;

    // 1.10新增,下行的包数
    ngx_uint_t                         responses;
    ngx_msec_t                         start_time;

    size_t                             upload_rate;
    size_t                             download_rate;

    ngx_str_t                          ssl_name;

    ngx_stream_upstream_srv_conf_t    *upstream;
    ngx_stream_upstream_resolved_t    *resolved;
    ngx_stream_upstream_state_t       *state;

    // 是否已经成功连接上游
    unsigned                           connected:1;

    unsigned                           proxy_protocol:1;
} ngx_stream_upstream_t;


// 创建或者获取一个upstream{}块的配置信息
// 获取时flags==0
// 检查是否有同名的upstream{}，如果是创建时有则报错
// 加入main conf里的upstreams数组，之后就可以在这里找到所有的upstream{}
ngx_stream_upstream_srv_conf_t *ngx_stream_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);


#define ngx_stream_conf_upstream_srv_conf(uscf, module)                       \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t  ngx_stream_upstream_module;


#endif /* _NGX_STREAM_UPSTREAM_H_INCLUDED_ */
