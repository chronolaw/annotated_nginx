// annotated by chrono since 2016
//
// 目前stream还缺少变量和log功能，今后也许能够完善
// * ngx_stream_core_main_conf_t
// * ngx_stream_core_srv_conf_t
// * ngx_stream_session_s

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STREAM_H_INCLUDED_
#define _NGX_STREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_STREAM_SSL)
#include <ngx_stream_ssl_module.h>
#endif


// 类似ngx_http_request_t，表示tcp通信的会话
// 存储有tcp处理里需要的数据，例如connection、ctx等
typedef struct ngx_stream_session_s  ngx_stream_session_t;


// 连接上游服务器（后端）的功能
#include <ngx_stream_upstream.h>
#include <ngx_stream_upstream_round_robin.h>


// tcp流处理的配置结构体
// 与http不同的是没有location，只有两级
// 在cycle->conf_ctx里存储的是stream{}级别的配置
typedef struct {
    // 保存stream{}块里的配置，是个数组，存储void*指针
    void                  **main_conf;

    // 保存server{}块里的配置，是个数组，存储void*指针
    void                  **srv_conf;
} ngx_stream_conf_ctx_t;


// tcp流处理的监听端口结构体
typedef struct {

    // socket地址，使用union适应各种情形
    // 主要使用的是u.sockaddr
    union {
        struct sockaddr     sockaddr;
        struct sockaddr_in  sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6 sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un  sockaddr_un;
#endif
        u_char              sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    // socket地址长度
    socklen_t               socklen;

    /* server ctx */
    // 监听端口所在的server{}配置数组
    ngx_stream_conf_ctx_t  *ctx;

    // 已经绑定
    unsigned                bind:1;

    // 使用通配符标志位
    unsigned                wildcard:1;
#if (NGX_STREAM_SSL)
    unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:1;
#endif
#if (NGX_HAVE_REUSEPORT)
    unsigned                reuseport:1;
#endif
    unsigned                so_keepalive:2;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif
    int                     backlog;
} ngx_stream_listen_t;


// 用于解决多个server监听相同端口的情况
// ctx里存储server{}对应的配置数组
// 存储在ngx_listening_t.servers里
typedef struct {
    // ctx里存储server{}对应的配置数组
    ngx_stream_conf_ctx_t  *ctx;

    ngx_str_t               addr_text;
#if (NGX_STREAM_SSL)
    ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} ngx_stream_addr_conf_t;

typedef struct {
    in_addr_t               addr;
    ngx_stream_addr_conf_t  conf;
} ngx_stream_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_stream_addr_conf_t  conf;
} ngx_stream_in6_addr_t;

#endif


// 端口
typedef struct {
    /* ngx_stream_in_addr_t or ngx_stream_in6_addr_t */
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_stream_port_t;

// 用在ngx_stream_add_ports
typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_stream_conf_addr_t */
} ngx_stream_conf_port_t;


// 存储在ngx_stream_conf_port_t的addrs数组里
typedef struct {
    ngx_stream_listen_t     opt;
} ngx_stream_conf_addr_t;


// 限制访问的函数原型
// 与ngx_stream_handler_pt很像，但返回的是整数错误码
typedef ngx_int_t (*ngx_stream_access_pt)(ngx_stream_session_t *s);


// stream core模块的main配置
// 主要存储server和监听端口
// 在stream{}里只有一个
typedef struct {
    // 存储stream{}里定义的server
    // 实际上存储的是每个server{}配置数组里的stream_core模块的srv配置
    // 里面的ctx指向了实际server的配置数组
    ngx_array_t             servers;     /* ngx_stream_core_srv_conf_t */

    // 存储server{}里定义的监听端口
    ngx_array_t             listen;      /* ngx_stream_listen_t */

    // 这两个回调相当于http模块里的phases数组
    // 自定义模块可以设置自己的函数
    // 在ngx_stream_init_connection里会被调用
    // 目前nginx对stream模块仅提供了这两个hook点
    ngx_stream_access_pt    limit_conn_handler;

    // 相当于http里的NGX_HTTP_ACCESS_PHASE
    ngx_stream_access_pt    access_handler;
} ngx_stream_core_main_conf_t;


// 重要！处理tcp的回调函数原型，相当于http里的content handler
// 与ngx_stream_access_pt很像，但没有返回值
typedef void (*ngx_stream_handler_pt)(ngx_stream_session_t *s);


// stream core模块的srv配置
// 每个server{}块都会有一个，表示一个server
// 成员ctx就是server{}块自己的配置信息存储数组
// 存储在ngx_stream_core_main_conf_t.servers
// 见ngx_stream_core_server()
typedef struct {
    // 收到tcp连接后的处理函数
    // 相当于http location里的content handler
    // 开发自己的stream模块必须设置此handler
    ngx_stream_handler_pt   handler;

    // 保存模块的配置结构体，其中的main指向stream里
    // 是每个server{}块独立的存储空间
    ngx_stream_conf_ctx_t  *ctx;

    // 记录server{}块定义所在的文件和行号
    u_char                 *file_name;
    ngx_int_t               line;

    ngx_log_t              *error_log;
    ngx_flag_t              tcp_nodelay;
} ngx_stream_core_srv_conf_t;


// 类似ngx_http_request_t，表示tcp通信的会话
// 存储有tcp处理里需要的数据，例如connection、ctx等
// 缺点是无法扩展，如果增加一个void*成员就好了
struct ngx_stream_session_s {
    // 结构体的标志，可以用来识别对象
    uint32_t                signature;         /* "STRM" */

    // 与客户端的连接对象
    ngx_connection_t       *connection;

    // 收到的字节数
    off_t                   received;

    ngx_log_handler_pt      log_handler;

    // 数组，存储每个stream模块的ctx
    void                  **ctx;

    // 数组，存储每个stream模块的main配置
    // s->main_conf = addr_conf->ctx->main_conf;
    void                  **main_conf;

    // 数组，存储每个stream模块的srv配置
    // s->srv_conf = addr_conf->ctx->srv_conf;
    void                  **srv_conf;

    // 连接上游
    ngx_stream_upstream_t  *upstream;
};


// 流模块的函数表，用于解析配置时调用
// 与http模块相比没有location相关函数
typedef struct {
    // 解析配置完成之后调用
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    // 创建main配置结构体
    void                 *(*create_main_conf)(ngx_conf_t *cf);

    // 解析完成后初始化main配置结构体
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    // 创建srv配置结构体
    void                 *(*create_srv_conf)(ngx_conf_t *cf);

    // 解析完成后合并srv配置结构体
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                            void *conf);
} ngx_stream_module_t;


// stream模块的标志
#define NGX_STREAM_MODULE       0x4d525453     /* "STRM" */

// 用在配置指令里决定可以出现的位置
#define NGX_STREAM_MAIN_CONF    0x02000000
#define NGX_STREAM_SRV_CONF     0x04000000
#define NGX_STREAM_UPS_CONF     0x08000000


// 用在配置指令里决定配置结构体存储的位置
// ngx_command_t.conf成员
#define NGX_STREAM_MAIN_CONF_OFFSET  offsetof(ngx_stream_conf_ctx_t, main_conf)
#define NGX_STREAM_SRV_CONF_OFFSET   offsetof(ngx_stream_conf_ctx_t, srv_conf)


// 获取模块的ctx数据
#define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]

// 设置模块的ctx数据
#define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;

// 删除模块的ctx数据
#define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


// 从会话对象里得到配置结构体
#define ngx_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

// 从conf里得到配置结构体
// cf->ctx实际上是ngx_stream_conf_ctx_t，所以要先转换
#define ngx_stream_conf_get_module_main_conf(cf, module)                       \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_stream_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_stream_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

// 从cycle里得到配置结构体
// 先判断stream模块是否存在
// 然后用两次指针，找到main conf，因为main conf是唯一的
#define ngx_stream_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_stream_module.index] ?                                \
        ((ngx_stream_conf_ctx_t *) cycle->conf_ctx[ngx_stream_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)


// 在ngx_stream_optimize_servers里设置有连接发生时的回调函数
// 创建一个处理tcp的会话对象
// 要先检查限速和访问限制这两个功能模块
// 最后调用ngx_stream_init_session
// 创建ctx数组，用于存储模块的ctx数据
// 调用handler，处理tcp数据，收发等等
void ngx_stream_init_connection(ngx_connection_t *c);

// 关闭stream连接，销毁线程池
void ngx_stream_close_connection(ngx_connection_t *c);


extern ngx_module_t  ngx_stream_module;

// 计数器，得到所有的stream模块数量
// 1.9.11后改用cycle里的变量
extern ngx_uint_t    ngx_stream_max_module;

extern ngx_module_t  ngx_stream_core_module;


#endif /* _NGX_STREAM_H_INCLUDED_ */
