// annotated by chrono since 2016
//
// 1.10.x版本里的stream缺少变量和log功能
// 1.11.x添加了变量、log
//
// * ngx_stream_conf_ctx_t
// * ngx_stream_core_main_conf_t
// * ngx_stream_core_srv_conf_t
// * ngx_stream_session_s
// * ngx_stream_module_t

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

// nginx 1.11.3新增变量支持
#include <ngx_stream_variables.h>
#include <ngx_stream_script.h>

// 连接上游服务器（后端）的功能
#include <ngx_stream_upstream.h>
#include <ngx_stream_upstream_round_robin.h>


// nginx 1.11.4新增的响应码定义
#define NGX_STREAM_OK                        200
#define NGX_STREAM_BAD_REQUEST               400
#define NGX_STREAM_FORBIDDEN                 403
#define NGX_STREAM_INTERNAL_SERVER_ERROR     500
#define NGX_STREAM_BAD_GATEWAY               502
#define NGX_STREAM_SERVICE_UNAVAILABLE       503


// tcp流处理的配置结构体
// 与http不同的是没有location，只有两级
// 在cycle->conf_ctx里存储的是stream{}级别的配置
typedef struct {
    // 保存stream{}块里的配置，是个数组，存储void*指针
    void                         **main_conf;

    // 保存server{}块里的配置，是个数组，存储void*指针
    void                         **srv_conf;
} ngx_stream_conf_ctx_t;


// tcp流处理的监听端口结构体
// ngx_stream_listen_t
typedef struct {

    // socket地址，使用union适应各种情形
    // 主要使用的是u.sockaddr
    // 1.11.x改为在ngx_inet.h里定义的ngx_sockaddr_t，简化了代码
    // 1.15.10后又改成了指针形式的数组
    //ngx_sockaddr_t                 sockaddr;

    struct sockaddr               *sockaddr;

    // socket地址长度
    socklen_t                      socklen;
    ngx_str_t                      addr_text;

    /* server ctx */
    // 监听端口所在的server{}配置数组
    ngx_stream_conf_ctx_t         *ctx;

    // 已经绑定
    unsigned                       bind:1;

    // 使用通配符标志位
    unsigned                       wildcard:1;

    unsigned                       ssl:1;
#if (NGX_HAVE_INET6)
    unsigned                       ipv6only:1;
#endif

    // 在linux上提高性能的reuseport功能
    unsigned                       reuseport:1;

    // 启用so_keepalive特性
    unsigned                       so_keepalive:2;
    unsigned                       proxy_protocol:1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                            tcp_keepidle;
    int                            tcp_keepintvl;
    int                            tcp_keepcnt;
#endif

    // 内核里等待连接的队列长度
    int                            backlog;

    // 1.14新增
    int                            rcvbuf;
    int                            sndbuf;

    // socket的类型，SOCK_STREAM 表示TCP
    int                            type;
} ngx_stream_listen_t;


// 用于解决多个server监听相同端口的情况
// ctx里存储server{}对应的配置数组
// 存储在ngx_listening_t.servers里
typedef struct {
    // ctx里存储server{}对应的配置数组
    ngx_stream_conf_ctx_t         *ctx;

    // 地址的文本形式
    ngx_str_t                      addr_text;

    unsigned                       ssl:1;
    unsigned                       proxy_protocol:1;
} ngx_stream_addr_conf_t;

// 记录地址信息和定义端口的server{}信息
typedef struct {
    // in_addr_t 一般为 32位的unsigned int
    // 其字节顺序为网络顺序（network byte ordered)
    in_addr_t                      addr;

    // ctx里存储server{}对应的配置数组
    ngx_stream_addr_conf_t         conf;
} ngx_stream_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr                addr6;
    ngx_stream_addr_conf_t         conf;
} ngx_stream_in6_addr_t;

#endif


// 给事件机制用的端口信息
// 存储在ls->servers
typedef struct {
    /* ngx_stream_in_addr_t or ngx_stream_in6_addr_t */

    // 一个数组，里面存储了一个或多个ngx_stream_in_addr_t
    // 在ngx_stream_add_ports里检查相同的端口添加
    // 在ngx_stream_init_connection里使用
    void                          *addrs;

    ngx_uint_t                     naddrs;
} ngx_stream_port_t;

// 用在ngx_stream_add_ports
// 整理在stream{}里定义的监听端口
// 多个相同的端口会存储在addrs里
// 用addrs[0].opt的方式得到实际的端口信息
typedef struct {
    int                            family;

    // 监听的类型， tcp/udp
    int                            type;

    // 监听的端口，支持ipv4和ipv6
    // in_port_t通常是uint16
    in_port_t                      port;

    // 用来保存多个相同的监听端口
    ngx_array_t                    addrs; /* array of ngx_stream_conf_addr_t */
} ngx_stream_conf_port_t;


// 存储在ngx_stream_conf_port_t的addrs数组里
// 用来保存多个相同的监听端口
typedef struct {
    ngx_stream_listen_t            opt;
} ngx_stream_conf_addr_t;

// nginx 1.11.5 stream结构变动很大
// 取消了之前固定的xxx_handler
// 改成了与http类似的阶段处理
// 使用枚举ngx_stream_phases


// 限制访问的函数原型
// 与ngx_stream_handler_pt很像，但返回的是整数错误码
// 1.11.5已经取消，统一改成了phase handler
// typedef ngx_int_t (*ngx_stream_access_pt)(ngx_stream_session_t *s);

// 1.11.5开始使用phase概念，类似http
// 目前只有7个phase，但每个阶段都可以使用
typedef enum {
    // 刚accept建立连接后
    NGX_STREAM_POST_ACCEPT_PHASE = 0,

    // = 1
    NGX_STREAM_PREACCESS_PHASE,

    // 访问控制阶段, = 2
    NGX_STREAM_ACCESS_PHASE,

    // = 3
    NGX_STREAM_SSL_PHASE,

    // 这个阶段可以预读部分数据，解析格式，如sni
    // = 4
    NGX_STREAM_PREREAD_PHASE,

    // 应该加一个新的阶段，preread之后的处理
    // NGX_STREAM_POST_READ_PHASE,
    // 相关函数：ngx_stream_init_phases

    // 内容产生阶段，只能有一个handler
    // = 5
    NGX_STREAM_CONTENT_PHASE,

    // 日志阶段
    // = 6
    NGX_STREAM_LOG_PHASE
} ngx_stream_phases;


typedef struct ngx_stream_phase_handler_s  ngx_stream_phase_handler_t;

typedef ngx_int_t (*ngx_stream_phase_handler_pt)(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);

// 标准的phase handler函数原型
typedef ngx_int_t (*ngx_stream_handler_pt)(ngx_stream_session_t *s);

// 重要！处理tcp的回调函数原型，相当于http里的content handler
// 与ngx_stream_access_pt很像，但没有返回值
typedef void (*ngx_stream_content_handler_pt)(ngx_stream_session_t *s);


// 阶段引擎数组里的元素，包括checker和handler
// checker调用handler
// next用于阶段跳转
struct ngx_stream_phase_handler_s {
    ngx_stream_phase_handler_pt    checker;
    ngx_stream_handler_pt          handler;
    ngx_uint_t                     next;
};


// 阶段引擎数组
typedef struct {
    ngx_stream_phase_handler_t    *handlers;
} ngx_stream_phase_engine_t;


// 存储stream模块的处理handler函数
typedef struct {
    ngx_array_t                    handlers;
} ngx_stream_phase_t;


// stream core模块的main配置
// 主要存储server和监听端口
// 在stream{}里只有一个
// ngx_stream_core_main_conf_t
typedef struct {
    // 存储stream{}里定义的server
    // 实际上存储的是每个server{}配置数组里的stream_core模块的srv配置
    // 里面的ctx指向了实际server的配置数组
    ngx_array_t                    servers;     /* ngx_stream_core_srv_conf_t */

    // 存储server{}里定义的监听端口
    ngx_array_t                    listen;      /* ngx_stream_listen_t */

    // nginx 1.11.4新增
    // ngx_stream_access_pt           realip_handler;
    // ngx_stream_access_pt    access_handler;
    // ngx_stream_access_pt           access_log_handler;
    // 这两个回调相当于http模块里的phases数组
    // 自定义模块可以设置自己的函数
    // 在ngx_stream_init_connection里会被调用
    // 目前nginx对stream模块仅提供了这两个hook点
    // ngx_stream_access_pt    limit_conn_handler;
    // 相当于http里的NGX_HTTP_ACCESS_PHASE

    // 1.11.5加入phase
    ngx_stream_phase_engine_t      phase_engine;

    // nginx 1.11.3新增变量支持
    ngx_hash_t                     variables_hash;

    ngx_array_t                    variables;        /* ngx_stream_variable_t */
    ngx_array_t                    prefix_variables; /* ngx_stream_variable_t */
    ngx_uint_t                     ncaptures;

    ngx_uint_t                     variables_hash_max_size;
    ngx_uint_t                     variables_hash_bucket_size;

    ngx_hash_keys_arrays_t        *variables_keys;

    // stream模块的handler都添加在这里
    ngx_stream_phase_t             phases[NGX_STREAM_LOG_PHASE + 1];
} ngx_stream_core_main_conf_t;


// stream core模块的srv配置
// 每个server{}块都会有一个，表示一个server
// 成员ctx就是server{}块自己的配置信息存储数组
// 存储在ngx_stream_core_main_conf_t.servers
// 见ngx_stream_core_server()
// ngx_stream_core_srv_conf_t
typedef struct {
    // 收到tcp连接后的处理函数
    // 相当于http location里的content handler
    // 开发自己的stream模块必须设置此handler
    //
    // nginx 1.11.5改为专门的content handler
    // 之前会有post_accept、access等处理
    // ngx_stream_content_handler_pt  handler;
    ngx_stream_content_handler_pt  handler;

    // 保存模块的配置结构体，其中的main指向stream里
    // 是每个server{}块独立的存储空间
    ngx_stream_conf_ctx_t         *ctx;

    // 记录server{}块定义所在的文件和行号
    u_char                        *file_name;
    ngx_uint_t                     line;

    // 使用nodelay特性
    ngx_flag_t                     tcp_nodelay;

    // 预读相关的设置
    size_t                         preread_buffer_size;
    ngx_msec_t                     preread_timeout;

    ngx_log_t                     *error_log;

    ngx_msec_t                     resolver_timeout;
    ngx_resolver_t                *resolver;

    ngx_msec_t                     proxy_protocol_timeout;

    ngx_uint_t                     listen;  /* unsigned  listen:1; */
} ngx_stream_core_srv_conf_t;


// 类似ngx_http_request_t，表示tcp通信的会话
// 存储有tcp处理里需要的数据，例如connection、ctx等
// 缺点是无法扩展，如果增加一个void*成员就好了
// 可以在ctx数组里利用模块ctx来扩展存储，但还是不太方便
struct ngx_stream_session_s {
    // 结构体的标志，可以用来识别对象
    uint32_t                       signature;         /* "STRM" */

    // 与客户端的连接对象
    ngx_connection_t              *connection;

    // 收到的字节数
    off_t                          received;

    // 1.11.x增加启动的秒数和毫秒数
    time_t                         start_sec;
    ngx_msec_t                     start_msec;

    ngx_log_handler_pt             log_handler;

    // 数组，存储每个stream模块的ctx
    void                         **ctx;

    // 数组指针，存储每个stream模块的main配置
    // s->main_conf = addr_conf->ctx->main_conf;
    void                         **main_conf;

    // 数组指针，存储每个stream模块的srv配置
    // s->srv_conf = addr_conf->ctx->srv_conf;
    void                         **srv_conf;

    // 连接上游相关的信息，用于转发请求
    // 里面有如何获取负载均衡server、上下游buf等
    ngx_stream_upstream_t         *upstream;
    ngx_array_t                   *upstream_states;
                                           /* of ngx_stream_upstream_state_t */

    // 1.11.x增加变量数组和phase计数器
    ngx_stream_variable_value_t   *variables;

#if (NGX_PCRE)
    ngx_uint_t                     ncaptures;
    int                           *captures;
    u_char                        *captures_data;
#endif

    // 阶段引擎运行时的游标，记录当前的运行位置
    ngx_int_t                      phase_handler;

    // 处理的结果状态，通常是200，发生错误则可能是403/500等
    ngx_uint_t                     status;

    // 会话是否启用ssl
    // 在ngx_stream_init_connection里设置
    unsigned                       ssl:1;

    unsigned                       stat_processing:1;

    unsigned                       health_check:1;

    unsigned                       limit_conn_status:2;
};


// 流模块的函数表，用于解析配置时调用
// 与http模块相比没有location相关函数
typedef struct {
    // nginx 1.11.x新增的函数接口，1.10没有
    // 所以要使用NGX_MODULE_NULL(4)
    ngx_int_t                    (*preconfiguration)(ngx_conf_t *cf);

    // 解析配置完成之后调用
    // 在这里可以修改stream_core模块的配置，设置handler
    ngx_int_t                    (*postconfiguration)(ngx_conf_t *cf);

    // 创建main配置结构体
    void                        *(*create_main_conf)(ngx_conf_t *cf);

    // 解析完成后初始化main配置结构体
    char                        *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    // 创建srv配置结构体
    void                        *(*create_srv_conf)(ngx_conf_t *cf);

    // 解析完成后合并srv配置结构体
    char                        *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
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
// 使用模块的ctx_index在ctx数组里索引得到
#define ngx_stream_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]

// 设置模块的ctx数据
// 使用模块的ctx_index在ctx数组里索引得到
#define ngx_stream_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;

// 删除模块的ctx数据
// 使用模块的ctx_index在ctx数组里索引得到
#define ngx_stream_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;


// 从会话对象里得到配置结构体
// 使用模块的ctx_index在ctx数组里索引得到
#define ngx_stream_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_stream_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

// 从conf里得到配置结构体
// cf->ctx实际上是ngx_stream_conf_ctx_t，所以要先转换
// 使用模块的ctx_index在ctx数组里索引得到
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


#define NGX_STREAM_WRITE_BUFFERED  0x10


// 启动引擎数组处理请求
// 从phase_handler的位置开始调用模块处理
void ngx_stream_core_run_phases(ngx_stream_session_t *s);

ngx_int_t ngx_stream_core_generic_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);
ngx_int_t ngx_stream_core_preread_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);
ngx_int_t ngx_stream_core_content_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph);


// 在ngx_stream_optimize_servers里设置有连接发生时的回调函数
// 创建一个处理tcp的会话对象
// 要先检查限速和访问限制这两个功能模块
// 最后调用ngx_stream_init_session
// 创建ctx数组，用于存储模块的ctx数据
// 调用handler，处理tcp数据，收发等等
void ngx_stream_init_connection(ngx_connection_t *c);

// 读事件处理函数，执行处理引擎
void ngx_stream_session_handler(ngx_event_t *rev);

// nginx 1.11.4新增
// 内部调用access_log_handler记录访问日志
// 之后调用ngx_stream_close_connection关闭连接
void ngx_stream_finalize_session(ngx_stream_session_t *s, ngx_uint_t rc);

// 关闭stream连接，销毁线程池
// nginx 1.11.4改为静态函数，外部不可见
// 使用stream_lua模块需要修改源码，加入声明，并改为非static
//void ngx_stream_close_connection(ngx_connection_t *c);


extern ngx_module_t  ngx_stream_module;

// 计数器，得到所有的stream模块数量
// 1.9.11后改用cycle里的变量
extern ngx_uint_t    ngx_stream_max_module;

extern ngx_module_t  ngx_stream_core_module;


// 过滤函数原型，参数from_upstream标记数据的方向
// 可以同时过滤上行和下行的数据，内部自行区分处理
typedef ngx_int_t (*ngx_stream_filter_pt)(ngx_stream_session_t *s,
    ngx_chain_t *chain, ngx_uint_t from_upstream);


// 过滤函数链表头指针
extern ngx_stream_filter_pt  ngx_stream_top_filter;


#endif /* _NGX_STREAM_H_INCLUDED_ */
