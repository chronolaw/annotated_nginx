// annotated by chrono since 2016
//
// * ngx_http_phases
// * ngx_http_core_main_conf_t
// * ngx_http_core_srv_conf_t
// * ngx_http_core_loc_conf_s

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#elif (NGX_COMPAT)
typedef struct ngx_thread_pool_s  ngx_thread_pool_t;
#endif


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_THREADS            2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define NGX_HTTP_SERVER_TOKENS_OFF      0
#define NGX_HTTP_SERVER_TOKENS_ON       1
#define NGX_HTTP_SERVER_TOKENS_BUILD    2


// 存储location的红黑树节点
typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;

// 前置声明，location的配置结构体
// 重要的成员是handler，定义此location特有的内容处理函数
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


// http用的监听端口结构体
typedef struct {

    // socket地址，使用union适应各种情形
    // 主要使用的是u.sockaddr
    // 1.11.x改为在ngx_inet.h里定义的ngx_sockaddr_t，简化了代码
    // 1.15.10后又改成了指针形式的数组
    //ngx_sockaddr_t             sockaddr;

    struct sockaddr           *sockaddr;

    // socket地址长度
    socklen_t                  socklen;
    ngx_str_t                  addr_text;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
    unsigned                   ssl:1;
    unsigned                   http2:1;
#if (NGX_HAVE_INET6)
    unsigned                   ipv6only:1;
#endif

    // 延后accept连接特性，由内核处理有数据的连接，提高性能
    unsigned                   deferred_accept:1;

    unsigned                   reuseport:1;
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    // listen指令设置的backlog队列，收发缓冲区
    int                        backlog;

    // 收发缓冲区大小
    int                        rcvbuf;
    int                        sndbuf;

#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif

    // tcp专用的fast open特性
#if (NGX_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
} ngx_http_listen_opt_t;


// http处理的11个阶段，非常重要
// 需要在配置解析后的postconfiguration里向cmcf->phases数组注册
// content阶段较特殊，在loc_conf里可以为每个location设置单独的handler
// 这样可以避免数组过大
typedef enum {
    // 读取并解析完http头后，即将开始读取body
    // 目前仅有一个模块ngx_http_realip_module
    NGX_HTTP_POST_READ_PHASE = 0,

    // 在server阶段重写url
    NGX_HTTP_SERVER_REWRITE_PHASE,

    // 此阶段用户不可介入
    NGX_HTTP_FIND_CONFIG_PHASE,

    // 在location阶段重写url，较常用
    NGX_HTTP_REWRITE_PHASE,

    // 此阶段用户不可介入
    NGX_HTTP_POST_REWRITE_PHASE,

    // 检查访问权限之前
    NGX_HTTP_PREACCESS_PHASE,

    // 检查访问权限，较常用
    NGX_HTTP_ACCESS_PHASE,

    // 此阶段用户不可介入
    NGX_HTTP_POST_ACCESS_PHASE,

    // 1.13.3之前此阶段用户不可介入
    //NGX_HTTP_TRY_FILES_PHASE,
    // 1.13.4后改为NGX_HTTP_PRECONTENT_PHASE
    // 用户可以在此阶段添加模块，在产生内容前做一些处理
    NGX_HTTP_PRECONTENT_PHASE,

    // 最常用的阶段，产生http内容，响应客户端请求
    // 在这里发出去的数据会由过滤链表处理最终发出
    // content阶段较特殊，在loc_conf里可以为每个location设置单独的handler
    NGX_HTTP_CONTENT_PHASE,

    // 记录访问日志，请求已经处理完毕
    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

// 存储handler/checker，里面用next实现阶段的快速跳转
typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

// 阶段的checker函数
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// 存储handler/checker，里面用next实现阶段的快速跳转
// 是ngx_http_phase_engine_t.handlers里的元素
struct ngx_http_phase_handler_s {

    // 阶段的checker函数
    ngx_http_phase_handler_pt  checker;

    // 每个模块自己的处理函数
    ngx_http_handler_pt        handler;

    // 指向下一个阶段第一个模块在数组里的位置
    ngx_uint_t                 next;
};


// 所有的http请求都要使用这个引擎处理
typedef struct {
    // 存储所有handler/checker的数组，里面用next实现阶段的快速跳转
    ngx_http_phase_handler_t  *handlers;

    // server重写的跳转位置
    ngx_uint_t                 server_rewrite_index;

    // location重写的跳转位置
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;


// 存储在ngx_http_core_main_conf_t里
// 需要操作任何http请求的模块添加进这个数组
typedef struct {
    ngx_array_t                handlers;
} ngx_http_phase_t;


// ngx_http_core_main_conf_t
// 重要结构体，存储server、监听端口、变量等信息
typedef struct {
    // 存储http{}里定义的所有server，元素是ngx_http_core_srv_conf_t
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    // 所有的http请求都要使用这个引擎处理
    ngx_http_phase_engine_t    phase_engine;

    ngx_hash_t                 headers_in_hash;

    // 变量的散列表
    ngx_hash_t                 variables_hash;

    // 存储http里定义的所有变量
    ngx_array_t                variables;         /* ngx_http_variable_t */
    ngx_array_t                prefix_variables;  /* ngx_http_variable_t */

    ngx_uint_t                 ncaptures;

    // server散列表设置
    ngx_uint_t                 server_names_hash_max_size;
    ngx_uint_t                 server_names_hash_bucket_size;

    // 变量散列表设置
    // 由指令variables_hash_max_size/variables_hash_bucket_size设置
    ngx_uint_t                 variables_hash_max_size;
    ngx_uint_t                 variables_hash_bucket_size;

    // hash表初始化完毕，临时的variables_keys不再需要
    // 置为空指针，最后在tmp_pool时释放
    ngx_hash_keys_arrays_t    *variables_keys;

    // http{}里定义的所有监听端口
    ngx_array_t               *ports;

    // 1.13.4之前有
    //ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

    // http handler模块需要向这个数组添加元素
    // 在配置解析后的postconfiguration里向cmcf->phases数组注册
    // 在处理请求时不使用此数组，而是用的phase_engine
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;


// ngx_http_core_srv_conf_t
typedef struct {
    // 在ngx_http_core_server_name()里存储ngx_http_server_name_t
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    // 本server使用的配置结构体数组，避免多个server的冲突
    ngx_http_conf_ctx_t        *ctx;

    u_char                     *file_name;
    ngx_uint_t                  line;

    ngx_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    // 本server内的location
    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


// 保存server{}块里的server_name信息
// 在解析http请求头时调用ngx_http_process_request_line()
// 最后在ngx_http_set_virtual_server()里定位server{}块位置
typedef struct {
    // 正则表达式对象指针
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    // 指向本server{}块的配置信息
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */

    // 配置文件里的的server名字，如果没有默认取本机的hostname
    ngx_str_t                  name;
} ngx_http_server_name_t;


typedef struct {
    ngx_hash_combined_t        names;

    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;


typedef struct {
    ngx_int_t                  family;
    in_port_t                  port;
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;


typedef struct {
    ngx_http_listen_opt_t      opt;

    ngx_hash_t                 hash;
    ngx_hash_wildcard_t       *wc_head;
    ngx_hash_wildcard_t       *wc_tail;

#if (NGX_PCRE)
    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


// before 1.13.4
//typedef struct {
//    ngx_array_t               *lengths;
//    ngx_array_t               *values;
//    ngx_str_t                  name;
//
//    unsigned                   code:10;
//    unsigned                   test_dir:1;
//} ngx_http_try_file_t;


// location的配置结构体
// 重要的成员是handler，定义此location特有的内容处理函数
struct ngx_http_core_loc_conf_s {
    // location的名字
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;

    // named location，也就是@开头的location
    unsigned      named:1;

    // location精确匹配配置文件里的uri
    // 即使用'='前缀
    unsigned      exact_match:1;

    // ^~ 不使用正则，前缀匹配
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    // 重要的成员，定义此location特有的内容处理函数
    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */

    // 如果是alias别名功能，存储location的名字长度，即name.len
    size_t        alias;

    // 存储root/alias指定的路径
    ngx_str_t     root;                    /* root, alias */

    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    // 允许post的最大body长度
    off_t         client_max_body_size;    /* client_max_body_size */

    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */

    // 默认值是0,只有socket发送缓冲区大于此值才会触发可写事件
    size_t        send_lowat;              /* send_lowat */

    // 默认值是1460，只有数据大于这个值才会真正发送
    // 用于提高效率，避免频繁的系统调用
    size_t        postpone_output;         /* postpone_output */

    // 限制速率
    // 用在ngx_http_write_filter_module.c
    //size_t        limit_rate;              /* limit_rate */

    // 限制速率
    // 用在ngx_http_write_filter_module.c
    //size_t        limit_rate_after;        /* limit_rate_after */

    // 发送数据的限制，默认是0，即不限制，尽量多发
    // 用在ngx_http_write_filter_module.c
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */

    size_t        read_ahead;              /* read_ahead */
    size_t        subrequest_output_buffer_size;
                                           /* subrequest_output_buffer_size */

    // 1.17.0 新变量
    ngx_http_complex_value_t  *limit_rate; /* limit_rate */
    ngx_http_complex_value_t  *limit_rate_after; /* limit_rate_after */

    // 超时相关的参数
    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */
    ngx_msec_t    auth_delay;              /* auth_delay */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */

    // 注意，下面的这些标志量没有使用bit field特性，而是直接用ngx_flag_t

    // location只能被子请求调用，不能被外部访问
    ngx_flag_t    internal;                /* internal */

    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    aio;                     /* aio */
    ngx_flag_t    aio_write;               /* aio_write */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    absolute_redirect;       /* absolute_redirect */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */

    // 子请求是否记录日志，默认不记录
    ngx_flag_t    log_subrequest;          /* log_subrequest */

    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_uint_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_pool_t         *thread_pool;
    ngx_http_complex_value_t  *thread_pool_value;
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    // 使用queue串联起location
    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    ngx_queue_t                      queue;
    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;
    ngx_http_location_tree_node_t   *right;
    ngx_http_location_tree_node_t   *tree;

    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


// 启动引擎数组处理请求
// 从phase_handler的位置开始调用模块处理
void ngx_http_core_run_phases(ngx_http_request_t *r);

// 各个阶段使用的checker

// NGX_HTTP_POST_READ_PHASE/NGX_HTTP_PREACCESS_PHASE
// post read/pre-access只有一个模块会执行，之后的就跳过
//
// ok:模块已经处理成功，直接跳过本阶段
// decline:表示不处理,继续在本阶段（rewrite）里查找下一个模块
// again/done:暂时中断ngx_http_core_run_phases
//
// 由于r->write_event_handler = ngx_http_core_run_phases
// 当再有写事件时会继续从之前的模块执行
// 其他的错误，结束请求
// 但如果count>1，则不会真正结束
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// NGX_HTTP_SERVER_REWRITE_PHASE/NGX_HTTP_REWRITE_PHASE
// 使用的checker，参数是当前的引擎数组，里面的handler是每个模块自己的处理函数
//
// decline:表示不处理,继续在本阶段（rewrite）里查找下一个模块
// done:暂时中断ngx_http_core_run_phases
//
// 由于r->write_event_handler = ngx_http_core_run_phases
// 当再有写事件时会继续从之前的模块执行
// 其他的错误，结束请求
// 但如果count>1，则不会真正结束
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// 查找请求对应的location
// 设置location里的content_handler
// 检查本location里的最大body长度
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// 检查uri的改写次数，只能nginx框架处理，用户不可介入
// uri改写次数限制，最多10次，in ngx_http_create_request
// 次数减到0，那么就出错，不允许无限改写uri跳转
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// NGX_HTTP_ACCESS_PHASE checker
// 子请求不做访问控制，直接跳过本阶段
//
// decline:表示不处理,继续在本阶段（rewrite）里查找下一个模块
// again/done:暂时中断ngx_http_core_run_phases
//
// 由于r->write_event_handler = ngx_http_core_run_phases
// 当再有写事件时会继续从之前的模块执行
// 其他的错误，结束请求
// 但如果count>1，则不会真正结束
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// 检查access阶段设置的access_code
// 决定是否可以访问，即继续处理
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// 不研究
//ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
//    ngx_http_phase_handler_t *ph);

// 处理请求，产生响应内容，最常用的阶段
// 这已经是处理的最后阶段了（log阶段不处理请求，不算）
// 设置写事件为ngx_http_request_empty_handler
// 即暂时不再进入ngx_http_core_run_phases
// 之后发送数据时会改为ngx_http_set_write_handler
// 但我们也可以修改，让写事件触发我们自己的回调
// 检查请求是否有handler，也就是location里定义了handler
// 调用location专用的内容处理handler
// 返回值传递给ngx_http_finalize_request
// 相当于处理完后结束请求
//
// 没有专门的handler
// 调用每个模块自己的处理函数
// 模块handler返回decline，表示不处理
// 没有一个content模块可以处理,返回404
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


// 创建子请求对象，复制父请求的大部分字段
ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);

ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


// 当http请求结束时的清理动作
ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


// 响应头过滤函数原型
typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);

// 响应体过滤函数原型
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);

// 请求体过滤函数原型
typedef ngx_int_t (*ngx_http_request_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


// 发送响应数据，调用过滤链表，执行数据过滤
// 发送响应体，调用ngx_http_top_body_filter
// 走过整个body过滤链表
// 最后由ngx_http_write_filter真正的向客户端发送数据，调用send_chain
// 也由ngx_http_set_write_handler设置epoll的写事件触发
// 如果数据发送不完，就保存在r->out里，返回again
// 需要再次发生可写事件才能发送
// 不是last、flush，且数据量较小（默认1460）
// 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);

// 真正的向客户端发送数据，调用send_chain
// 也由ngx_http_set_write_handler设置epoll的写事件触发
// 如果数据发送不完，就保存在r->out里，返回again
// 需要再次发生可写事件才能发送
// 不是last、flush，且数据量较小（默认1460）
// 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
// 在此函数里处理限速
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);

// 参数in实际上是ngx_http_request_body_length_filter里的out，即读取到的数据
// 从内存池里分配节点
// 拷贝in链表里的buf到rb->bufs里，不是直接连接
// 同样是指针操作，没有内存拷贝
// 如果要求写磁盘文件，那么调用ngx_http_write_request_body
ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
    ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_array_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


// 简化操作宏，清除响应头里的长度信息
#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
