// annotated by chrono since 2016
//
// * ngx_stream_proxy_pass
// * ngx_stream_proxy_handler
// * ngx_stream_proxy_connect_handler
// * ngx_stream_proxy_init_upstream
// * ngx_stream_proxy_process

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


// 定义各种连接上游服务器的参数
// 例如超时、缓冲区大小
typedef struct {
    ngx_addr_t                      *addr;
    ngx_stream_complex_value_t      *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_stream_upstream_local_t;


// proxy_pass的各种配置参数，比较容易理解
typedef struct {
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    ngx_stream_complex_value_t      *upload_rate;
    ngx_stream_complex_value_t      *download_rate;
    ngx_uint_t                       requests;
    ngx_uint_t                       responses;
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       next_upstream;
    ngx_flag_t                       proxy_protocol;
    ngx_stream_upstream_local_t     *local;
    ngx_flag_t                       socket_keepalive;

#if (NGX_STREAM_SSL)
    ngx_flag_t                       ssl_enable;
    ngx_flag_t                       ssl_session_reuse;
    ngx_uint_t                       ssl_protocols;
    ngx_str_t                        ssl_ciphers;
    ngx_stream_complex_value_t      *ssl_name;
    ngx_flag_t                       ssl_server_name;

    ngx_flag_t                       ssl_verify;
    ngx_uint_t                       ssl_verify_depth;
    ngx_str_t                        ssl_trusted_certificate;
    ngx_str_t                        ssl_crl;
    ngx_str_t                        ssl_certificate;
    ngx_str_t                        ssl_certificate_key;
    ngx_array_t                     *ssl_passwords;

    ngx_ssl_t                       *ssl;
#endif

    // 将要转发的上游服务器集群
    // 定义为一个upstream{}
    ngx_stream_upstream_srv_conf_t  *upstream;

    // proxy_pass支持复杂变量
    ngx_stream_complex_value_t      *upstream_value;
} ngx_stream_proxy_srv_conf_t;


// ngx_stream_init_connection->ngx_stream_init_session之后调用，处理请求
// 即content handler
//
// 创建连接上游的结构体
// 里面有如何获取负载均衡server、上下游buf等
// 负载均衡算法初始化
// 准备开始连接，设置开始时间，秒数，没有毫秒
// 最后启动连接
static void ngx_stream_proxy_handler(ngx_stream_session_t *s);

static ngx_int_t ngx_stream_proxy_eval(ngx_stream_session_t *s,
    ngx_stream_proxy_srv_conf_t *pscf);
static ngx_int_t ngx_stream_proxy_set_local(ngx_stream_session_t *s,
    ngx_stream_upstream_t *u, ngx_stream_upstream_local_t *local);

// 连接上游
// 使用ngx_peer_connection_t连接上游服务器
// 连接失败，需要尝试下一个上游server
// 连接成功要调用init初始化上游
static void ngx_stream_proxy_connect(ngx_stream_session_t *s);

// 分配供上游读取数据的缓冲区
// 进入此函数，肯定已经成功连接了上游服务器
// 修改上游读写事件，不再测试连接，改为ngx_stream_proxy_upstream_handler
// 实际是ngx_stream_proxy_process_connection(ev, !ev->write);
static void ngx_stream_proxy_init_upstream(ngx_stream_session_t *s);

static void ngx_stream_proxy_resolve_handler(ngx_resolver_ctx_t *ctx);

// 连接成功之后的事件处理函数
// 实际是ngx_stream_proxy_process_connection(ev, !ev->write);
static void ngx_stream_proxy_upstream_handler(ngx_event_t *ev);

// 处理下游的handler
// ev->write==true，即向下游写数据
static void ngx_stream_proxy_downstream_handler(ngx_event_t *ev);

// 处理上下游的数据收发
// from_upstream参数标记是否是上游，使用的是ev->write
// 可读是上游，可写是下游
static void ngx_stream_proxy_process_connection(ngx_event_t *ev,
    ngx_uint_t from_upstream);

// 第一次连接上游不成功后的handler
// 当上游连接再次有读写事件发生时测试连接
// 测试连接是否成功，失败就再试下一个上游
// 最后还是要调用init初始化上游
static void ngx_stream_proxy_connect_handler(ngx_event_t *ev);

// 测试连接是否成功，失败就再试下一个上游
static ngx_int_t ngx_stream_proxy_test_connect(ngx_connection_t *c);

// 核心处理函数，处理两个连接的数据收发
// 可以处理上下游的数据收发
// 参数标记是否是上游、是否写数据
static void ngx_stream_proxy_process(ngx_stream_session_t *s,
    ngx_uint_t from_upstream, ngx_uint_t do_write);

// 1.15.7
static ngx_int_t ngx_stream_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream);

// 连接失败，尝试下一个上游server
static void ngx_stream_proxy_next_upstream(ngx_stream_session_t *s);

// 关闭上下游的连接
static void ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);

static u_char *ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf,
    size_t len);

// 配置结构体相关函数，比较简单
static void *ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

// 解析proxy_pass指令，设置处理handler，在init建立连接之后会调用
// 获取一个upstream{}块的配置信息
static char *ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#if (NGX_STREAM_SSL)

static ngx_int_t ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s);
static char *ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s);
static void ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc);
static void ngx_stream_proxy_ssl_save_session(ngx_connection_t *c);
static ngx_int_t ngx_stream_proxy_ssl_name(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_proxy_set_ssl(ngx_conf_t *cf,
    ngx_stream_proxy_srv_conf_t *pscf);


static ngx_conf_bitmask_t  ngx_stream_proxy_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_string("TLSv1.3"), NGX_SSL_TLSv1_3 },
    { ngx_null_string, 0 }
};

#endif


static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_downstream_buffer = {
    ngx_conf_deprecated, "proxy_downstream_buffer", "proxy_buffer_size"
};

static ngx_conf_deprecated_t  ngx_conf_deprecated_proxy_upstream_buffer = {
    ngx_conf_deprecated, "proxy_upstream_buffer", "proxy_buffer_size"
};


// proxy模块定义的各种指令
static ngx_command_t  ngx_stream_proxy_commands[] = {

    // 关键指令， 设置处理handler，在init建立连接之后会调用
    { ngx_string("proxy_pass"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_proxy_pass,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_bind"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE12,
      ngx_stream_proxy_bind,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_socket_keepalive"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, socket_keepalive),
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, timeout),
      NULL },

    { ngx_string("proxy_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_downstream_buffer"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      &ngx_conf_deprecated_proxy_downstream_buffer },

    { ngx_string("proxy_upstream_buffer"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, buffer_size),
      &ngx_conf_deprecated_proxy_upstream_buffer },

    { ngx_string("proxy_upload_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, upload_rate),
      NULL },

    { ngx_string("proxy_download_rate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, download_rate),
      NULL },

    { ngx_string("proxy_requests"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, requests),
      NULL },

    { ngx_string("proxy_responses"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, responses),
      NULL },

    { ngx_string("proxy_next_upstream"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream),
      NULL },

    { ngx_string("proxy_next_upstream_tries"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_tries),
      NULL },

    { ngx_string("proxy_next_upstream_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, next_upstream_timeout),
      NULL },

    { ngx_string("proxy_protocol"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, proxy_protocol),
      NULL },

#if (NGX_STREAM_SSL)

    { ngx_string("proxy_ssl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_enable),
      NULL },

    { ngx_string("proxy_ssl_session_reuse"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_session_reuse),
      NULL },

    { ngx_string("proxy_ssl_protocols"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_protocols),
      &ngx_stream_proxy_ssl_protocols },

    { ngx_string("proxy_ssl_ciphers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("proxy_ssl_name"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_set_complex_value_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_name),
      NULL },

    { ngx_string("proxy_ssl_server_name"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_server_name),
      NULL },

    { ngx_string("proxy_ssl_verify"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify),
      NULL },

    { ngx_string("proxy_ssl_verify_depth"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("proxy_ssl_trusted_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("proxy_ssl_crl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_crl),
      NULL },

    { ngx_string("proxy_ssl_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate),
      NULL },

    { ngx_string("proxy_ssl_certificate_key"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_proxy_srv_conf_t, ssl_certificate_key),
      NULL },

    { ngx_string("proxy_ssl_password_file"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_proxy_ssl_password_file,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

#endif

      ngx_null_command
};


// 没有main配置，都在server{}里
static ngx_stream_module_t  ngx_stream_proxy_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_proxy_create_srv_conf,      /* create server configuration */
    ngx_stream_proxy_merge_srv_conf        /* merge server configuration */
};


// 模块功能集成定义
ngx_module_t  ngx_stream_proxy_module = {
    NGX_MODULE_V1,
    &ngx_stream_proxy_module_ctx,          /* module context */
    ngx_stream_proxy_commands,             /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// ngx_stream_init_connection->ngx_stream_init_session之后调用，处理请求
// 创建连接上游的结构体
// 里面有如何获取负载均衡server、上下游buf等
// 负载均衡算法初始化
// 准备开始连接，设置开始时间，秒数，没有毫秒
// 使用内存池分配接收数据的缓冲区
// 最后启动连接
static void
ngx_stream_proxy_handler(ngx_stream_session_t *s)
{
    u_char                           *p;
    ngx_str_t                        *host;
    ngx_uint_t                        i;
    ngx_connection_t                 *c;
    ngx_resolver_ctx_t               *ctx, temp;
    ngx_stream_upstream_t            *u;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_proxy_srv_conf_t      *pscf;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    // 获取连接对象
    c = s->connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy connection handler");

    // 创建连接上游的结构体
    // 里面有如何获取负载均衡server、上下游buf等
    u = ngx_pcalloc(c->pool, sizeof(ngx_stream_upstream_t));
    if (u == NULL) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    // 关联到会话对象
    s->upstream = u;

    s->log_handler = ngx_stream_proxy_log_error;

    // 1.15新增
    u->requests = 1;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR_ERR;

    if (ngx_stream_proxy_set_local(s, u, pscf->local) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    // 连接的类型，tcp or udp
    u->peer.type = c->type;

    // 开始连接后端的时间
    // 准备开始连接，设置开始时间，秒数，没有毫秒
    u->start_sec = ngx_time();

    // 连接的读写事件都设置为ngx_stream_proxy_downstream_handler
    // 注意这个连接是客户端发起的连接，即下游
    // 当客户端连接可读或可写时就会调用ngx_stream_proxy_downstream_handler
    c->write->handler = ngx_stream_proxy_downstream_handler;
    c->read->handler = ngx_stream_proxy_downstream_handler;

    // 使用数组，可能会连接多个上游服务器
    s->upstream_states = ngx_array_create(c->pool, 1,
                                          sizeof(ngx_stream_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    // 1.15给udp/tcp都创建一个缓冲区，用来接收数据
    p = ngx_pnalloc(c->pool, pscf->buffer_size);
    if (p == NULL) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    // 注意是给下游使用的缓冲区
    u->downstream_buf.start = p;
    u->downstream_buf.end = p + pscf->buffer_size;
    u->downstream_buf.pos = p;
    u->downstream_buf.last = p;

    // 连接可读，表示客户端有数据发过来
    // 加入到&ngx_posted_events
    // 稍后由ngx_stream_proxy_downstream_handler来处理
    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    // udp不需要，始终用一个固定大小的数组接收数据

    // proxy_pass支持复杂变量
    // 如果使用了"proxy_pass $xxx"，那么就要解析复杂变量
    if (pscf->upstream_value) {
        if (ngx_stream_proxy_eval(s, pscf) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    // 检查proxy_pass的目标地址
    if (u->resolved == NULL) {

        uscf = pscf->upstream;

    } else {

#if (NGX_STREAM_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        // 获取上游的配置结构体
        // 在ngx_stream_proxy_pass里设置的
        //uscf = pscf->upstream;

        umcf = ngx_stream_get_module_main_conf(s, ngx_stream_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && ngx_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "no port in upstream \"%V\"", host);
                ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_stream_upstream_create_round_robin_peer(s, u->resolved)
                != NGX_OK)
            {
                ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_stream_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no port in upstream \"%V\"", host);
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

        ctx = ngx_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no resolver defined to resolve %V", host);
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = ngx_stream_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "no upstream configuration");
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (NGX_STREAM_SSL)
    u->ssl_name = uscf->host;
#endif

    // 负载均衡算法初始化
    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    // 准备开始连接，设置开始时间，毫秒
    u->peer.start_time = ngx_current_msec;

    // 设置负载均衡的重试次数
    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    //u->proxy_protocol = pscf->proxy_protocol;

    // 最后启动连接
    // 使用ngx_peer_connection_t连接上游服务器
    // 连接失败，需要尝试下一个上游server
    // 连接成功要调用init初始化上游
    ngx_stream_proxy_connect(s);
}


// proxy_pass支持复杂变量
// 如果使用了"proxy_pass $xxx"，那么就要解析复杂变量
static ngx_int_t
ngx_stream_proxy_eval(ngx_stream_session_t *s,
    ngx_stream_proxy_srv_conf_t *pscf)
{
    ngx_str_t               host;
    ngx_url_t               url;
    ngx_stream_upstream_t  *u;

    if (ngx_stream_complex_value(s, pscf->upstream_value, &host) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u = s->upstream;

    u->resolved = ngx_pcalloc(s->connection->pool,
                              sizeof(ngx_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_proxy_set_local(ngx_stream_session_t *s, ngx_stream_upstream_t *u,
    ngx_stream_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_stream_complex_value(s, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        return NGX_OK;
    }

    addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}


// 连接上游
// 使用ngx_peer_connection_t连接上游服务器
// 连接失败，需要尝试下一个上游server
// 连接成功要调用init初始化上游
static void
ngx_stream_proxy_connect(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    // 获取连接对象
    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    // 连接上游的结构体
    // 里面有如何获取负载均衡server、上下游buf等
    u = s->upstream;

    u->connected = 0;
    u->proxy_protocol = pscf->proxy_protocol;

    // 何时会执行这个？
    if (u->state) {
        u->state->response_time = ngx_current_msec - u->start_time;
    }

    // 把一个上游的状态添加进会话的数组
    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_stream_upstream_state_t));

    // 1.15.7
    u->start_time = ngx_current_msec;

    // 这两个值置为-1，表示未初始化
    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;

    // 用来计算响应时间，保存当前的毫秒值
    // 之后连接成功后就会两者相减
    u->state->response_time = (ngx_msec_t) -1;

    // 连接上游
    // 使用ngx_peer_connection_t连接上游服务器
    // 从upstream{}里获取一个上游server地址
    // 从cycle的连接池获取一个空闲连接
    // 设置连接的数据收发接口函数
    // 向epoll添加连接，即同时添加读写事件
    // 当与上游服务器有任何数据收发时都会触发epoll
    // socket api调用连接上游服务器
    // 写事件ready，即可以立即向上游发送数据
    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    // 所有上游都busy
    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_stream_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    // 连接失败，需要尝试下一个上游server
    if (rc == NGX_DECLINED) {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    // 连接“成功”，again/done表示正在连接过程中

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    // 连接成功
    // 分配供上游读取数据的缓冲区
    // 修改上游读写事件，不再测试连接，改为ngx_stream_proxy_upstream_handler
    // 实际是ngx_stream_proxy_process_connection(ev, !ev->write);
    if (rc != NGX_AGAIN) {
        ngx_stream_proxy_init_upstream(s);
        return;
    }

    // again，要再次尝试连接

    // 设置上游的读写事件处理函数是ngx_stream_proxy_connect_handler
    // 第一次连接上游不成功后的handler
    // 当上游连接再次有读写事件发生时测试连接
    // 测试连接是否成功，失败就再试下一个上游
    // 最后还是要调用init初始化上游
    pc->read->handler = ngx_stream_proxy_connect_handler;
    pc->write->handler = ngx_stream_proxy_connect_handler;

    // 连接上游先写，所以设置写事件的超时时间
    ngx_add_timer(pc->write, pscf->connect_timeout);
}


// 分配供上游读取数据的缓冲区
// 进入此函数，肯定已经成功连接了上游服务器
// 修改上游读写事件，不再测试连接，改为ngx_stream_proxy_upstream_handler
// 实际是ngx_stream_proxy_process_connection(ev, !ev->write);
static void
ngx_stream_proxy_init_upstream(ngx_stream_session_t *s)
{
    u_char                       *p;
    ngx_chain_t                  *cl;
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_proxy_srv_conf_t  *pscf;

    // u保存了上游相关的信息
    u = s->upstream;

    // pc是上游的连接对象
    pc = u->peer.connection;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    if (pc->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(pc) != NGX_OK)
    {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

#if (NGX_STREAM_SSL)

    if (pc->type == SOCK_STREAM && pscf->ssl) {

        if (u->proxy_protocol) {
            if (ngx_stream_proxy_send_proxy_protocol(s) != NGX_OK) {
                return;
            }

            u->proxy_protocol = 0;
        }

        if (pc->ssl == NULL) {
            ngx_stream_proxy_ssl_init_connection(s);
            return;
        }
    }

#endif

    // c是到客户端即下游的连接对象
    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t  str;
        u_char     addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "%sproxy %V connected to %V",
                          pc->type == SOCK_DGRAM ? "udp " : "",
                          &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    // before 1.15.7
    // u->state->connect_time = ngx_current_msec - u->state->response_time;
    // 计算连接使用的时间，毫秒值
    u->state->connect_time = ngx_current_msec - u->start_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
                       NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
    }

    //c->log->action = "proxying connection";

    // 检查给上游使用的缓冲区
    if (u->upstream_buf.start == NULL) {

        // 分配供上游读取数据的缓冲区
        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    // 此时u里面上下游都有缓冲区了

    // udp处理
    // if (c->type == SOCK_DGRAM) {
    //     // 使用客户端连接的buffer计算收到的字节数
    //     s->received = c->buffer->last - c->buffer->pos;

    //     // nginx 1.11.x删除了此行代码！！
    //     // downstream_buf直接就是客户端连接的buffer
    //     u->downstream_buf = *c->buffer;


    // 客户端里已经发来了一些数据
    if (c->buffer && c->buffer->pos < c->buffer->last) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add preread buffer: %uz",
                       c->buffer->last - c->buffer->pos);

        // 拿一个链表节点
        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        // 把连接的缓冲区关联到链表节点里
        *cl->buf = *c->buffer;

        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;
        cl->buf->flush = 1;

        // 1.15.0之前udp特殊处理，直接是最后一块数据，所以Nginx暂不支持udp会话
        // cl->buf->last_buf = (c->type == SOCK_DGRAM);

        // 把数据挂到upstream_out里，要发给上游
        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }

    if (u->proxy_protocol) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream proxy add PROXY protocol header");

        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        p = ngx_pnalloc(c->pool, NGX_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->pos = p;

        p = ngx_proxy_protocol_write(c, p, p + NGX_PROXY_PROTOCOL_MAX_HEADER);
        if (p == NULL) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        cl->buf->last = p;
        cl->buf->temporary = 1;
        cl->buf->flush = 0;
        cl->buf->last_buf = 0;
        cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;

        cl->next = u->upstream_out;
        u->upstream_out = cl;

        u->proxy_protocol = 0;
    }

    // 进入此函数，肯定已经成功连接了上游服务器

    // 1.17.0
    u->upload_rate = ngx_stream_complex_value_size(s, pscf->upload_rate, 0);
    u->download_rate = ngx_stream_complex_value_size(s, pscf->download_rate, 0);

    u->connected = 1;

    // 修改上游读写事件，不再测试连接，改为ngx_stream_proxy_upstream_handler
    // 实际是ngx_stream_proxy_process_connection(ev, !ev->write);
    pc->read->handler = ngx_stream_proxy_upstream_handler;
    pc->write->handler = ngx_stream_proxy_upstream_handler;

    if (pc->read->ready) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    // 参数表示上游连接，上游可写
    ngx_stream_proxy_process(s, 0, 1);
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_proxy_send_proxy_protocol(ngx_stream_session_t *s)
{
    u_char                       *p;
    ssize_t                       n, size;
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;
    u_char                        buf[NGX_PROXY_PROTOCOL_MAX_HEADER];

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy send PROXY protocol header");

    p = ngx_proxy_protocol_write(c, buf, buf + NGX_PROXY_PROTOCOL_MAX_HEADER);
    if (p == NULL) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    u = s->upstream;

    pc = u->peer.connection;

    size = p - buf;

    n = pc->send(pc, buf, size);

    if (n == NGX_AGAIN) {
        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

        ngx_add_timer(pc->write, pscf->timeout);

        pc->write->handler = ngx_stream_proxy_connect_handler;

        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
        return NGX_ERROR;
    }

    if (n != size) {

        /*
         * PROXY protocol specification:
         * The sender must always ensure that the header
         * is sent at once, so that the transport layer
         * maintains atomicity along the path to the receiver.
         */

        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "could not send PROXY protocol header at once");

        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);

        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_stream_proxy_ssl_password_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_str_t  *value;

    if (pscf->ssl_passwords != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    pscf->ssl_passwords = ngx_ssl_read_password_file(cf, &value[1]);

    if (pscf->ssl_passwords == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_stream_proxy_ssl_init_connection(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    u = s->upstream;

    pc = u->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (ngx_ssl_create_connection(pscf->ssl, pc, NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (pscf->ssl_server_name || pscf->ssl_verify) {
        if (ngx_stream_proxy_ssl_name(s) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (pscf->ssl_session_reuse) {
        pc->ssl->save_session = ngx_stream_proxy_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    s->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(pc);

    if (rc == NGX_AGAIN) {

        if (!pc->write->timer_set) {
            ngx_add_timer(pc->write, pscf->connect_timeout);
        }

        pc->ssl->handler = ngx_stream_proxy_ssl_handshake;
        return;
    }

    ngx_stream_proxy_ssl_handshake(pc);
}


static void
ngx_stream_proxy_ssl_handshake(ngx_connection_t *pc)
{
    long                          rc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    s = pc->data;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (pc->ssl->handshaked) {

        if (pscf->ssl_verify) {
            rc = SSL_get_verify_result(pc->ssl->connection);

            if (rc != X509_V_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            u = s->upstream;

            if (ngx_ssl_check_host(pc, &u->ssl_name) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        ngx_stream_proxy_init_upstream(s);

        return;
    }

failed:

    ngx_stream_proxy_next_upstream(s);
}


static void
ngx_stream_proxy_ssl_save_session(ngx_connection_t *c)
{
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = c->data;
    u = s->upstream;

    u->peer.save_session(&u->peer, u->peer.data);
}


static ngx_int_t
ngx_stream_proxy_ssl_name(ngx_stream_session_t *s)
{
    u_char                       *p, *last;
    ngx_str_t                     name;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    u = s->upstream;

    if (pscf->ssl_name) {
        if (ngx_stream_complex_value(s, pscf->ssl_name, &name) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, strip it for compatibility
     * with the http module
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = ngx_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = ngx_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!pscf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (ngx_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = ngx_pnalloc(s->connection->pool, name.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(u->peer.connection->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_ERR, s->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return NGX_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return NGX_OK;
}

#endif


// 处理下游的handler
// ev->write==true，即向下游写数据
static void
ngx_stream_proxy_downstream_handler(ngx_event_t *ev)
{
    ngx_stream_proxy_process_connection(ev, ev->write);
}


static void
ngx_stream_proxy_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_stream_session_t            *s;
    ngx_stream_upstream_t           *u;
    ngx_stream_proxy_srv_conf_t     *pscf;
    ngx_stream_upstream_resolved_t  *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream upstream resolve");

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    u_char      text[NGX_SOCKADDR_STRLEN];
    ngx_str_t   addr;
    ngx_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, NGX_SOCKADDR_STRLEN, 0);

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (ngx_stream_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    if (pscf->next_upstream_tries
        && u->peer.tries > pscf->next_upstream_tries)
    {
        u->peer.tries = pscf->next_upstream_tries;
    }

    // 连接上游
    // 使用ngx_peer_connection_t连接上游服务器
    // 连接失败，需要尝试下一个上游server
    // 连接成功要调用init初始化上游
    ngx_stream_proxy_connect(s);
}


// 连接成功之后的事件处理函数
// 实际是ngx_stream_proxy_process_connection(ev, !ev->write);
// 即从上游读数据
static void
ngx_stream_proxy_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_proxy_process_connection(ev, !ev->write);
}


// 处理上下游的数据收发
// from_upstream参数标记是否是上游，使用的是ev->write
// 可读是上游，可写是下游
static void
ngx_stream_proxy_process_connection(ngx_event_t *ev, ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    // 连接、会话、上游
    c = ev->data;
    s = c->data;
    u = s->upstream;

    if (c->close) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");
        ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    // c是下游连接，pc是上游连接
    c = s->connection;
    pc = u->peer.connection;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    // 超时处理，没有delay则失败
    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    ngx_stream_proxy_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, pscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {

                if (pscf->responses == NGX_MAX_INT32_VALUE
                    || (u->responses >= pscf->responses * u->requests))
                {

                    /*
                     * successfully terminate timed out UDP session
                     * if expected number of responses was received
                     */

                    handler = c->log->handler;
                    c->log->handler = NULL;

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "udp timed out"
                                  ", packets from/to client:%ui/%ui"
                                  ", bytes from/to client:%O/%O"
                                  ", bytes from/to upstream:%O/%O",
                                  u->requests, u->responses,
                                  s->received, c->sent, u->received,
                                  pc ? pc->sent : 0);

                    c->log->handler = handler;

                    ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
                    return;
                }

                ngx_connection_error(pc, NGX_ETIMEDOUT, "upstream timed out");

                pc->read->error = 1;

                ngx_stream_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);

                return;
            }

            ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");

            ngx_stream_proxy_finalize(s, NGX_STREAM_OK);

            return;
        }

    } else if (ev->delayed) {

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    // 核心处理函数，处理两个连接的数据收发
    ngx_stream_proxy_process(s, from_upstream, ev->write);
}


// 第一次连接上游不成功后的handler
// 当上游连接再次有读写事件发生时测试连接
// 测试连接是否成功，失败就再试下一个上游
// 最后还是要调用init初始化上游
static void
ngx_stream_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_stream_session_t  *s;

    // 连接、会话对象
    c = ev->data;
    s = c->data;

    // 超时就尝试下一个上游
    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream proxy connect upstream");

    // 测试连接是否成功，失败就再试下一个上游
    if (ngx_stream_proxy_test_connect(c) != NGX_OK) {
        ngx_stream_proxy_next_upstream(s);
        return;
    }

    // 最后还是要调用init初始化上游
    ngx_stream_proxy_init_upstream(s);
}


// 测试连接是否成功，失败就再试下一个上游
static ngx_int_t
ngx_stream_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


// 核心处理函数，处理两个连接的数据收发
// 可以处理上下游的数据收发
// 参数标记是否是上游、是否写数据
static void
ngx_stream_proxy_process(ngx_stream_session_t *s, ngx_uint_t from_upstream,
    ngx_uint_t do_write)
{
    char                         *recv_action, *send_action;
    off_t                        *received, limit;
    size_t                        size, limit_rate;
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_int_t                     rc;
    ngx_uint_t                    flags, *packets;
    ngx_msec_t                    delay;
    ngx_chain_t                  *cl, **ll, **out, **busy;
    ngx_connection_t             *c, *pc, *src, *dst;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    // u是上游结构体
    u = s->upstream;

    // c是下游的连接
    c = s->connection;

    // pc是上游的连接，如果连接失败就是nullptr
    pc = u->connected ? u->peer.connection : NULL;

    // nginx处于即将停止状态，连接是udp
    // 使用连接的log记录日志
    if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    // 取proxy模块的配置
    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    // 根据上下游状态决定来源和目标
    // 以及缓冲区、限速等
    // 注意使用的缓冲区指针
    if (from_upstream) {
        // 数据下行
        src = pc;
        dst = c;

        // 缓冲区是upstream_buf，即上游来的数据
        b = &u->upstream_buf;

        //limit_rate = pscf->download_rate;
        // 1.17.0
        limit_rate = u->download_rate;

        received = &u->received;
        packets = &u->responses;
        out = &u->downstream_out;
        busy = &u->downstream_busy;
        recv_action = "proxying and reading from upstream";
        send_action = "proxying and sending to client";

    } else {
        // 数据上行
        src = c;
        dst = pc;

        // 缓冲区是downstream_buf，即下游来的数据
        // 早期downstream_buf直接就是客户端连接的buffer
        // 现在是一个正常分配的buffer
        b = &u->downstream_buf;

        //limit_rate = pscf->upload_rate;
        // 1.17.0
        limit_rate = u->upload_rate;

        received = &s->received;
        packets = &u->requests;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
        recv_action = "proxying and reading from client";
        send_action = "proxying and sending to upstream";
    }

    // b指向当前需要操作的缓冲区
    // 死循环操作，直到出错或者again
    for ( ;; ) {

        // 如果要求写，那么把缓冲区里的数据发到dst
        if (do_write && dst) {

            // 条件是有数据，且dst连接是可写的
            if (*out || *busy || dst->buffered) {
                c->log->action = send_action;

                // 调用filter过滤链表，过滤数据最后发出去
                rc = ngx_stream_top_filter(s, *out, from_upstream);

                if (rc == NGX_ERROR) {
                    ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
                    return;
                }

                // 调整缓冲区链表，节约内存使用
                ngx_chain_update_chains(c->pool, &u->free, busy, out,
                                      (ngx_buf_tag_t) &ngx_stream_proxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }

                // n = ngx_again，需要等待可写才能再次发送
            }
        }

        // size是缓冲区的剩余可用空间
        size = b->end - b->last;

        // 如果缓冲区有剩余，且src还可以读数据
        if (size && src->read->ready && !src->read->delayed
            && !src->read->error)
        {

            // 限速处理
            if (limit_rate) {
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                if (c->type == SOCK_STREAM && (off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            c->log->action = recv_action;

            // 尽量读满缓冲区
            n = src->recv(src, b->last, size);

            // nginx 1.11.x代码不同，只判断NGX_AGAIN

            // 如果不可读，或者已经读完
            // break结束for循环
            if (n == NGX_AGAIN) {
                break;
            }

            // 出错，标记为eof
            if (n == NGX_ERROR) {
                src->read->eof = 1;
                n = 0;
            }

            // nginx 1.11.x代码不同，判断n >= 0
            // 读取了n字节的数据
            if (n >= 0) {

                // 限速
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec
                                                    - u->start_time;
                    }
                }

                // 找到链表末尾
                for (ll = out; *ll; ll = &(*ll)->next) { /* void */ }

                // 把读到的数据挂到链表末尾
                cl = ngx_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    ngx_stream_proxy_finalize(s,
                                              NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_stream_proxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                // 增加接收的包数
                // packets = &u->requests;
                // packets = &u->responses;
                (*packets)++;

                // 增加接收的数据字节数
                *received += n;

                // 缓冲区的末尾指针移动，表示收到了n字节新数据
                b->last += n;

                // 有数据，那么就可以继续向dst发送
                do_write = 1;

                // 回到for循环开头，继续发送数据
                continue;
            }
        }   // 读数据部分结束

        break;
    }   // for循环结束

    c->log->action = "proxying connection";

    // before 1.15.7
    // 这时应该是src已经读完，数据也发送完
    // 读取出错也会有eof标志
    //if (src->read->eof && dst && (dst->read->eof || !dst->buffered)) {
    //if (c->type == SOCK_DGRAM
    //    && pscf->responses != NGX_MAX_INT32_VALUE
    //    && u->responses >= pscf->responses * u->requests
    //    && !src->buffered && dst && !dst->buffered)
    //{
    //    handler = c->log->handler;
    //    c->log->handler = NULL;

    //    ngx_log_error(NGX_LOG_INFO, c->log, 0,
    //                  "udp done"
    //                  ", packets from/to client:%ui/%ui"
    //                  ", bytes from/to client:%O/%O"
    //                  ", bytes from/to upstream:%O/%O",
    //                  u->requests, u->responses,
    //                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    //    c->log->handler = handler;

    //    ngx_stream_proxy_finalize(s, NGX_STREAM_OK);
    //    return;
    //}

    //if (c->type == SOCK_STREAM
    //    && src->read->eof && dst && (dst->read->eof || !dst->buffered))
    //{
    //    handler = c->log->handler;
    //    c->log->handler = NULL;

    //    ngx_log_error(NGX_LOG_INFO, c->log, 0,
    //                  "%s disconnected"
    //                  ", bytes from/to client:%O/%O"
    //                  ", bytes from/to upstream:%O/%O",
    //                  from_upstream ? "upstream" : "client",
    //                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    //    c->log->handler = handler;

    //    // 在这里记录访问日志
    //    ngx_stream_proxy_finalize(s, NGX_STREAM_OK);

    if (ngx_stream_proxy_test_finalize(s, from_upstream) == NGX_OK) {
        return;
    }

    // 如果eof就要关闭读事件
    flags = src->read->eof ? NGX_CLOSE_EVENT : 0;

    if (ngx_handle_read_event(src->read, flags) != NGX_OK) {
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {
        if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, pscf->timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}


// 1.15.7
static ngx_int_t
ngx_stream_proxy_test_finalize(ngx_stream_session_t *s,
    ngx_uint_t from_upstream)
{
    ngx_connection_t             *c, *pc;
    ngx_log_handler_pt            handler;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    c = s->connection;
    u = s->upstream;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM) {

        if (pscf->requests && u->requests < pscf->requests) {
            return NGX_DECLINED;
        }

        if (pscf->requests) {
            ngx_delete_udp_connection(c);
        }

        if (pscf->responses == NGX_MAX_INT32_VALUE
            || u->responses < pscf->responses * u->requests)
        {
            return NGX_DECLINED;
        }

        if (pc == NULL || c->buffered || pc->buffered) {
            return NGX_DECLINED;
        }

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "udp done"
                      ", packets from/to client:%ui/%ui"
                      ", bytes from/to client:%O/%O"
                      ", bytes from/to upstream:%O/%O",
                      u->requests, u->responses,
                      s->received, c->sent, u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        ngx_stream_proxy_finalize(s, NGX_STREAM_OK);

        return NGX_OK;
    }

    /* c->type == SOCK_STREAM */

    if (pc == NULL
        || (!c->read->eof && !pc->read->eof)
        || (!c->read->eof && c->buffered)
        || (!pc->read->eof && pc->buffered))
    {
        return NGX_DECLINED;
    }

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "%s disconnected"
                  ", bytes from/to client:%O/%O"
                  ", bytes from/to upstream:%O/%O",
                  from_upstream ? "upstream" : "client",
                  s->received, c->sent, u->received, pc ? pc->sent : 0);

    c->log->handler = handler;

    ngx_stream_proxy_finalize(s, NGX_STREAM_OK);

    return NGX_OK;
}


// 连接失败，尝试下一个上游server
static void
ngx_stream_proxy_next_upstream(ngx_stream_session_t *s)
{
    ngx_msec_t                    timeout;
    ngx_connection_t             *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_proxy_srv_conf_t  *pscf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (pc && pc->buffered) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "buffered data on next upstream");
        ngx_stream_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (s->connection->type == SOCK_DGRAM) {
        u->upstream_out = NULL;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0
        || !pscf->next_upstream
        || (timeout && ngx_current_msec - u->peer.start_time >= timeout))
    {
        ngx_stream_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            pc->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(pc);
        }
#endif

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    // 连接上游
    // 使用ngx_peer_connection_t连接上游服务器
    // 连接失败，需要尝试下一个上游server
    // 连接成功要调用init初始化上游
    ngx_stream_proxy_connect(s);
}


// 关闭上下游的连接
static void
ngx_stream_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            u->state->response_time = ngx_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}


static u_char *
ngx_stream_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}


static void *
ngx_stream_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_proxy_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_name = NULL;
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     *
     *     conf->upload_rate = NULL;
     *     conf->download_rate = NULL;
     *     conf->ssl = NULL;
     *     conf->upstream = NULL;
     *     conf->upstream_value = NULL;
     */

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->requests = NGX_CONF_UNSET_UINT;
    conf->responses = NGX_CONF_UNSET_UINT;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->next_upstream = NGX_CONF_UNSET;
    conf->proxy_protocol = NGX_CONF_UNSET;
    conf->local = NGX_CONF_UNSET_PTR;
    conf->socket_keepalive = NGX_CONF_UNSET;

#if (NGX_STREAM_SSL)
    conf->ssl_enable = NGX_CONF_UNSET;
    conf->ssl_session_reuse = NGX_CONF_UNSET;
    conf->ssl_server_name = NGX_CONF_UNSET;
    conf->ssl_verify = NGX_CONF_UNSET;
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
    conf->ssl_passwords = NGX_CONF_UNSET_PTR;
#endif

    return conf;
}


static char *
ngx_stream_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_proxy_srv_conf_t *prev = parent;
    ngx_stream_proxy_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout,
                              prev->timeout, 10 * 60000);

    ngx_conf_merge_msec_value(conf->next_upstream_timeout,
                              prev->next_upstream_timeout, 0);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size, 16384);

    if (conf->upload_rate == NULL) {
        conf->upload_rate = prev->upload_rate;
    }

    if (conf->download_rate == NULL) {
        conf->download_rate = prev->download_rate;
    }

    ngx_conf_merge_uint_value(conf->requests,
                              prev->requests, 0);

    ngx_conf_merge_uint_value(conf->responses,
                              prev->responses, NGX_MAX_INT32_VALUE);

    ngx_conf_merge_uint_value(conf->next_upstream_tries,
                              prev->next_upstream_tries, 0);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    ngx_conf_merge_value(conf->proxy_protocol, prev->proxy_protocol, 0);

    ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);

    ngx_conf_merge_value(conf->socket_keepalive,
                              prev->socket_keepalive, 0);

#if (NGX_STREAM_SSL)

    ngx_conf_merge_value(conf->ssl_enable, prev->ssl_enable, 0);

    ngx_conf_merge_value(conf->ssl_session_reuse,
                              prev->ssl_session_reuse, 1);

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                              (NGX_CONF_BITMASK_SET|NGX_SSL_TLSv1
                               |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers, "DEFAULT");

    if (conf->ssl_name == NULL) {
        conf->ssl_name = prev->ssl_name;
    }

    ngx_conf_merge_value(conf->ssl_server_name, prev->ssl_server_name, 0);

    ngx_conf_merge_value(conf->ssl_verify, prev->ssl_verify, 0);

    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);

    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    ngx_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");

    ngx_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");

    ngx_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl_enable && ngx_stream_proxy_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    return NGX_CONF_OK;
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_proxy_set_ssl(ngx_conf_t *cf, ngx_stream_proxy_srv_conf_t *pscf)
{
    ngx_pool_cleanup_t  *cln;

    pscf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (pscf->ssl == NULL) {
        return NGX_ERROR;
    }

    pscf->ssl->log = cf->log;

    if (ngx_ssl_create(pscf->ssl, pscf->ssl_protocols, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(pscf->ssl);
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = pscf->ssl;

    if (pscf->ssl_certificate.len) {

        if (pscf->ssl_certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &pscf->ssl_certificate);
            return NGX_ERROR;
        }

        if (ngx_ssl_certificate(cf, pscf->ssl, &pscf->ssl_certificate,
                                &pscf->ssl_certificate_key, pscf->ssl_passwords)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_ciphers(cf, pscf->ssl, &pscf->ssl_ciphers, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (pscf->ssl_verify) {
        if (pscf->ssl_trusted_certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return NGX_ERROR;
        }

        if (ngx_ssl_trusted_certificate(cf, pscf->ssl,
                                        &pscf->ssl_trusted_certificate,
                                        pscf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_ssl_crl(cf, pscf->ssl, &pscf->ssl_crl) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_ssl_client_session_cache(cf, pscf->ssl, pscf->ssl_session_reuse)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


// 解析proxy_pass指令，设置处理handler，在init建立连接之后会调用
// 获取一个upstream{}块的配置信息
static char *
ngx_stream_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_url_t                            u;
    ngx_str_t                           *value, *url;
    ngx_stream_complex_value_t           cv;
    ngx_stream_core_srv_conf_t          *cscf;
    ngx_stream_compile_complex_value_t   ccv;

    // upstream是将要转发的上游服务器集群
    // 如果不空表示指令重复定义了
    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    // 设置处理handler，在init建立连接之后会调用
    cscf->handler = ngx_stream_proxy_handler;

    // 获取upstream名字
    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths) {
        pscf->upstream_value = ngx_palloc(cf->pool,
                                          sizeof(ngx_stream_complex_value_t));
        if (pscf->upstream_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *pscf->upstream_value = cv;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    // 获取一个upstream{}块的配置信息
    // 获取时flags==0
    pscf->upstream = ngx_stream_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_proxy_srv_conf_t *pscf = conf;

    ngx_int_t                            rc;
    ngx_str_t                           *value;
    ngx_stream_complex_value_t           cv;
    ngx_stream_upstream_local_t         *local;
    ngx_stream_compile_complex_value_t   ccv;

    if (pscf->local != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_stream_upstream_local_t));
    if (local == NULL) {
        return NGX_CONF_ERROR;
    }

    pscf->local = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_stream_complex_value_t));
        if (local->value == NULL) {
            return NGX_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
        if (local->addr == NULL) {
            return NGX_CONF_ERROR;
        }

        rc = ngx_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case NGX_OK:
            local->addr->name = value[1];
            break;

        case NGX_DECLINED:
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return NGX_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (NGX_HAVE_TRANSPARENT_PROXY)
            ngx_core_conf_t  *ccf;

            ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                   ngx_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
