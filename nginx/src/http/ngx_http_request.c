// annotated by chrono since 2016
//
// * ngx_http_init_connection
// * ngx_http_create_request
// * ngx_http_wait_request_handler
// * ngx_http_process_request_line
// * ngx_http_find_virtual_server
// * ngx_http_process_request_headers
// * ngx_http_request_handler
// * ngx_http_run_posted_requests
//
// * ngx_http_set_write_handler
// * ngx_http_writer
//
// * ngx_http_ssl_handshake
//
// * ngx_http_log_request
// * ngx_http_free_request
// * ngx_http_close_connection
// * ngx_http_close_request
// * ngx_http_finalize_connection
// * ngx_http_finalize_request

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 接受连接后，读事件加入epoll，当socket有数据可读时就调用
// 因为是事件触发，可能会被多次调用，即重入
// 处理读事件，读取请求头
static void ngx_http_wait_request_handler(ngx_event_t *ev);

// 1.15.9新函数，专门创建请求结构体
static ngx_http_request_t *ngx_http_alloc_request(ngx_connection_t *c);

// 调用recv读取数据，解析出请求行信息,存在r->header_in里
// 如果头太大，或者配置的太小，nginx会再多分配内存
// 这里用无限循环，保证读取完数据
// again说明客户端发送的数据不足，会继续读取，error则结束请求
// 请求行处理完毕设置读事件处理函数为ngx_http_process_request_headers
static void ngx_http_process_request_line(ngx_event_t *rev);

// 解析请求行之后的请求头数据
// 处理逻辑与ngx_http_process_request_line类似，也是无限循环，保证读取完数据
// 如果头太大，或者配置的太小，nginx会再多分配内存
// 检查收到的http请求头:content_length不能是非数字,不支持trace方法,设置keep_alive头信息
// 最后调用ngx_http_process_request
// again说明客户端发送的数据不足，会继续读取，error则结束请求
static void ngx_http_process_request_headers(ngx_event_t *rev);

// 调用recv读数据，存在r->header_in里
// 如果暂时无数据就加入定时器等待，加入读事件
// 下次读事件发生还会进入这里继续读取
// 返回读取的字节数量
static ssize_t ngx_http_read_request_header(ngx_http_request_t *r);

// 为接收http头数据分配一个大的缓冲区，拷贝已经接收的数据
// 使用了hc->busy/free等成员
static ngx_int_t ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
    ngx_uint_t request_line);

// 使用offset设置headers_in里的请求头
static ngx_int_t ngx_http_process_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

// 使用offset设置headers_in里的请求头，但不允许重复
// 如Content-Length/If-Modified-Since
static ngx_int_t ngx_http_process_unique_header_line(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

// 使用offset设置headers_in里的请求头，允许重复
// 加入动态数组headers
static ngx_int_t ngx_http_process_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

// 处理请求头里的host
static ngx_int_t ngx_http_process_host(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

static ngx_int_t ngx_http_process_connection(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

// 检查头里的user_agent，设置ie/chrome/safari标志位
static ngx_int_t ngx_http_process_user_agent(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);

// 简单验证host字符串的合法性
static ngx_int_t ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool,
    ngx_uint_t alloc);

// 由请求行或请求头里的host定位server{}块位置，决定进入哪个server
// 核心是ngx_http_find_virtual_server
static ngx_int_t ngx_http_set_virtual_server(ngx_http_request_t *r,
    ngx_str_t *host);

// 查找匹配的server{}块
// 先在hash表里找完全匹配
// hash找不到用正则匹配
static ngx_int_t ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp);

// http请求处理时的事件handler
// 当读取完请求头后读写事件的handler都是它
// 通常写事件就是ngx_http_core_run_phases引擎数组处理请求
static void ngx_http_request_handler(ngx_event_t *ev);

// 释放主请求相关的资源，调用cleanup链表，相当于析构
// 如果主请求有多线程任务阻塞，那么不能结束请求
// 否则调用ngx_http_close_request尝试关闭请求，引用计数减1
static void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc);

// 设置为主请求的write_event_handler
// 强制令引用计数为1，必须关闭
// 调用ngx_http_close_request
static void ngx_http_terminate_handler(ngx_http_request_t *r);

// 检查请求相关的异步事件，尝试关闭请求
//
// 有多个引用计数，表示有其他异步事件在处理
// 那么就不能真正结束请求
// 调用ngx_http_close_request尝试关闭请求，引用计数减1
// r->main->count == 1，可以结束请求
// 如果正在读取请求体，那么设置标志位，要求延后读取数据关闭
// 如果进程正在运行，没有退出，且请求要求keepalive
// 那么调用ngx_http_set_keepalive而不是关闭请求
// 不keepalive，也不延后关闭,那么就真正关闭
// 尝试关闭请求，引用计数减1，表示本操作完成
static void ngx_http_finalize_connection(ngx_http_request_t *r);

// 设置发送数据的handler，即写事件的回调handler为write_event_handler
// 不限速，需要加入发送超时，即send_timeout时间内socket不可写则报错
// 使用send_lowat设置epoll写事件
// 只有内核socket缓冲区有send_lowat的空间才会触发写事件
// 当可写时真正的向客户端发送数据，调用send_chain
// 如果数据发送不完，就保存在r->out里，返回again,需要再次发生可写事件才能发送
// 不是last、flush，且数据量较小（默认1460）
// 那么就不真正调用write发送，减少系统调用的次数，提高性能
static ngx_int_t ngx_http_set_write_handler(ngx_http_request_t *r);

// 写事件handler是ngx_http_writer
// 检查写事件是否已经超时
// delayed表示限速,如果不限速那么就结束请求
// 调用过滤链表发送数据
// 有数据被缓存，没有完全发送
// 加上超时等待，注册写事件，等socket可写再发送
static void ngx_http_writer(ngx_http_request_t *r);

static void ngx_http_request_finalizer(ngx_http_request_t *r);

// 代替关闭连接的动作，保持连接
// 释放请求相关的资源，调用cleanup链表，相当于析构
// 但连接的内存池还在，可以用于长连接继续使用
// 关注读事件，等待客户端发送数据
// rev->handler = ngx_http_keepalive_handler;
static void ngx_http_set_keepalive(ngx_http_request_t *r);

static void ngx_http_keepalive_handler(ngx_event_t *ev);

// 计算延后关闭的时间，添加超时
// 设置读事件处理函数为ngx_http_lingering_close_handler
// 如果此时有数据可读那么直接调用ngx_http_lingering_close_handler
static void ngx_http_set_lingering_close(ngx_http_request_t *r);

// 超时直接关闭连接
// 否则读取数据，但并不处理，使用固定的buffer
// 返回again，无数据可读，需要继续等待
static void ngx_http_lingering_close_handler(ngx_event_t *ev);

static ngx_int_t ngx_http_post_action(ngx_http_request_t *r);

// 尝试关闭请求，引用计数减1，表示本操作完成
// 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
// 不能关闭，直接返回
// 引用计数为0，没有任何操作了，可以安全关闭
// 释放请求相关的资源，调用cleanup链表，相当于析构
// 此时请求已经结束，调用log模块记录日志
// 销毁请求的内存池
// 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
// 最后销毁连接的内存池
static void ngx_http_close_request(ngx_http_request_t *r, ngx_int_t error);

// 请求已经结束，调用log模块记录日志
// 在ngx_http_free_request里调用
// log handler不在引擎数组里
// 不检查handler的返回值，直接调用，不使用checker
static void ngx_http_log_request(ngx_http_request_t *r);

// 记录错误日志时由log对象调用的函数，增加http请求的专有信息
static u_char *ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len);

static u_char *ngx_http_log_error_handler(ngx_http_request_t *r,
    ngx_http_request_t *sr, u_char *buf, size_t len);

#if (NGX_HTTP_SSL)
static void ngx_http_ssl_handshake(ngx_event_t *rev);
static void ngx_http_ssl_handshake_handler(ngx_connection_t *c);
#endif


static char *ngx_http_client_errors[] = {

    /* NGX_HTTP_PARSE_INVALID_METHOD */
    "client sent invalid method",

    /* NGX_HTTP_PARSE_INVALID_REQUEST */
    "client sent invalid request",

    /* NGX_HTTP_PARSE_INVALID_VERSION */
    "client sent invalid version",

    /* NGX_HTTP_PARSE_INVALID_09_METHOD */
    "client sent invalid method in HTTP/0.9 request"
};


// 使用字符串映射操作函数，填充headers_in
// 在ngx_http_init_headers_in_hash构造为散列表，提高查找效率
ngx_http_header_t  ngx_http_headers_in[] = {
    { ngx_string("Host"), offsetof(ngx_http_headers_in_t, host),
                 ngx_http_process_host },

    { ngx_string("Connection"), offsetof(ngx_http_headers_in_t, connection),
                 ngx_http_process_connection },

    { ngx_string("If-Modified-Since"),
                 offsetof(ngx_http_headers_in_t, if_modified_since),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-Unmodified-Since"),
                 offsetof(ngx_http_headers_in_t, if_unmodified_since),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-Match"),
                 offsetof(ngx_http_headers_in_t, if_match),
                 ngx_http_process_unique_header_line },

    { ngx_string("If-None-Match"),
                 offsetof(ngx_http_headers_in_t, if_none_match),
                 ngx_http_process_unique_header_line },

    { ngx_string("User-Agent"), offsetof(ngx_http_headers_in_t, user_agent),
                 ngx_http_process_user_agent },

    { ngx_string("Referer"), offsetof(ngx_http_headers_in_t, referer),
                 ngx_http_process_header_line },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_in_t, content_length),
                 ngx_http_process_unique_header_line },

    { ngx_string("Content-Range"),
                 offsetof(ngx_http_headers_in_t, content_range),
                 ngx_http_process_unique_header_line },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_in_t, content_type),
                 ngx_http_process_header_line },

    { ngx_string("Range"), offsetof(ngx_http_headers_in_t, range),
                 ngx_http_process_header_line },

    { ngx_string("If-Range"),
                 offsetof(ngx_http_headers_in_t, if_range),
                 ngx_http_process_unique_header_line },

    { ngx_string("Transfer-Encoding"),
                 offsetof(ngx_http_headers_in_t, transfer_encoding),
                 ngx_http_process_unique_header_line },

    { ngx_string("TE"),
                 offsetof(ngx_http_headers_in_t, te),
                 ngx_http_process_header_line },

    { ngx_string("Expect"),
                 offsetof(ngx_http_headers_in_t, expect),
                 ngx_http_process_unique_header_line },

    { ngx_string("Upgrade"),
                 offsetof(ngx_http_headers_in_t, upgrade),
                 ngx_http_process_header_line },

#if (NGX_HTTP_GZIP || NGX_HTTP_HEADERS)
    { ngx_string("Accept-Encoding"),
                 offsetof(ngx_http_headers_in_t, accept_encoding),
                 ngx_http_process_header_line },

    { ngx_string("Via"), offsetof(ngx_http_headers_in_t, via),
                 ngx_http_process_header_line },
#endif

    { ngx_string("Authorization"),
                 offsetof(ngx_http_headers_in_t, authorization),
                 ngx_http_process_unique_header_line },

    { ngx_string("Keep-Alive"), offsetof(ngx_http_headers_in_t, keep_alive),
                 ngx_http_process_header_line },

#if (NGX_HTTP_X_FORWARDED_FOR)
    { ngx_string("X-Forwarded-For"),
                 offsetof(ngx_http_headers_in_t, x_forwarded_for),
                 ngx_http_process_multi_header_lines },
#endif

#if (NGX_HTTP_REALIP)
    { ngx_string("X-Real-IP"),
                 offsetof(ngx_http_headers_in_t, x_real_ip),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_HEADERS)
    { ngx_string("Accept"), offsetof(ngx_http_headers_in_t, accept),
                 ngx_http_process_header_line },

    { ngx_string("Accept-Language"),
                 offsetof(ngx_http_headers_in_t, accept_language),
                 ngx_http_process_header_line },
#endif

#if (NGX_HTTP_DAV)
    { ngx_string("Depth"), offsetof(ngx_http_headers_in_t, depth),
                 ngx_http_process_header_line },

    { ngx_string("Destination"), offsetof(ngx_http_headers_in_t, destination),
                 ngx_http_process_header_line },

    { ngx_string("Overwrite"), offsetof(ngx_http_headers_in_t, overwrite),
                 ngx_http_process_header_line },

    { ngx_string("Date"), offsetof(ngx_http_headers_in_t, date),
                 ngx_http_process_header_line },
#endif

    { ngx_string("Cookie"), offsetof(ngx_http_headers_in_t, cookies),
                 ngx_http_process_multi_header_lines },

    { ngx_null_string, 0, NULL }
};


// 当epoll检测到连接事件，会调用event_accept，最后会调用此函数，开始处理http请求
// 在ngx_http_optimize_servers->ngx_http_add_listening里设置有连接发生时的回调函数
// 调用发生在ngx_event_accept.c:ngx_event_accept()
// 把读事件加入epoll，当socket有数据可读时就调用ngx_http_wait_request_handler
void
ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_event_t            *rev;
    struct sockaddr_in     *sin;
    ngx_http_port_t        *port;
    ngx_http_in_addr_t     *addr;
    ngx_http_log_ctx_t     *ctx;
    ngx_http_connection_t  *hc;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
    ngx_http_in6_addr_t    *addr6;
#endif

    // 建立连接时server{}里相关的信息
    // 重要的是conf_ctx，server的配置数组
    // 准备初始化hc
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    // 之后在create_request里使用
    c->data = hc;

    /* find the server configuration for the address:port */

    // 取监听同一端口的server信息
    port = c->listening->servers;

    // 一个端口对应多个地址的情况
    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
         * is required to determine a server address
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            hc->addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            hc->addr_conf = &addr[i].conf;

            break;
        }

    } else {
        // 唯一监听端口的server
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            hc->addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            hc->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */

    // addr_conf->default_server->ctx就是端口所在的server的配置数组
    hc->conf_ctx = hc->addr_conf->default_server->ctx;

    // http log相关的信息
    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    c->log->connection = c->number;
    c->log->handler = ngx_http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = NGX_ERROR_INFO;

    // 连接的读事件，此时是已经发生连接，即将读数据
    rev = c->read;

    // 处理读事件，读取请求头
    // 设置了读事件的handler，可读时就会调用ngx_http_wait_request_handler
    rev->handler = ngx_http_wait_request_handler;

    // 暂时不处理写事件
    c->write->handler = ngx_http_empty_handler;

    // http2使用特殊的读事件处理函数ngx_http_v2_init
#if (NGX_HTTP_V2)
    if (hc->addr_conf->http2) {
        rev->handler = ngx_http_v2_init;
    }
#endif

    // ssl连接使用特殊的读事件处理函数ngx_http_ssl_handshake
#if (NGX_HTTP_SSL)
    {
    ngx_http_ssl_srv_conf_t  *sscf;

    sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);

    // sscf->enable对应指令ssl on，通常不使用
    // hc->addr_conf->ssl对应listen xxx ssl
    if (sscf->enable || hc->addr_conf->ssl) {
        // 1.15.0不要求必须指定证书

        hc->ssl = 1;
        c->log->action = "SSL handshaking";

        // ssl连接使用特殊的读事件处理函数ngx_http_ssl_handshake
        // 进入ssl握手处理，而不是直接读取http头
        rev->handler = ngx_http_ssl_handshake;
    }
    }
#endif

    // listen指令配置了代理协议，需要额外处理
    if (hc->addr_conf->proxy_protocol) {
        hc->proxy_protocol = 1;
        c->log->action = "reading PROXY protocol";
    }

    // 通常此时读事件都是ready=0，只有iocp或者使用了deferred才是ready
    // ngx_event_accept里设置
    // 为了提高nginx的性能，减少epoll调用，应该设置deferred
    if (rev->ready) {
        /* the deferred accept(), iocp */

        if (ngx_use_accept_mutex) {
            // 如果是负载均衡，那么加入延后处理队列
            // 尽快释放锁，方便其他进程再接受请求
            // 会在ngx_event_process_posted里处理
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        // 否则直接处理请求,即调用ngx_http_wait_request_handler
        rev->handler(rev);
        return;
    }

    // 虽然建立了连接，但暂时没有数据可读，ready=0
    // 加一个超时事件，等待读事件发生
    ngx_add_timer(rev, c->listening->post_accept_timeout);

    // 连接加入cycle的复用队列ngx_cycle->reusable_connections_queue
    ngx_reusable_connection(c, 1);

    // 把读事件加入epoll，当socket有数据可读时就调用ngx_http_wait_request_handler
    // 因为事件加入了定时器，超时时也会调用ngx_http_wait_request_handler
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        // 调用ngx_close_connection
        // 释放连接，加入空闲链表，可以再次使用
        // 销毁连接的内存池
        ngx_http_close_connection(c);
        return;
    }
}


// 接受连接后，读事件加入epoll，当socket有数据可读时就调用
// 因为是事件触发，可能会被多次调用，即重入
// 处理读事件，读取请求头
static void
ngx_http_wait_request_handler(ngx_event_t *rev)
{
    u_char                    *p;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    // 从事件的data获得连接对象
    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");

    // 首先检查超时
    // 由定时器超时引发的，由ngx_event_expire_timers调用
    // 超时客户端没有发送数据，关闭连接
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");

        // 调用ngx_close_connection
        // 释放连接，加入空闲链表，可以再次使用
        // 销毁连接的内存池
        ngx_http_close_connection(c);
        return;
    }

    // 没有超时，检查连接是否被关闭了
    if (c->close) {

        // 调用ngx_close_connection
        // 释放连接，加入空闲链表，可以再次使用
        // 销毁连接的内存池
        ngx_http_close_connection(c);
        return;
    }

    // 连接对象里获取配置数组， 在ngx_http_init_connection里设置的
    // 重要的是conf_ctx，server的配置数组
    hc = c->data;
    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    // 配置的头缓冲区大小，默认1k
    // 如果头太大，或者配置的太小
    // nginx会再多分配内存，保证读取完数据
    size = cscf->client_header_buffer_size;

    // 这个缓冲区是给连接对象用的
    b = c->buffer;

    // 如果还没有创建缓冲区则创建
    // 第一次调用是没有，之后再调用就有了
    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        c->buffer = b;

    // 虽然已经有了buf结构，但没有关联的内存空间
    // 之前因为again被释放了，所以要重新分配内存
    // 见后面的recv判断
    } else if (b->start == NULL) {

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        // 这里pos==last==start，表示一个空的缓冲区
        b->pos = b->start;
        b->last = b->start;

        b->end = b->last + size;
    }

    // 调用接收函数,b->last是缓冲区的末位置，前面可能有数据
    // ngx_event_accept.c:ngx_event_accept()里设置为ngx_recv
    // ngx_posix_init.c里初始化为linux的底层接口
    // <0 出错， =0 连接关闭， >0 接收到数据大小
    n = c->recv(c, b->last, size);

    // 如果返回NGX_AGAIN表示还没有数据
    // 就要再次加定时器防止超时，然后epoll等待下一次的读事件发生
    if (n == NGX_AGAIN) {

        // 没设置超时就再来一次
        if (!rev->timer_set) {
            ngx_add_timer(rev, c->listening->post_accept_timeout);
            ngx_reusable_connection(c, 1);
        }

        // 把读事件加入epoll，当socket有数据可读时就调用ngx_http_wait_request_handler
        // 因为事件加入了定时器，超时时也会调用ngx_http_wait_request_handler
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        // 释放缓冲区，避免空闲连接占用内存
        // 这样，即使有大量的无数据连接，也不会占用很多的内存
        // 只有连接对象的内存消耗
        if (ngx_pfree(c->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }

        // 读事件处理完成，因为没读到数据，等待下一次事件发生
        return;
    }

    // 读数据出错了，直接关闭连接
    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    // 读到了0字节，即连接被客户端关闭，client abort
    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_http_close_connection(c);
        return;
    }

    // 真正读取了n个字节
    b->last += n;

    // listen指令是否使用了proxy_protocol参数
    if (hc->proxy_protocol) {
        // 清除标志位
        hc->proxy_protocol = 0;

        // 读取proxy_protocol定义的信息
        // 早期只支持版本1的文本形式
        // 见http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
        p = ngx_proxy_protocol_read(c, b->pos, b->last);

        if (p == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        // 消费已经读取的proxy protocol数据
        b->pos = p;

        // 如果缓冲区空，那么等待下次读事件
        // 否则后续的是正常的http头
        if (b->pos == b->last) {
            c->log->action = "waiting for request";
            b->pos = b->start;
            b->last = b->start;
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }
    }

    // http日志的额外信息
    c->log->action = "reading client request line";

    // 参数reusable表示是否可以复用，即加入队列
    // 因为此时连接已经在使用，故不能复用
    ngx_reusable_connection(c, 0);

    // 创建ngx_http_request_t对象，准备开始真正的处理请求
    c->data = ngx_http_create_request(c);
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    // 读事件的handler改变，变成ngx_http_process_request_line
    // 之后再有数据来就换成ngx_http_process_request_line
    rev->handler = ngx_http_process_request_line;

    // 必须马上执行ngx_http_process_request_line
    // 否则因为et模式的特性，将无法再获得此事件
    ngx_http_process_request_line(rev);
}


// 创建ngx_http_request_t对象，准备开始真正的处理请求
// 连接对象里获取配置数组， 在ngx_http_init_connection里设置的
// 创建请求内存池，创建请求对象
// 为所有http模块分配存储ctx数据的空间，即一个大数组
// 为所有变量创建数组
ngx_http_request_t *
ngx_http_create_request(ngx_connection_t *c)
{
    ngx_http_request_t        *r;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        return NULL;
    }

    // 处理的请求次数，在ngx_http_create_request里增加
    // 用来控制长连接里可处理的请求次数，指令keepalive_requests
    // requests字段仅在http处理时有用
    c->requests++;

    // 取当前location的配置
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(c, clcf->error_log);

    // 日志的ctx
    // 在记录错误日志时使用
    ctx = c->log->data;
    ctx->request = r;
    ctx->current_request = r;

    // 在共享内存里增加计数器
#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
    r->stat_reading = 1;
    (void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
#endif

    return r;
}


// 1.15.9新函数，专门创建请求结构体
static ngx_http_request_t *
ngx_http_alloc_request(ngx_connection_t *c)
{
    ngx_pool_t                 *pool;
    ngx_time_t                 *tp;
    ngx_http_request_t         *r;
    ngx_http_connection_t      *hc;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    // 连接对象里获取配置数组， 在ngx_http_init_connection里设置的
    // 重要的是conf_ctx，server的配置数组
    hc = c->data;

    // 获取server{}的配置
    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    // 请求用的内存池
    pool = ngx_create_pool(cscf->request_pool_size, c->log);
    if (pool == NULL) {
        return NULL;
    }

    // 在请求内存池里创建请求对象
    // 不使用连接的内存池，当请求结束时自动回收
    r = ngx_pcalloc(pool, sizeof(ngx_http_request_t));
    if (r == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    // 保存请求的内存池
    r->pool = pool;

    // 请求的连接参数，重要的是conf_ctx，server的配置数组
    r->http_connection = hc;

    r->signature = NGX_HTTP_MODULE;

    // 请求关联的连接对象，里面有log
    r->connection = c;

    // 请求对应的配置数组
    // 此时只是default server的配置信息
    // main_conf所有server都只有一个，所以这个不需要再设置
    r->main_conf = hc->conf_ctx->main_conf;

    // 在读取完请求头后，会在ngx_http_find_virtual_server()里再设置正确的
    r->srv_conf = hc->conf_ctx->srv_conf;
    r->loc_conf = hc->conf_ctx->loc_conf;

    // 设置请求的读处理函数
    // 注意这个不是读事件的处理函数！！
    r->read_event_handler = ngx_http_block_reading;

    // 设置读取缓冲区，暂不深究
    r->header_in = hc->busy ? hc->busy->buf : c->buffer;

    // 初始化响应头链表
    if (ngx_list_init(&r->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    if (ngx_list_init(&r->headers_out.trailers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_destroy_pool(r->pool);
        return NULL;
    }


    // 为所有http模块分配存储ctx数据的空间，即一个大数组
    r->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (r->ctx == NULL) {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

    // 取http core的main配置
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    // 为所有变量创建数组
    // 里面存放的是变量值
    r->variables = ngx_pcalloc(r->pool, cmcf->variables.nelts
                                        * sizeof(ngx_http_variable_value_t));
    if (r->variables == NULL) {
        ngx_destroy_pool(r->pool);
        return NULL;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        r->main_filter_need_in_memory = 1;
    }
#endif

    // accept的连接是主请求
    r->main = r;

    // 当前只有一个请求，所有子请求最大调用深度不能超过50
    // 在1.8版之前是个数200,1.10之后改变为深度50
    r->count = 1;

    // 得到当前时间
    tp = ngx_timeofday();

    // 设置请求开始的时间，限速用
    r->start_sec = tp->sec;
    r->start_msec = tp->msec;

    // 还没有开始解析请求头，方法未知
    r->method = NGX_HTTP_UNKNOWN;

    // http协议版本号默认是1.0
    r->http_version = NGX_HTTP_VERSION_10;

    // 初始化请求头、响应头的长度都是未知
    r->headers_in.content_length_n = -1;
    r->headers_in.keep_alive_n = -1;
    r->headers_out.content_length_n = -1;
    r->headers_out.last_modified_time = -1;

    // uri改写次数限制，最多10次
    // 每次rewrite就会减少，到0就不能rewrite，返回错误
    r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;

    // 每个请求最多只能产生50层次调用的子请求
    // 在1.8版之前是主请求最多200个
    // 1.10之后改变了实现方式，50是子请求的“深度”限制
    // 所以产生子请求基本已经没有限制
    // 每产生一个子请求，sr->subrequests递减
    r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;

    // 当前请求的状态，正在读取请求
    r->http_state = NGX_HTTP_READING_REQUEST_STATE;

    // 在记录错误日志时回调
    r->log_handler = ngx_http_log_error_handler;

    return r;
}


#if (NGX_HTTP_SSL)

// ssl连接使用特殊的读事件处理函数ngx_http_ssl_handshake
// 进入ssl握手处理，而不是直接读取http头
static void
ngx_http_ssl_handshake(ngx_event_t *rev)
{
    u_char                    *p, buf[NGX_PROXY_PROTOCOL_MAX_HEADER + 1];
    size_t                     size;
    ssize_t                    n;
    ngx_err_t                  err;
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_loc_conf_t  *clcf;

    // 连接可读，即客户端发来了数据

    // 取连接对象
    c = rev->data;

    // 取配置信息
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http check ssl handshake");

    // 检查超时
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    // 连接已经关闭
    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    // 是否代理协议，不是则size=1
    size = hc->proxy_protocol ? sizeof(buf) : 1;

    // 读取数据
    // 通常只读取1个字节，是ssl的版本号
    n = recv(c->fd, (char *) buf, size, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http recv(): %z", n);

    // 检查错误码
    if (n == -1) {

        // again表示数据未准备好
        // 需要加入epoll监控再次等待读事件
        if (err == NGX_EAGAIN) {
            rev->ready = 0;

            if (!rev->timer_set) {
                ngx_add_timer(rev, c->listening->post_accept_timeout);
                ngx_reusable_connection(c, 1);
            }

            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_http_close_connection(c);
            }

            return;
        }

        // 其他的错误码都视为失败
        ngx_connection_error(c, err, "recv() failed");
        ngx_http_close_connection(c);

        return;
    }

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        // 读取proxy_protocol定义的信息
        // 见http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
        p = ngx_proxy_protocol_read(c, buf, buf + n);

        if (p == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        size = p - buf;

        if (c->recv(c, buf, size) != (ssize_t) size) {
            ngx_http_close_connection(c);
            return;
        }

        c->log->action = "SSL handshaking";

        if (n == (ssize_t) size) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        n = 1;
        buf[0] = *p;
    }

    // 读取了一个字节，是ssl的版本号
    if (n == 1) {
        if (buf[0] & 0x80 /* SSLv2 */ || buf[0] == 0x16 /* SSLv3/TLSv1 */) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "https ssl handshake: 0x%02Xd", buf[0]);

            clcf = ngx_http_get_module_loc_conf(hc->conf_ctx,
                                                ngx_http_core_module);

            if (clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
                ngx_http_close_connection(c);
                return;
            }

            // 取ssl模块的各种配置
            sscf = ngx_http_get_module_srv_conf(hc->conf_ctx,
                                                ngx_http_ssl_module);

            // 创建ssl连接对象
            // 在event/ngx_event_openssl.c
            // #define NGX_SSL_BUFFER   1
            // 默认启用ssl缓冲
            if (ngx_ssl_create_connection(&sscf->ssl, c, NGX_SSL_BUFFER)
                != NGX_OK)
            {
                ngx_http_close_connection(c);
                return;
            }


            ngx_reusable_connection(c, 0);

            // 开始握手
            // 在event/ngx_event_openssl.c
            rc = ngx_ssl_handshake(c);

            // again说明数据不足，要加handler等待数据
            if (rc == NGX_AGAIN) {

                if (!rev->timer_set) {
                    ngx_add_timer(rev, c->listening->post_accept_timeout);
                }

                c->ssl->handler = ngx_http_ssl_handshake_handler;
                return;
            }

            ngx_http_ssl_handshake_handler(c);

            return;
        }

        // 不是ssl，就是普通的http
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "plain http");

        c->log->action = "waiting for request";

        // 修改读事件handler，开始读取http头
        // https也就可以兼容http
        rev->handler = ngx_http_wait_request_handler;
        ngx_http_wait_request_handler(rev);

        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "client closed connection");
    ngx_http_close_connection(c);
}


static void
ngx_http_ssl_handshake_handler(ngx_connection_t *c)
{
    if (c->ssl->handshaked) {

        /*
         * The majority of browsers do not send the "close notify" alert.
         * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
         * and Links.  And what is more, MSIE ignores the server's alert.
         *
         * Opera and recent Mozilla send the alert.
         */

        c->ssl->no_wait_shutdown = 1;

#if (NGX_HTTP_V2                                                              \
     && (defined TLSEXT_TYPE_application_layer_protocol_negotiation           \
         || defined TLSEXT_TYPE_next_proto_neg))
        {
        unsigned int            len;
        const unsigned char    *data;
        ngx_http_connection_t  *hc;

        hc = c->data;

        if (hc->addr_conf->http2) {

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
            SSL_get0_alpn_selected(c->ssl->connection, &data, &len);

#ifdef TLSEXT_TYPE_next_proto_neg
            if (len == 0) {
                SSL_get0_next_proto_negotiated(c->ssl->connection, &data, &len);
            }
#endif

#else /* TLSEXT_TYPE_next_proto_neg */
            SSL_get0_next_proto_negotiated(c->ssl->connection, &data, &len);
#endif

            if (len == 2 && data[0] == 'h' && data[1] == '2') {
                ngx_http_v2_init(c->read);
                return;
            }
        }
        }
#endif

        c->log->action = "waiting for request";

        c->read->handler = ngx_http_wait_request_handler;
        /* STUB: epoll edge */ c->write->handler = ngx_http_empty_handler;

        ngx_reusable_connection(c, 1);

        ngx_http_wait_request_handler(c->read);

        return;
    }

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
    }

    ngx_http_close_connection(c);
}


#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

int
ngx_http_ssl_servername(ngx_ssl_conn_t *ssl_conn, int *ad, void *arg)
{
    ngx_int_t                  rc;
    ngx_str_t                  host;
    const char                *servername;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        *ad = SSL_AD_NO_RENEGOTIATION;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);

    if (servername == NULL) {
        return SSL_TLSEXT_ERR_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "SSL server name: \"%s\"", servername);

    host.len = ngx_strlen(servername);

    if (host.len == 0) {
        return SSL_TLSEXT_ERR_OK;
    }

    host.data = (u_char *) servername;

    rc = ngx_http_validate_host(&host, c->pool, 1);

    if (rc == NGX_ERROR) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rc == NGX_DECLINED) {
        return SSL_TLSEXT_ERR_OK;
    }

    hc = c->data;

    rc = ngx_http_find_virtual_server(c, hc->addr_conf->virtual_names, &host,
                                      NULL, &cscf);

    if (rc == NGX_ERROR) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (rc == NGX_DECLINED) {
        return SSL_TLSEXT_ERR_OK;
    }

    hc->ssl_servername = ngx_palloc(c->pool, sizeof(ngx_str_t));
    if (hc->ssl_servername == NULL) {
        *ad = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    *hc->ssl_servername = host;

    hc->conf_ctx = cscf->ctx;

    clcf = ngx_http_get_module_loc_conf(hc->conf_ctx, ngx_http_core_module);

    ngx_set_connection_log(c, clcf->error_log);

    sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module);

    c->ssl->buffer_size = sscf->buffer_size;

    if (sscf->ssl.ctx) {
        SSL_set_SSL_CTX(ssl_conn, sscf->ssl.ctx);

        /*
         * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
         * adjust other things we care about
         */

        SSL_set_verify(ssl_conn, SSL_CTX_get_verify_mode(sscf->ssl.ctx),
                       SSL_CTX_get_verify_callback(sscf->ssl.ctx));

        SSL_set_verify_depth(ssl_conn, SSL_CTX_get_verify_depth(sscf->ssl.ctx));

#if OPENSSL_VERSION_NUMBER >= 0x009080dfL
        /* only in 0.9.8m+ */
        SSL_clear_options(ssl_conn, SSL_get_options(ssl_conn) &
                                    ~SSL_CTX_get_options(sscf->ssl.ctx));
#endif

        SSL_set_options(ssl_conn, SSL_CTX_get_options(sscf->ssl.ctx));

#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_set_options(ssl_conn, SSL_OP_NO_RENEGOTIATION);
#endif
    }

    return SSL_TLSEXT_ERR_OK;
}

#endif


#ifdef SSL_R_CERT_CB_ERROR

int
ngx_http_ssl_certificate(ngx_ssl_conn_t *ssl_conn, void *arg)
{
    ngx_str_t                  cert, key;
    ngx_uint_t                 i, nelts;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_complex_value_t  *certs, *keys;

    c = ngx_ssl_get_connection(ssl_conn);

    if (c->ssl->handshaked) {
        return 0;
    }

    r = ngx_http_alloc_request(c);
    if (r == NULL) {
        return 0;
    }

    r->logged = 1;

    sscf = arg;

    nelts = sscf->certificate_values->nelts;
    certs = sscf->certificate_values->elts;
    keys = sscf->certificate_key_values->elts;

    for (i = 0; i < nelts; i++) {

        if (ngx_http_complex_value(r, &certs[i], &cert) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl cert: \"%s\"", cert.data);

        if (ngx_http_complex_value(r, &keys[i], &key) != NGX_OK) {
            goto failed;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ssl key: \"%s\"", key.data);

        if (ngx_ssl_connection_certificate(c, r->pool, &cert, &key,
                                           sscf->passwords)
            != NGX_OK)
        {
            goto failed;
        }
    }

    ngx_http_free_request(r, 0);
    c->destroyed = 0;
    return 1;

failed:

    ngx_http_free_request(r, 0);
    c->destroyed = 0;
    return 0;
}

#endif

#endif


// 调用recv读取数据，解析出请求行信息,存在r->header_in里
// 如果头太大，或者配置的太小，nginx会再多分配内存
// 这里用无限循环，保证读取完数据
// again说明客户端发送的数据不足，会继续读取，error则结束请求
// 请求行处理完毕设置读事件处理函数为ngx_http_process_request_headers
static void
ngx_http_process_request_line(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_int_t            rc, rv;
    ngx_str_t            host;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    // 获取读事件相关的连接对象和请求对象
    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    // 检查是否超时
    // 由定时器超时引发的，由ngx_event_expire_timers调用
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    // 预设没有数据，需要重试
    rc = NGX_AGAIN;

    // 配置的头缓冲区大小，默认1k
    // 如果头太大，或者配置的太小，nginx会再多分配内存
    // 这里用无限循环，保证读取完数据
    for ( ;; ) {

        if (rc == NGX_AGAIN) {

            // 调用recv读数据，存在r->header_in里
            // 如果暂时无数据就加入定时器等待，加入读事件
            // 下次读事件发生还会进入这里继续读取
            // 返回读取的字节数量
            n = ngx_http_read_request_header(r);

            // again会继续读取，error则结束请求
            // again说明客户端发送的数据不足
            if (n == NGX_AGAIN || n == NGX_ERROR) {
                break;
            }
        }

        // 此时已经在r->header_in里有一些请求头的数据
        // 解析请求行, in ngx_http_parse.c
        // 使用状态机解析，会调整缓冲区里的指针位置
        // 填充r->method、r->http_version
        // 如果数据不完整，无法解析则返回NGX_AGAIN，会再次读取
        rc = ngx_http_parse_request_line(r, r->header_in);

        // 成功解析出了http请求行
        if (rc == NGX_OK) {

            /* the request line has been parsed successfully */

            // “拷贝”请求行原始字符串
            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;

            // 获取请求行的长度
            r->request_length = r->header_in->pos - r->request_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line);

            // “拷贝”方法名
            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            if (r->http_protocol.data) {
                r->http_protocol.len = r->request_end - r->http_protocol.data;
            }

            if (ngx_http_process_request_uri(r) != NGX_OK) {
                break;
            }

            // 1.15.1 新增r->schema
            // 例如http/https/ws/wss等
            if (r->schema_end) {
                r->schema.len = r->schema_end - r->schema_start;
                r->schema.data = r->schema_start;
            }

            // 请求行里解析出host
            if (r->host_end) {

                host.len = r->host_end - r->host_start;
                host.data = r->host_start;

                // 简单验证host字符串的合法性
                rc = ngx_http_validate_host(&host, r->pool, 0);

                if (rc == NGX_DECLINED) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                    break;
                }

                if (rc == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                // 定位server{}块位置
                if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
                    break;
                }

                // 设置请求头结构体里的server成员
                r->headers_in.server = host;
            }

            if (r->http_version < NGX_HTTP_VERSION_10) {

                if (r->headers_in.server.len == 0
                    && ngx_http_set_virtual_server(r, &r->headers_in.server)
                       == NGX_ERROR)
                {
                    break;
                }

                ngx_http_process_request(r);
                break;
            }


            // 初始化请求头链表，准备解析请求头
            if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(ngx_table_elt_t))
                != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            c->log->action = "reading client request headers";

            // 请求行处理完毕
            // 设置读事件处理函数为ngx_http_process_request_headers
            rev->handler = ngx_http_process_request_headers;

            // 立即调用ngx_http_process_request_headers，解析请求头
            ngx_http_process_request_headers(rev);

            break;
        }

        // 不是again则有错误
        if (rc != NGX_AGAIN) {

            /* there was error while a request line parsing */

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          ngx_http_client_errors[rc - NGX_HTTP_CLIENT_ERROR]);

            if (rc == NGX_HTTP_PARSE_INVALID_VERSION) {
                ngx_http_finalize_request(r, NGX_HTTP_VERSION_NOT_SUPPORTED);

            } else {
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            }

            break;
        }

        /* NGX_AGAIN: a request line parsing is still incomplete */

        // agian，请求行数据不完整
        // 看看是否缓冲区用完了
        // 如果满了说明数据很多，还在socket里但缓冲区太小放不下
        if (r->header_in->pos == r->header_in->end) {

            // 为接收http头数据分配一个大的缓冲区，拷贝已经接收的数据
            // 使用了hc->busy/free等成员
            rv = ngx_http_alloc_large_header_buffer(r, 1);

            if (rv == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (rv == NGX_DECLINED) {
                r->request_line.len = r->header_in->end - r->request_start;
                r->request_line.data = r->request_start;

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
                break;
            }
            // 此时缓冲区已经足够大了
        }

        // 缓冲区没有满，那么大小是足够的，那么就再次尝试接收数据
        // 再次进入for循环，这时recv可能返回again，那么就等待下一次读事件即有数据可读
    }

    // 处理主请求里延后处理的请求链表，直至处理完毕
    // r->main->posted_requests
    // 调用请求里的write_event_handler
    // 通常就是ngx_http_core_run_phases引擎数组处理请求
    ngx_http_run_posted_requests(c);
}


ngx_int_t
ngx_http_process_request_uri(ngx_http_request_t *r)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (r->args_start) {
        r->uri.len = r->args_start - 1 - r->uri_start;
    } else {
        r->uri.len = r->uri_end - r->uri_start;
    }

    if (r->complex_uri || r->quoted_uri) {

        r->uri.data = ngx_pnalloc(r->pool, r->uri.len + 1);
        if (r->uri.data == NULL) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        if (ngx_http_parse_complex_uri(r, cscf->merge_slashes) != NGX_OK) {
            r->uri.len = 0;

            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid request");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }

    } else {
        r->uri.data = r->uri_start;
    }

    r->unparsed_uri.len = r->uri_end - r->uri_start;
    r->unparsed_uri.data = r->uri_start;

    r->valid_unparsed_uri = r->space_in_uri ? 0 : 1;

    if (r->uri_ext) {
        if (r->args_start) {
            r->exten.len = r->args_start - 1 - r->uri_ext;
        } else {
            r->exten.len = r->uri_end - r->uri_ext;
        }

        r->exten.data = r->uri_ext;
    }

    if (r->args_start && r->uri_end > r->args_start) {
        r->args.len = r->uri_end - r->args_start;
        r->args.data = r->args_start;
    }

#if (NGX_WIN32)
    {
    u_char  *p, *last;

    p = r->uri.data;
    last = r->uri.data + r->uri.len;

    while (p < last) {

        if (*p++ == ':') {

            /*
             * this check covers "::$data", "::$index_allocation" and
             * ":$i30:$index_allocation"
             */

            if (p < last && *p == '$') {
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "client sent unsafe win32 URI");
                ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR;
            }
        }
    }

    p = r->uri.data + r->uri.len - 1;

    while (p > r->uri.data) {

        if (*p == ' ') {
            p--;
            continue;
        }

        if (*p == '.') {
            p--;
            continue;
        }

        break;
    }

    if (p != r->uri.data + r->uri.len - 1) {
        r->uri.len = p + 1 - r->uri.data;
        ngx_http_set_exten(r);
    }

    }
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uri: \"%V\"", &r->uri);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http args: \"%V\"", &r->args);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http exten: \"%V\"", &r->exten);

    return NGX_OK;
}


// 解析请求行之后的请求头数据
// 处理逻辑与ngx_http_process_request_line类似，也是无限循环，保证读取完数据
// 如果头太大，或者配置的太小，nginx会再多分配内存
// 检查收到的http请求头:content_length不能是非数字,不支持trace方法,设置keep_alive头信息
// 最后调用ngx_http_process_request
// again说明客户端发送的数据不足，会继续读取，error则结束请求
static void
ngx_http_process_request_headers(ngx_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    ngx_int_t                   rc, rv;
    ngx_table_elt_t            *h;
    ngx_connection_t           *c;
    ngx_http_header_t          *hh;
    ngx_http_request_t         *r;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    // 获取读事件相关的连接对象和请求对象
    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    // 检查是否超时
    // 由定时器超时引发的，由ngx_event_expire_timers调用
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    // 预设没有数据，需要重试
    rc = NGX_AGAIN;

    // 处理逻辑与ngx_http_process_request_line类似，也是无限循环
    for ( ;; ) {

        if (rc == NGX_AGAIN) {

            // 看看是否缓冲区用完了
            // 如果满了说明数据很多，还在socket里但缓冲区太小放不下
            if (r->header_in->pos == r->header_in->end) {

                // 为接收http头数据分配一个大的缓冲区，拷贝已经接收的数据
                // 如果数据超过了配置的缓存区大小4k，返回declined
                // 使用了hc->busy/free等成员
                rv = ngx_http_alloc_large_header_buffer(r, 0);

                if (rv == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    break;
                }

                // 如果数据超过了配置的缓存区大小4k，返回declined
                if (rv == NGX_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                        break;
                    }

                    len = r->header_in->end - p;

                    if (len > NGX_MAX_ERROR_STR - 300) {
                        len = NGX_MAX_ERROR_STR - 300;
                    }

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);

                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                    break;
                }

                // rv == ok
                // 此时缓冲区已经足够大了
            }

            // 调用recv读数据，存在r->header_in里
            // 如果暂时无数据就加入定时器等待，加入读事件
            // 下次读事件发生还会进入这里继续读取
            // 返回读取的字节数量
            n = ngx_http_read_request_header(r);

            // again会继续读取，error则结束请求
            // again说明客户端发送的数据不足
            if (n == NGX_AGAIN || n == NGX_ERROR) {
                break;
            }
        }

        // 此时已经读取了数据，存储在r->header_in里

        /* the host header could change the server configuration context */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        // 解析一行请求头，是否支持下划线由配置确定
        rc = ngx_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == NGX_OK) {

            r->request_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            // 把请求头加入链表
            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                break;
            }

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                break;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            // 成功解析完一行，继续循环，解析下一行
            continue;
        }

        // 全部头解析完毕
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            // 设置请求的状态，准备处理请求
            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

            // 检查收到的http请求头
            // http1.1不允许没有host头
            // content_length不能是非数字
            // 不支持trace方法
            // 如果是chunked编码那么长度头无意义
            // 设置keep_alive头信息
            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                break;
            }

            // 此时已经读取了完整的http请求头，可以开始处理请求了
            // 如果还在定时器红黑树里，那么就删除，不需要检查超时
            // 连接的读写事件handler都设置为ngx_http_request_handler
            // 请求的读事件设置为ngx_http_block_reading
            // 启动引擎数组，即r->write_event_handler = ngx_http_core_run_phases
            // 从phase_handler的位置开始调用模块处理
            // 如果有子请求，那么都要处理
            ngx_http_process_request(r);

            break;
        }

        // agian，请求行数据不完整
        if (rc == NGX_AGAIN) {

            /* a header line parsing is still not complete */

            // 继续循环，读取数据，保证解析一行成功
            continue;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        // 其他情况则是错误

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line");

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        break;
    }

    // 处理主请求里延后处理的请求链表，直至处理完毕
    // r->main->posted_requests
    // 调用请求里的write_event_handler
    // 通常就是ngx_http_core_run_phases引擎数组处理请求
    ngx_http_run_posted_requests(c);
}


// 调用recv读数据，存在r->header_in里
// 如果暂时无数据就加入定时器等待，加入读事件
// 下次读事件发生还会进入这里继续读取
// 返回读取的字节数量
static ssize_t
ngx_http_read_request_header(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_srv_conf_t  *cscf;

    // 从请求对象里获取连接对象和读事件
    c = r->connection;
    rev = c->read;

    // 已经读取的数据
    n = r->header_in->last - r->header_in->pos;

    // 如果缓冲区里还有数据，那么就不调用recv直接返回
    if (n > 0) {
        return n;
    }

    // 缓冲区里无数据，需要调用recv收取
    // <0 出错， =0 连接关闭， >0 接收到数据大小
    if (rev->ready) {
        // 注意缓冲区剩余空间的计算
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        n = NGX_AGAIN;
    }

    // 还是没有数据
    // 那么就加入定时器等待，加入读事件
    // 读事件的handler不需要重新设置，仍然是ngx_http_process_request_line
    // 下次读事件发生还会进入这里
    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, cscf->client_header_timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    // 读到了0字节，即连接被客户端关闭，client abort
    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    // 读到了0字节，即连接被客户端关闭，client abort
    if (n == 0 || n == NGX_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    // 设置缓冲区指针，读取了n个字节
    r->header_in->last += n;

    return n;
}


// 为接收http头数据分配一个大的缓冲区，拷贝已经接收的数据
// 如果数据超过了配置的缓存区大小4k，返回declined
// 使用了hc->busy/free等成员
static ngx_int_t
ngx_http_alloc_large_header_buffer(ngx_http_request_t *r,
    ngx_uint_t request_line)
{
    u_char                    *old, *new;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http alloc large header buffer");

    if (request_line && r->state == 0) {

        /* the client fills up the buffer with "\r\n" */

        r->header_in->pos = r->header_in->start;
        r->header_in->last = r->header_in->start;

        return NGX_OK;
    }

    old = request_line ? r->request_start : r->header_name_start;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (r->state != 0
        && (size_t) (r->header_in->pos - old)
                                     >= cscf->large_client_header_buffers.size)
    {
        return NGX_DECLINED;
    }

    hc = r->http_connection;

    if (hc->free) {
        cl = hc->free;
        hc->free = cl->next;

        b = cl->buf;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header free: %p %uz",
                       b->pos, b->end - b->last);

    } else if (hc->nbusy < cscf->large_client_header_buffers.num) {

        b = ngx_create_temp_buf(r->connection->pool,
                                cscf->large_client_header_buffers.size);
        if (b == NULL) {
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(r->connection->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http large header alloc: %p %uz",
                       b->pos, b->end - b->last);

    } else {
        return NGX_DECLINED;
    }

    cl->next = hc->busy;
    hc->busy = cl;
    hc->nbusy++;

    if (r->state == 0) {
        /*
         * r->state == 0 means that a header line was parsed successfully
         * and we do not need to copy incomplete header line and
         * to relocate the parser header pointers
         */

        r->header_in = b;

        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http large header copy: %uz", r->header_in->pos - old);

    new = b->start;

    ngx_memcpy(new, old, r->header_in->pos - old);

    b->pos = new + (r->header_in->pos - old);
    b->last = new + (r->header_in->pos - old);

    if (request_line) {
        r->request_start = new;

        if (r->request_end) {
            r->request_end = new + (r->request_end - old);
        }

        r->method_end = new + (r->method_end - old);

        r->uri_start = new + (r->uri_start - old);
        r->uri_end = new + (r->uri_end - old);

        if (r->schema_start) {
            r->schema_start = new + (r->schema_start - old);
            r->schema_end = new + (r->schema_end - old);
        }

        if (r->host_start) {
            r->host_start = new + (r->host_start - old);
            if (r->host_end) {
                r->host_end = new + (r->host_end - old);
            }
        }

        if (r->port_start) {
            r->port_start = new + (r->port_start - old);
            r->port_end = new + (r->port_end - old);
        }

        if (r->uri_ext) {
            r->uri_ext = new + (r->uri_ext - old);
        }

        if (r->args_start) {
            r->args_start = new + (r->args_start - old);
        }

        if (r->http_protocol.data) {
            r->http_protocol.data = new + (r->http_protocol.data - old);
        }

    } else {
        r->header_name_start = new;
        r->header_name_end = new + (r->header_name_end - old);
        r->header_start = new + (r->header_start - old);
        r->header_end = new + (r->header_end - old);
    }

    r->header_in = b;

    return NGX_OK;
}


// 使用offset设置headers_in里的请求头
static ngx_int_t
ngx_http_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return NGX_OK;
}


// 使用offset设置headers_in里的请求头，但不允许重复
static ngx_int_t
ngx_http_process_unique_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "client sent duplicate header line: \"%V: %V\", "
                  "previous value: \"%V: %V\"",
                  &h->key, &h->value, &(*ph)->key, &(*ph)->value);

    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t  rc;
    ngx_str_t  host;

    if (r->headers_in.host) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate host header: \"%V: %V\", "
                      "previous value: \"%V: %V\"",
                      &h->key, &h->value, &r->headers_in.host->key,
                      &r->headers_in.host->value);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->headers_in.host = h;

    host = h->value;

    // 简单验证host字符串的合法性
    rc = ngx_http_validate_host(&host, r->pool, 0);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (r->headers_in.server.len) {
        return NGX_OK;
    }

    // 定位server{}块位置
    if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->headers_in.server = host;

    return NGX_OK;
}


static ngx_int_t
ngx_http_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    if (ngx_strcasestrn(h->value.data, "close", 5 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    } else if (ngx_strcasestrn(h->value.data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return NGX_OK;
}


// 检查头里的user_agent，设置ie/chrome/safari标志位
static ngx_int_t
ngx_http_process_user_agent(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char  *user_agent, *msie;

    if (r->headers_in.user_agent) {
        return NGX_OK;
    }

    r->headers_in.user_agent = h;

    /* check some widespread browsers while the header is in CPU cache */

    user_agent = h->value.data;

    msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + h->value.len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }

#if 0
        /* MSIE ignores the SSL "close notify" alert */
        if (c->ssl) {
            c->ssl->no_send_shutdown = 1;
        }
#endif
    }

    if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
                   && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return NGX_OK;
}


// 使用offset设置headers_in里的请求头，允许重复
// 加入动态数组headers
static ngx_int_t
ngx_http_process_multi_header_lines(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_array_t       *headers;
    ngx_table_elt_t  **ph;

    headers = (ngx_array_t *) ((char *) &r->headers_in + offset);

    if (headers->elts == NULL) {
        if (ngx_array_init(headers, r->pool, 1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }
    }

    ph = ngx_array_push(headers);
    if (ph == NULL) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    *ph = h;
    return NGX_OK;
}


// 检查收到的http请求头
// http1.1不允许没有host头
// content_length不能是非数字
// 不支持trace方法
// 如果是chunked编码那么长度头无意义
// 设置keep_alive头信息
ngx_int_t
ngx_http_process_request_header(ngx_http_request_t *r)
{
    if (r->headers_in.server.len == 0
        && ngx_http_set_virtual_server(r, &r->headers_in.server)
           == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    // http1.1不允许没有host头
    if (r->headers_in.host == NULL && r->http_version > NGX_HTTP_VERSION_10) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                   "client sent HTTP/1.1 request without \"Host\" header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    // content_length不能是非数字
    if (r->headers_in.content_length) {
        r->headers_in.content_length_n =
                            ngx_atoof(r->headers_in.content_length->value.data,
                                      r->headers_in.content_length->value.len);

        if (r->headers_in.content_length_n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid \"Content-Length\" header");
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
    }

    // 不支持trace方法
    if (r->method == NGX_HTTP_TRACE) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent TRACE method");
        ngx_http_finalize_request(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR;
    }

    if (r->headers_in.transfer_encoding) {
        if (r->headers_in.transfer_encoding->value.len == 7
            && ngx_strncasecmp(r->headers_in.transfer_encoding->value.data,
                               (u_char *) "chunked", 7) == 0)
        {
            r->headers_in.content_length = NULL;
            r->headers_in.content_length_n = -1;
            r->headers_in.chunked = 1;

        } else {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent unknown \"Transfer-Encoding\": \"%V\"",
                          &r->headers_in.transfer_encoding->value);
            ngx_http_finalize_request(r, NGX_HTTP_NOT_IMPLEMENTED);
            return NGX_ERROR;
        }
    }

    if (r->headers_in.connection_type == NGX_HTTP_CONNECTION_KEEP_ALIVE) {
        if (r->headers_in.keep_alive) {
            r->headers_in.keep_alive_n =
                            ngx_atotm(r->headers_in.keep_alive->value.data,
                                      r->headers_in.keep_alive->value.len);
        }
    }

    return NGX_OK;
}


// 此时已经读取了完整的http请求头，可以开始处理请求了
// 如果还在定时器红黑树里，那么就删除，不需要检查超时
// 连接的读写事件handler都设置为ngx_http_request_handler
// 请求的读事件设置为ngx_http_block_reading
// 启动引擎数组，即r->write_event_handler = ngx_http_core_run_phases
// 从phase_handler的位置开始调用模块处理
// 如果有子请求，那么都要处理
void
ngx_http_process_request(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    // 获取读事件相关的连接对象
    c = r->connection;

#if (NGX_HTTP_SSL)

    if (r->http_connection->ssl) {
        long                      rc;
        X509                     *cert;
        const char               *s;
        ngx_http_ssl_srv_conf_t  *sscf;

        if (c->ssl == NULL) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent plain HTTP request to HTTPS port");
            ngx_http_finalize_request(r, NGX_HTTP_TO_HTTPS);
            return;
        }

        sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

        if (sscf->verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK
                && (sscf->verify != 3 || !ngx_ssl_verify_error_optional(rc)))
            {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));

                ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);
                return;
            }

            if (sscf->verify == 1) {
                cert = SSL_get_peer_certificate(c->ssl->connection);

                if (cert == NULL) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent no required SSL certificate");

                    ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                    ngx_http_finalize_request(r, NGX_HTTPS_NO_CERT);
                    return;
                }

                X509_free(cert);
            }

            if (ngx_ssl_ocsp_get_status(c, &s) != NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client SSL certificate verify error: %s", s);

                ngx_ssl_remove_cached_session(c->ssl->session_ctx,
                                       (SSL_get0_session(c->ssl->connection)));

                ngx_http_finalize_request(r, NGX_HTTPS_CERT_ERROR);
                return;
            }
        }
    }

#endif

    // 此时已经读取了完整的http请求头，可以开始处理请求了
    // 如果还在定时器红黑树里，那么就删除，不需要检查超时
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    r->stat_reading = 0;
    (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);
    r->stat_writing = 1;
#endif

    // 头读取完毕
    // 连接的读写事件handler都设置为ngx_http_request_handler
    // 内部会转调用r->write_event_handler/r->read_event_handler
    c->read->handler = ngx_http_request_handler;
    c->write->handler = ngx_http_request_handler;

    // 请求的读事件设置为ngx_http_block_reading
    // 即忽略读事件，有数据也不会处理
    // 如果之后调用了丢弃或者读取body
    // 那么会变成ngx_http_discarded_request_body_handler/ngx_http_read_client_request_body_handler
    r->read_event_handler = ngx_http_block_reading;

    // in ngx_http_core_module.c
    // 启动引擎数组，即r->write_event_handler = ngx_http_core_run_phases
    //
    // 外部请求的引擎数组起始序号是0，从头执行引擎数组,即先从Post read开始
    // 内部请求，即子请求.跳过post read，直接从server rewrite开始执行，即查找server
    // 启动引擎数组处理请求，调用ngx_http_core_run_phases
    // 从phase_handler的位置开始调用模块处理
    ngx_http_handler(r);

    // 如果有子请求，那么都要处理
    // 处理主请求里延后处理的请求链表，直至处理完毕
    // r->main->posted_requests
    // 调用请求里的write_event_handler
    // 通常就是ngx_http_core_run_phases引擎数组处理请求
    // 1.15.4将此行删除
    //ngx_http_run_posted_requests(c);
}


// 简单验证host字符串的合法性
static ngx_int_t
ngx_http_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NGX_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NGX_DECLINED;

        default:

            if (ngx_path_separator(ch)) {
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    if (alloc) {
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}


// 由请求行或请求头里的host定位server{}块位置，决定进入哪个server
// 核心是ngx_http_find_virtual_server
static ngx_int_t
ngx_http_set_virtual_server(ngx_http_request_t *r, ngx_str_t *host)
{
    ngx_int_t                  rc;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

#if (NGX_SUPPRESS_WARN)
    cscf = NULL;
#endif

    hc = r->http_connection;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        if (hc->ssl_servername->len == host->len
            && ngx_strncmp(hc->ssl_servername->data,
                           host->data, host->len) == 0)
        {
#if (NGX_PCRE)
            if (hc->ssl_servername_regex
                && ngx_http_regex_exec(r, hc->ssl_servername_regex,
                                          hc->ssl_servername) != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_ERROR;
            }
#endif
            return NGX_OK;
        }
    }

#endif

    // 查找匹配的server{}块
    // 先在hash表里找完全匹配
    // 找不到用正则匹配
    rc = ngx_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names,
                                      host, r, &cscf);

    if (rc == NGX_ERROR) {
        ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

    if (hc->ssl_servername) {
        ngx_http_ssl_srv_conf_t  *sscf;

        if (rc == NGX_DECLINED) {
            cscf = hc->addr_conf->default_server;
            rc = NGX_OK;
        }

        sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);

        if (sscf->verify) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
            return NGX_ERROR;
        }
    }

#endif

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    // cscf是找到的server{}配置结构体
    // 里面的ctx是配置数组
    // 这里正确设置了请求所在server{}块的配置信息
    r->srv_conf = cscf->ctx->srv_conf;
    r->loc_conf = cscf->ctx->loc_conf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_set_connection_log(r->connection, clcf->error_log);

    return NGX_OK;
}


// 查找匹配的server{}块
// 先在hash表里找完全匹配
// 找不到用正则匹配
static ngx_int_t
ngx_http_find_virtual_server(ngx_connection_t *c,
    ngx_http_virtual_names_t *virtual_names, ngx_str_t *host,
    ngx_http_request_t *r, ngx_http_core_srv_conf_t **cscfp)
{
    ngx_http_core_srv_conf_t  *cscf;

    if (virtual_names == NULL) {
        return NGX_DECLINED;
    }

    // 先在hash表里找完全匹配
    cscf = ngx_hash_find_combined(&virtual_names->names,
                                  ngx_hash_key(host->data, host->len),
                                  host->data, host->len);

    if (cscf) {
        *cscfp = cscf;
        return NGX_OK;
    }

    // hash找不到用正则匹配
#if (NGX_PCRE)

    if (host->len && virtual_names->nregex) {
        ngx_int_t                n;
        ngx_uint_t               i;
        ngx_http_server_name_t  *sn;

        sn = virtual_names->regex;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)

        if (r == NULL) {
            ngx_http_connection_t  *hc;

            for (i = 0; i < virtual_names->nregex; i++) {

                n = ngx_regex_exec(sn[i].regex->regex, host, NULL, 0);

                if (n == NGX_REGEX_NO_MATCHED) {
                    continue;
                }

                if (n >= 0) {
                    hc = c->data;
                    hc->ssl_servername_regex = sn[i].regex;

                    *cscfp = sn[i].server;
                    return NGX_OK;
                }

                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              ngx_regex_exec_n " failed: %i "
                              "on \"%V\" using \"%V\"",
                              n, host, &sn[i].regex->name);

                return NGX_ERROR;
            }

            return NGX_DECLINED;
        }

#endif /* NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME */

        for (i = 0; i < virtual_names->nregex; i++) {

            n = ngx_http_regex_exec(r, sn[i].regex, host);

            if (n == NGX_DECLINED) {
                continue;
            }

            if (n == NGX_OK) {
                *cscfp = sn[i].server;
                return NGX_OK;
            }

            return NGX_ERROR;
        }
    }

#endif /* NGX_PCRE */

    return NGX_DECLINED;
}


// http请求处理时的事件handler
// 当读取完请求头后读写事件的handler都是它
// 通常写事件就是ngx_http_core_run_phases引擎数组处理请求
static void
ngx_http_request_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    // 获取读事件相关的连接对象和请求对象
    c = ev->data;
    r = c->data;

    ngx_http_set_log_request(c->log, r);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http run request: \"%V?%V\"", &r->uri, &r->args);

    if (c->close) {
        r->main->count++;
        ngx_http_terminate_request(r, 0);
        ngx_http_run_posted_requests(c);
        return;
    }

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    // 有写事件就调用请求里的write_event_handler
    if (ev->write) {
        // write_event_handler通常就是ngx_http_core_run_phases引擎数组处理请求
        r->write_event_handler(r);

    } else {
        // 否则是读事件，调用read_event_handler
        r->read_event_handler(r);
    }

    // 请求自己的读写事件已经处理完

    // 如果有子请求，那么都要处理
    // 每当有事件发生，子请求都会有机会得到处理
    ngx_http_run_posted_requests(c);
}


// 处理主请求里延后处理的请求链表，直至处理完毕
// r->main->posted_requests
// 调用请求里的write_event_handler
// 通常就是ngx_http_core_run_phases引擎数组处理请求
void
ngx_http_run_posted_requests(ngx_connection_t *c)
{
    ngx_http_request_t         *r;
    ngx_http_posted_request_t  *pr;

    // 处理主请求里延后处理的请求链表，直至处理完毕
    for ( ;; ) {

        // 连接对象被销毁则结束
        if (c->destroyed) {
            return;
        }

        // 取连接里的请求对象
        r = c->data;

        // 获取主请求里的延后处理请求链表
        pr = r->main->posted_requests;

        // 没有延后处理请求
        if (pr == NULL) {
            return;
        }

        // 取头元素，注意用的是r->main，获得一个请求
        r->main->posted_requests = pr->next;

        r = pr->request;

        ngx_http_set_log_request(c->log, r);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);

        // 调用请求里的write_event_handler
        // 通常就是ngx_http_core_run_phases引擎数组处理请求
        r->write_event_handler(r);
    }
}


// 把请求r加入到主请求的延后处理链表末尾
ngx_int_t
ngx_http_post_request(ngx_http_request_t *r, ngx_http_posted_request_t *pr)
{
    ngx_http_posted_request_t  **p;

    // 分配一个链表节点
    if (pr == NULL) {
        pr = ngx_palloc(r->pool, sizeof(ngx_http_posted_request_t));
        if (pr == NULL) {
            return NGX_ERROR;
        }
    }

    // 填充字段
    pr->request = r;
    pr->next = NULL;

    // 主请求的链表末尾
    for (p = &r->main->posted_requests; *p; p = &(*p)->next) { /* void */ }

    // 加到末尾
    *p = pr;

    return NGX_OK;
}


// 重要函数，以“适当”的方式“结束”请求
// 并不一定会真正结束，大部分情况下只是暂时停止处理，等待epoll事件发生
// 参数rc决定了函数的逻辑，在content阶段就是handler的返回值
// 调用ngx_http_finalize_connection，检查请求相关的异步事件，尝试关闭请求
//
// done，例如调用read body,因为count已经增加，所以不会关闭请求
void
ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
    ngx_http_request_t        *pr;
    ngx_http_core_loc_conf_t  *clcf;

    // 连接对象
    c = r->connection;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %i, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    // handler返回done，例如调用read body
    // 因为count已经增加，所以不会关闭请求
    if (rc == NGX_DONE) {
        // 检查请求相关的异步事件，尝试关闭请求
        //
        // 有多个引用计数，表示有其他异步事件在处理
        // 那么就不能真正结束请求
        // 调用ngx_http_close_request尝试关闭请求，引用计数减1
        ngx_http_finalize_connection(r);
        return;
    }

    // ok处理成功，但过滤链表出错了
    if (rc == NGX_OK && r->filter_finalize) {
        c->error = 1;
    }

    // 请求被拒绝处理，那么就重新设置r->write_event_handler
    // 继续走ngx_http_core_run_phases
    // 使用引擎数组里的content handler处理
    if (rc == NGX_DECLINED) {

        // content_handler设置为空指针，不再使用location专用handler
        r->content_handler = NULL;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    // 不是done、declined，可能是ok、error、again

    // 不是done、declined，是子请求
    if (r != r->main && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    // 返回错误，或者是http超时等错误
    if (rc == NGX_ERROR
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (ngx_http_post_action(r) == NGX_OK) {
            return;
        }

        //if (r->main->blocked) {
        //    r->write_event_handler = ngx_http_request_finalizer;
        //}

        // 释放主请求相关的资源，调用cleanup链表，相当于析构
        // 如果主请求有多线程任务阻塞，那么不能结束请求
        // 否则调用ngx_http_close_request尝试关闭请求，引用计数减1
        ngx_http_terminate_request(r, rc);
        return;
    }

    // 返回了300以上的http错误码
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE
        || rc == NGX_HTTP_CREATED
        || rc == NGX_HTTP_NO_CONTENT)
    {
        // NGX_HTTP_CLOSE是Nginx自己定义的错误码
        // #define NGX_HTTP_CLOSE                     444
        if (rc == NGX_HTTP_CLOSE) {
            c->timedout = 1;
            ngx_http_terminate_request(r, rc);
            return;
        }

        // 主请求，需要删除定时器，不再考虑超时
        if (r == r->main) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }
        }

        c->read->handler = ngx_http_request_handler;
        c->write->handler = ngx_http_request_handler;

        // 发生错误时返回合适的响应内容
        ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
        return;
    }

    // 不是done、declined，可能是ok、error、again

    // 是子请求
    if (r != r->main) {
#if 0   // 1.17.9
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        // 子请求在后台处理，通常是mirror镜像流量
        if (r->background) {
            if (!r->logged) {
                if (clcf->log_subrequest) {
                    ngx_http_log_request(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            // background则直接结束子请求
            ngx_http_finalize_connection(r);
            return;
        }
#endif

        if (r->buffered || r->postponed) {

            // 设置发送数据的handler，即写事件的回调handler为write_event_handler
            // 不限速，需要加入发送超时，即send_timeout时间内socket不可写则报错
            // 使用send_lowat设置epoll写事件
            // 只有内核socket缓冲区有send_lowat的空间才会触发写事件
            // 当可写时真正的向客户端发送数据，调用send_chain
            // 如果数据发送不完，就保存在r->out里，返回again,需要再次发生可写事件才能发送
            // 不是last、flush，且数据量较小（默认1460）
            // 那么就不真正调用write发送，减少系统调用的次数，提高性能
            if (ngx_http_set_write_handler(r) != NGX_OK) {
                ngx_http_terminate_request(r, 0);
            }

            return;
        }

        // 检查父请求
        pr = r->parent;

        if (r == c->data || r->background) {

            if (!r->logged) {

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->log_subrequest) {
                    ngx_http_log_request(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (r->background) {
                ngx_http_finalize_connection(r);
                return;
            }

            r->main->count--;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = ngx_http_request_finalizer;

            // NGX_HTTP_SUBREQUEST_WAITED
            if (r->waited) {
                r->done = 1;
            }
        }

        if (ngx_http_post_request(pr, NULL) != NGX_OK) {
            r->main->count++;
            ngx_http_terminate_request(r, 0);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }   // 子请求处理结束

    // c->buffered，有数据在r->out里还没有发送
    // r->blocked，有线程task正在阻塞运行
    if (r->buffered || c->buffered || r->postponed) {

        // 设置发送数据的handler，即写事件的回调handler为write_event_handler
        // 不限速，需要加入发送超时，即send_timeout时间内socket不可写则报错
        // 使用send_lowat设置epoll写事件
        // 只有内核socket缓冲区有send_lowat的空间才会触发写事件
        // 当可写时真正的向客户端发送数据，调用send_chain
        // 如果数据发送不完，就保存在r->out里，返回again,需要再次发生可写事件才能发送
        // 不是last、flush，且数据量较小（默认1460）
        // 那么就不真正调用write发送，减少系统调用的次数，提高性能
        if (ngx_http_set_write_handler(r) != NGX_OK) {
            ngx_http_terminate_request(r, 0);
        }

        return;
    }

    // c->data里存储的必须是当前请求
    // 如果设置错了会导致alert
    if (r != c->data) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    // 到这里，请求应该基本可以确定要结束了，设置done
    r->done = 1;

    r->read_event_handler = ngx_http_block_reading;

    // 不需要再关注写事件，因为数据已经发送完了
    r->write_event_handler = ngx_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (ngx_http_post_action(r) == NGX_OK) {
        return;
    }

    // 准备结束请求

    // 删除读事件超时，不再需要了
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    // 删除写事件超时，不再需要了
    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    if (c->read->eof) {
        // 尝试关闭请求，引用计数减1，表示本操作完成
        // 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
        // 不能关闭，直接返回
        // 引用计数为0，没有任何操作了，可以安全关闭
        // 释放请求相关的资源，调用cleanup链表，相当于析构
        // 此时请求已经结束，调用log模块记录日志
        // 销毁请求的内存池
        // 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
        // 最后销毁连接的内存池
        ngx_http_close_request(r, 0);
        return;
    }

    // 检查请求相关的异步事件，尝试关闭请求
    //
    // 有多个引用计数，表示有其他异步事件在处理
    // 那么就不能真正结束请求
    // 调用ngx_http_close_request尝试关闭请求，引用计数减1
    ngx_http_finalize_connection(r);
}


// 释放主请求相关的资源，调用cleanup链表，相当于析构
// 如果主请求有多线程任务阻塞，那么不能结束请求
// 否则调用ngx_http_close_request尝试关闭请求，引用计数减1
static void
ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_cleanup_t    *cln;
    ngx_http_request_t    *mr;
    ngx_http_ephemeral_t  *e;

    // mr是主请求
    mr = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate request count:%d", mr->count);

    // rc > 0 是http状态码
    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    // 释放主请求相关的资源，调用cleanup链表，相当于析构
    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    // 检查主请求是否还在处理
    // 把请求加入到mr的延后处理链表末尾
    if (mr->write_event_handler) {

        // 如果主请求有多线程任务阻塞，那么不能结束请求
        if (mr->blocked) {
            r->connection->error = 1;
            r->write_event_handler = ngx_http_request_finalizer;
            return;
        }

        e = ngx_http_ephemeral(mr);
        mr->posted_requests = NULL;

        // 设置为主请求的write_event_handler
        // 强制令引用计数为1，必须关闭
        // 调用ngx_http_close_request
        mr->write_event_handler = ngx_http_terminate_handler;

        // 把请求加入到mr的延后处理链表末尾
        (void) ngx_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    // 尝试关闭请求，引用计数减1，表示本操作完成
    // 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
    // 不能关闭，直接返回
    // 引用计数为0，没有任何操作了，可以安全关闭
    // 释放请求相关的资源，调用cleanup链表，相当于析构
    // 此时请求已经结束，调用log模块记录日志
    // 销毁请求的内存池
    // 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
    // 最后销毁连接的内存池
    ngx_http_close_request(mr, rc);
}


// 设置为主请求的write_event_handler
// 强制令引用计数为1，必须关闭
// 调用ngx_http_close_request
static void
ngx_http_terminate_handler(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate handler count:%d", r->count);

    // 强制令引用计数为1，必须关闭
    r->count = 1;

    // 尝试关闭请求，引用计数减1，表示本操作完成
    // 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
    // 不能关闭，直接返回
    // 引用计数为0，没有任何操作了，可以安全关闭
    // 释放请求相关的资源，调用cleanup链表，相当于析构
    // 此时请求已经结束，调用log模块记录日志
    // 销毁请求的内存池
    // 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
    // 最后销毁连接的内存池
    ngx_http_close_request(r, 0);
}


// 检查请求相关的异步事件，尝试关闭请求
//
// 有多个引用计数，表示有其他异步事件在处理
// 那么就不能真正结束请求
// 调用ngx_http_close_request尝试关闭请求，引用计数减1
// r->main->count == 1，可以结束请求
// 如果正在读取请求体，那么设置标志位，要求延后读取数据关闭
// 如果进程正在运行，没有退出，且请求要求keepalive
// 那么调用ngx_http_set_keepalive而不是关闭请求
// 不keepalive，也不延后关闭,那么就真正关闭
// 尝试关闭请求，引用计数减1，表示本操作完成
static void
ngx_http_finalize_connection(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_close_request(r, 0);
        return;
    }
#endif

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    // 有多个引用计数，表示有其他异步事件在处理
    // 那么就不能真正结束请求
    // 调用ngx_http_close_request尝试关闭请求，引用计数减1
    if (r->main->count != 1) {

        // 如果正在丢弃请求体，那么设置丢弃handler和超时时间
        if (r->discard_body) {
            r->read_event_handler = ngx_http_discarded_request_body_handler;
            ngx_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = ngx_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

        // 尝试关闭请求，引用计数减1，表示本操作完成
        // 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
        // 不能关闭，直接返回
        // 引用计数为0，没有任何操作了，可以安全关闭
        // 释放请求相关的资源，调用cleanup链表，相当于析构
        // 此时请求已经结束，调用log模块记录日志
        // 销毁请求的内存池
        // 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
        // 最后销毁连接的内存池
        ngx_http_close_request(r, 0);
        return;
    }

    // r->main->count == 1，可以结束请求

    r = r->main;

    // 如果正在读取请求体，那么设置标志位，要求延后读取数据关闭
    if (r->reading_body) {
        r->keepalive = 0;
        r->lingering_close = 1;
    }

    // 如果进程正在运行，没有退出，且请求要求keepalive
    // 那么调用ngx_http_set_keepalive而不是关闭请求
    if (!ngx_terminate
         && !ngx_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        ngx_http_set_keepalive(r);
        return;
    }

    // 如果要求延后关闭，那么就延后关闭
    if (clcf->lingering_close == NGX_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == NGX_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready)))
    {
        ngx_http_set_lingering_close(r);
        return;
    }

    // 不keepalive，也不延后关闭
    // 那么就真正关闭

    // 尝试关闭请求，引用计数减1，表示本操作完成
    // 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
    // 不能关闭，直接返回
    // 引用计数为0，没有任何操作了，可以安全关闭
    // 释放请求相关的资源，调用cleanup链表，相当于析构
    // 此时请求已经结束，调用log模块记录日志
    // 销毁请求的内存池
    // 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
    // 最后销毁连接的内存池
    ngx_http_close_request(r, 0);
}


// 设置发送数据的handler，即写事件的回调handler为write_event_handler
// 不限速，需要加入发送超时，即send_timeout时间内socket不可写则报错
// 使用send_lowat设置epoll写事件
// 只有内核socket缓冲区有send_lowat的空间才会触发写事件
// 当可写时真正的向客户端发送数据，调用send_chain
// 如果数据发送不完，就保存在r->out里，返回again,需要再次发生可写事件才能发送
// 不是last、flush，且数据量较小（默认1460）
// 那么就不真正调用write发送，减少系统调用的次数，提高性能
static ngx_int_t
ngx_http_set_write_handler(ngx_http_request_t *r)
{
    ngx_event_t               *wev;
    ngx_http_core_loc_conf_t  *clcf;

    // 当前的状态是正在发送数据
    r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;

    // 如果当前是丢弃请求体，那么读handler是ngx_http_discarded_request_body_handler
    // 否则是ngx_http_test_reading
    r->read_event_handler = r->discard_body ?
                                ngx_http_discarded_request_body_handler:
                                ngx_http_test_reading;

    // 写事件handler是ngx_http_writer
    //
    // 真正的向客户端发送数据，调用send_chain
    // 如果数据发送不完，就保存在r->out里，返回again
    // 需要再次发生可写事件才能发送
    // 不是last、flush，且数据量较小（默认1460）
    // 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
    // 在此函数里处理限速
    r->write_event_handler = ngx_http_writer;

    // 连接里的写事件
    wev = r->connection->write;

    // 如果此时是可写的，或者需要限速，那么直接返回
    // 不需要加入epoll事件
    if (wev->ready && wev->delayed) {
        return NGX_OK;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    // 不限速，需要加入发送超时
    // 即send_timeout时间内socket不可写则报错
    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    // 使用send_lowat设置epoll写事件
    // 只有内核socket缓冲区有send_lowat的空间才会触发写事件
    // linux不支持send_lowat指令，send_lowat总是0
    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}


// 写事件handler是ngx_http_writer
// 检查写事件是否已经超时
// delayed表示限速,如果不限速那么就结束请求
// 调用过滤链表发送数据
// 有数据被缓存，没有完全发送
// 加上超时等待，注册写事件，等socket可写再发送
static void
ngx_http_writer(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    // 从请求里获得连接和写事件
    c = r->connection;
    wev = c->write;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

    // 检查写事件是否已经超时
    if (wev->timedout) {
        // 1.12.0删除了下面的代码
        //
        //// delayed表示限速
        //// 如果不限速那么就结束请求
        //if (!wev->delayed) {
        //    ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
        //                  "client timed out");
        //    c->timedout = 1;

        //    ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        //    return;
        //}

        //// 限速，超时就不处理，暂时不发送数据

        //// 清除超时标志位
        //wev->timedout = 0;
        //wev->delayed = 0;

        //// 再次加上超时检查
        //if (!wev->ready) {
        //    ngx_add_timer(wev, clcf->send_timeout);

        //    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        //        ngx_http_close_request(r, 0);
        //    }

        //    return;
        //}
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out");
        c->timedout = 1;

        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    // 没有超时， 但限速
    // 那么继续等待写事件
    if (wev->delayed || r->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    // 调用过滤链表发送数据
    //
    // 真正的向客户端发送数据，调用send_chain
    // 如果数据发送不完，就保存在r->out里，返回again
    // 需要再次发生可写事件才能发送
    // 不是last、flush，且数据量较小（默认1460）
    // 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
    // 在此函数里处理限速
    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %i, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    // 出错直接结束请求
    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    // rc == NGX_AGAIN/NGX_OK

    // 有数据被缓存，没有完全发送
    // 加上超时等待，注册写事件，等socket可写再发送
    // rc == NGX_AGAIN
    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    // rc == NGX_OK
    // 数据已经发送完毕

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    // 设置写事件处理函数，不再有任何发送动作
    r->write_event_handler = ngx_http_request_empty_handler;

    // 结束请求，注意传入的rc，会有其他判断动作
    // 写事件处理函数也可能在这里再变为其他函数
    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_request_finalizer(ngx_http_request_t *r)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http finalizer done: \"%V?%V\"", &r->uri, &r->args);

    ngx_http_finalize_request(r, 0);
}


// 仅打印日志，不从socket读数据，故客户端发送将阻塞
void
ngx_http_block_reading(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http reading blocked");

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }
}


void
ngx_http_test_reading(ngx_http_request_t *r)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http test reading");

#if (NGX_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}


// 代替关闭连接的动作，保持连接
// 释放请求相关的资源，调用cleanup链表，相当于析构
// 但连接的内存池还在，可以用于长连接继续使用
// 关注读事件，等待客户端发送数据
// rev->handler = ngx_http_keepalive_handler;
static void
ngx_http_set_keepalive(ngx_http_request_t *r)
{
    int                        tcp_nodelay;
    ngx_buf_t                 *b, *f;
    ngx_chain_t               *cl, *ln;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_core_loc_conf_t  *clcf;

    // 从请求里获得连接和读事件
    c = r->connection;
    rev = c->read;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "set http keepalive handler");

    // 请求正在丢弃body
    // 使用lingering_time延迟关闭，如果一段时间内没有数据发过来就关闭连接
    // r->read_event_handler = ngx_http_discarded_request_body_handler;
    if (r->discard_body) {
        r->write_event_handler = ngx_http_request_empty_handler;
        r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
        ngx_add_timer(rev, clcf->lingering_timeout);
        return;
    }

    c->log->action = "closing request";

    hc = r->http_connection;

    // b是请求的读取缓冲区
    b = r->header_in;

    // 检查缓冲区里是否还有数据没有处理
    if (b->pos < b->last) {

        /* the pipelined request */

        if (b != c->buffer) {

            /*
             * If the large header buffers were allocated while the previous
             * request processing then we do not use c->buffer for
             * the pipelined request (see ngx_http_create_request()).
             *
             * Now we would move the large header buffers to the free list.
             */

            for (cl = hc->busy; cl; /* void */) {
                ln = cl;
                cl = cl->next;

                if (ln->buf == b) {
                    ngx_free_chain(c->pool, ln);
                    continue;
                }

                f = ln->buf;
                f->pos = f->start;
                f->last = f->start;

                ln->next = hc->free;
                hc->free = ln;
            }

            cl = ngx_alloc_chain_link(c->pool);
            if (cl == NULL) {
                ngx_http_close_request(r, 0);
                return;
            }

            cl->buf = b;
            cl->next = NULL;

            hc->busy = cl;
            hc->nbusy = 1;
        }
    }

    /* guard against recursive call from ngx_http_finalize_connection() */
    r->keepalive = 0;

    // 释放请求相关的资源，调用cleanup链表，相当于析构
    // 此时请求已经结束，调用log模块记录日志
    // 销毁请求的内存池
    // 但连接的内存池还在，可以用于长连接继续使用
    ngx_http_free_request(r, 0);

    // 请求已经销毁，连接的data成员改为保存hc
    c->data = hc;

    // 关注读事件，等待客户端发送数据
    // rev->handler = ngx_http_keepalive_handler;
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

    // 写事件暂时阻塞
    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (b->pos < b->last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "pipelined request");

        c->log->action = "reading client pipelined request line";

        r = ngx_http_create_request(c);
        if (r == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        r->pipeline = 1;

        c->data = r;

        c->sent = 0;
        c->destroyed = 0;

        if (rev->timer_set) {
            ngx_del_timer(rev);
        }

        rev->handler = ngx_http_process_request_line;
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    /*
     * To keep a memory footprint as small as possible for an idle keepalive
     * connection we try to free c->buffer's memory if it was allocated outside
     * the c->pool.  The large header buffers are always allocated outside the
     * c->pool and are freed too.
     */

    b = c->buffer;

    if (ngx_pfree(c->pool, b->start) == NGX_OK) {

        /*
         * the special note for ngx_http_keepalive_handler() that
         * c->buffer's memory was freed
         */

        b->pos = NULL;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc free: %p",
                   hc->free);

    if (hc->free) {
        for (cl = hc->free; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            ngx_pfree(c->pool, ln->buf->start);
            ngx_free_chain(c->pool, ln);
        }

        hc->free = NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "hc busy: %p %i",
                   hc->busy, hc->nbusy);

    if (hc->busy) {
        for (cl = hc->busy; cl; /* void */) {
            ln = cl;
            cl = cl->next;
            ngx_pfree(c->pool, ln->buf->start);
            ngx_free_chain(c->pool, ln);
        }

        hc->busy = NULL;
        hc->nbusy = 0;
    }

#if (NGX_HTTP_SSL)
    if (c->ssl) {
        ngx_ssl_free_buffer(c);
    }
#endif

    // 这里设置读事件处理函数
    rev->handler = ngx_http_keepalive_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }
    }

    c->log->action = "keepalive";

    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
        if (ngx_tcp_push(c->fd) == -1) {
            ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
            ngx_http_close_connection(c);
            return;
        }

        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;

    } else {
        tcp_nodelay = 1;
    }

    // 设置tcp nodelay选项
    if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

#if 0
    /* if ngx_http_request_t was freed then we need some other place */
    r->http_state = NGX_HTTP_KEEPALIVE_STATE;
#endif

    // 连接可以复用，加入复用队列
    c->idle = 1;
    ngx_reusable_connection(c, 1);

    // 设置keepalive超时时间
    ngx_add_timer(rev, clcf->keepalive_timeout);

    if (rev->ready) {
        ngx_post_event(rev, &ngx_posted_events);
    }
}


static void
ngx_http_keepalive_handler(ngx_event_t *rev)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_connection_t  *c;

    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http keepalive handler");

    if (rev->timedout || c->close) {
        ngx_http_close_connection(c);
        return;
    }

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        if (rev->pending_eof) {
            c->log->handler = NULL;
            ngx_log_error(NGX_LOG_INFO, c->log, rev->kq_errno,
                          "kevent() reported that client %V closed "
                          "keepalive connection", &c->addr_text);
#if (NGX_HTTP_SSL)
            if (c->ssl) {
                c->ssl->no_send_shutdown = 1;
            }
#endif
            ngx_http_close_connection(c);
            return;
        }
    }

#endif

    b = c->buffer;
    size = b->end - b->start;

    if (b->pos == NULL) {

        /*
         * The c->buffer's memory was freed by ngx_http_set_keepalive().
         * However, the c->buffer->start and c->buffer->end were not changed
         * to keep the buffer size.
         */

        b->pos = ngx_palloc(c->pool, size);
        if (b->pos == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        b->start = b->pos;
        b->last = b->pos;
        b->end = b->pos + size;
    }

    /*
     * MSIE closes a keepalive connection with RST flag
     * so we ignore ECONNRESET here.
     */

    c->log_error = NGX_ERROR_IGNORE_ECONNRESET;
    ngx_set_socket_errno(0);

    n = c->recv(c, b->last, size);
    c->log_error = NGX_ERROR_INFO;

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        /*
         * Like ngx_http_set_keepalive() we are trying to not hold
         * c->buffer's memory for a keepalive connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {

            /*
             * the special note that c->buffer's memory was freed
             */

            b->pos = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    c->log->handler = NULL;

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, ngx_socket_errno,
                      "client %V closed keepalive connection", &c->addr_text);
        ngx_http_close_connection(c);
        return;
    }

    b->last += n;

    c->log->handler = ngx_http_log_error;
    c->log->action = "reading client request line";

    c->idle = 0;
    ngx_reusable_connection(c, 0);

    c->data = ngx_http_create_request(c);
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->sent = 0;
    c->destroyed = 0;

    ngx_del_timer(rev);

    rev->handler = ngx_http_process_request_line;
    ngx_http_process_request_line(rev);
}


// 计算延后关闭的时间，添加超时
// 设置读事件处理函数为ngx_http_lingering_close_handler
// 如果此时有数据可读那么直接调用ngx_http_lingering_close_handler
static void
ngx_http_set_lingering_close(ngx_http_request_t *r)
{
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    // 获取连接对象
    c = r->connection;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    // 设置读事件处理函数为ngx_http_lingering_close_handler
    rev = c->read;
    rev->handler = ngx_http_lingering_close_handler;

    // 计算延后关闭的时间，添加超时
    r->lingering_time = ngx_time() + (time_t) (clcf->lingering_time / 1000);
    ngx_add_timer(rev, clcf->lingering_timeout);

    // 注册读事件
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return;
    }

    // 写事件不处理
    wev = c->write;
    wev->handler = ngx_http_empty_handler;

    if (wev->active && (ngx_event_flags & NGX_USE_LEVEL_EVENT)) {
        if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
            return;
        }
    }

    // 写关闭
    if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             ngx_shutdown_socket_n " failed");
        ngx_http_close_request(r, 0);
        return;
    }

    // 如果此时有数据可读那么直接调用ngx_http_lingering_close_handler
    if (rev->ready) {
        // 超时直接关闭连接
        // 否则读取数据，但并不处理，使用固定的buffer
        // 返回again，无数据可读，需要继续等待
        ngx_http_lingering_close_handler(rev);
    }
}


// 超时直接关闭连接
// 否则读取数据，但并不处理，使用固定的buffer
// 返回again，无数据可读，需要继续等待
static void
ngx_http_lingering_close_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_msec_t                 timer;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_core_loc_conf_t  *clcf;
    u_char                     buffer[NGX_HTTP_LINGERING_BUFFER_SIZE];

    // 获取连接对象
    c = rev->data;
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http lingering close handler");

    // 超时直接关闭连接
    if (rev->timedout) {
        ngx_http_close_request(r, 0);
        return;
    }

    // 可能还没加入定时器红黑树，需要再计算时间

    // 计算延迟关闭的时间，如果超过了就关闭
    timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();
    if ((ngx_msec_int_t) timer <= 0) {
        ngx_http_close_request(r, 0);
        return;
    }

    // 没超时，读事件表示有数据需要接收
    // 读取数据，但并不处理，使用固定的buffer
    do {
        n = c->recv(c, buffer, NGX_HTTP_LINGERING_BUFFER_SIZE);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "lingering read: %z", n);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_http_close_request(r, 0);
            return;
        }

    } while (rev->ready);

    // 返回again，无数据可读，需要继续等待
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return;
    }

    // 继续等待读时间，超时时间重新设置
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    timer *= 1000;

    if (timer > clcf->lingering_timeout) {
        timer = clcf->lingering_timeout;
    }

    ngx_add_timer(rev, timer);
}


// 用于忽略读写事件，即不处理
void
ngx_http_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http empty handler");

    return;
}


// 用于忽略写事件，即不处理
// r->write_event_handler = ngx_http_request_empty_handler;
void
ngx_http_request_empty_handler(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http request empty handler");

    return;
}


// 发送特殊的控制标志，如last_buf/flush
// flags使用NGX_HTTP_LAST/NGX_HTTP_FLUSH
ngx_int_t
ngx_http_send_special(ngx_http_request_t *r, ngx_uint_t flags)
{
    ngx_buf_t    *b;
    ngx_chain_t   out;

    // 一个buffer对象
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    // buffer不关联实际的内存空间
    // 只设置控制标志位
    if (flags & NGX_HTTP_LAST) {

        if (r == r->main && !r->post_action) {
            b->last_buf = 1;

        } else {
            b->sync = 1;
            b->last_in_chain = 1;
        }
    }

    if (flags & NGX_HTTP_FLUSH) {
        b->flush = 1;
    }

    out.buf = b;
    out.next = NULL;

    // 把buffer加入输出链，实现标志位控制
    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_post_action(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->post_action.data == NULL) {
        return NGX_DECLINED;
    }

    if (r->post_action && r->uri_changes == 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "post action: \"%V\"", &clcf->post_action);

    r->main->count--;

    r->http_version = NGX_HTTP_VERSION_9;
    r->header_only = 1;
    r->post_action = 1;

    r->read_event_handler = ngx_http_block_reading;

    if (clcf->post_action.data[0] == '/') {
        ngx_http_internal_redirect(r, &clcf->post_action, NULL);

    } else {
        ngx_http_named_location(r, &clcf->post_action);
    }

    return NGX_OK;
}


// 尝试关闭请求，引用计数减1，表示本操作完成
// 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
// 不能关闭，直接返回
// 引用计数为0，没有任何操作了，可以安全关闭
// 释放请求相关的资源，调用cleanup链表，相当于析构
// 此时请求已经结束，调用log模块记录日志
// 销毁请求的内存池
// 调用ngx_close_connection,释放连接，加入空闲链表，可以再次使用
// 最后销毁连接的内存池
static void
ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    // 引用计数至少为1，表示有一个操作，否则就是严重错误
    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    // 减少引用计数，本次操作结束
    r->count--;

    // 如果还有引用计数，意味着此请求还有关联的epoll事件未完成
    // 不能关闭，直接返回
    // blocked表示有线程操作正在阻塞，也不能关闭
    // blocked必须有线程eventhandler处理
    if (r->count || r->blocked) {
        return;
    }

    // 引用计数为0，没有任何操作了，可以安全关闭

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    // 释放请求相关的资源，调用cleanup链表，相当于析构
    // 此时请求已经结束，调用log模块记录日志
    // 销毁请求的内存池
    // 但连接的内存池还在，可以用于长连接继续使用
    ngx_http_free_request(r, rc);

    // 调用ngx_close_connection
    // 释放连接，加入空闲链表，可以再次使用
    // 销毁连接的内存池
    ngx_http_close_connection(c);
}


// 释放请求相关的资源，调用cleanup链表，相当于析构
// 此时请求已经结束，调用log模块记录日志
// 销毁请求的内存池
// 但连接的内存池还在，可以用于长连接继续使用
void
ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_t                 *log;
    ngx_pool_t                *pool;
    struct linger              linger;
    ngx_http_cleanup_t        *cln;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");

    // r->pool就是请求的内存池，也当做是请求释放的标志
    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "http request already closed");
        return;
    }

    // 释放请求相关的资源，调用cleanup链表，相当于析构
    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

#if (NGX_STAT_STUB)

    if (r->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }

#endif

    // rc > 0 是http状态码
    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    if (!r->logged) {
        log->action = "logging request";

        // 此时请求已经结束，调用log模块记录日志
        ngx_http_log_request(r);
    }

    log->action = "closing request";

    if (r->connection->timedout) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various request strings were allocated from r->pool */
    ctx = log->data;
    ctx->request = NULL;

    r->request_line.len = 0;

    r->connection->destroyed = 1;

    /*
     * Setting r->pool to NULL will increase probability to catch double close
     * of request since the request object is allocated from its own pool.
     */

    // 销毁请求的内存池
    // 但连接的内存池还在，可以用于长连接继续使用
    pool = r->pool;
    r->pool = NULL;

    ngx_destroy_pool(pool);
}


// 请求已经结束，调用log模块记录日志
// 在ngx_http_free_request里调用
// log handler不在引擎数组里
// 不检查handler的返回值，直接调用，不使用checker
static void
ngx_http_log_request(ngx_http_request_t *r)
{
    ngx_uint_t                  i, n;
    ngx_http_handler_pt        *log_handler;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    // log handler不在引擎数组里
    log_handler = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.nelts;

    // 不检查handler的返回值，直接调用，不使用checker
    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


// 调用ngx_close_connection
// 释放连接，加入空闲链表，可以再次使用
// 销毁连接的内存池
void
ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    // 关闭连接，删除epoll里的读写事件
    // 释放连接，加入空闲链表，可以再次使用
    ngx_close_connection(c);

    // 关闭连接，销毁连接的内存池
    ngx_destroy_pool(pool);
}


// 记录错误日志时由log对象调用的函数，增加http请求的专有信息
static u_char *
ngx_http_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_http_request_t  *r;
    ngx_http_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", &ctx->connection->addr_text);
    len -= p - buf;

    r = ctx->request;

    if (r) {
        return r->log_handler(r, ctx->current_request, p, len);

    } else {
        p = ngx_snprintf(p, len, ", server: %V",
                         &ctx->connection->listening->addr_text);
    }

    return p;
}


// 在记录错误日志时回调
static u_char *
ngx_http_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    char                      *uri_separator;
    u_char                    *p;
    ngx_http_upstream_t       *u;
    ngx_http_core_srv_conf_t  *cscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    p = ngx_snprintf(buf, len, ", server: %V", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = ngx_snprintf(buf, len, ", request: \"%V\"", &r->request_line);
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, ", subrequest: \"%V\"", &sr->uri);
        len -= p - buf;
        buf = p;
    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, ", upstream: \"%V%V%s%V\"",
                         &u->schema, u->peer.name,
                         uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, ", host: \"%V\"",
                         &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, ", referrer: \"%V\"",
                         &r->headers_in.referer->value);
        buf = p;
    }

    return buf;
}
