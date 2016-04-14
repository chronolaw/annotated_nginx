// annotated by chrono since 2016

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>


static u_char *ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len);

// 创建ctx数组，用于存储模块的ctx数据
// 调用handler，处理tcp数据，收发等等
static void ngx_stream_init_session(ngx_connection_t *c);

#if (NGX_STREAM_SSL)
static void ngx_stream_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_stream_ssl_handshake_handler(ngx_connection_t *c);
#endif


// 在ngx_stream_optimize_servers里设置有连接发生时的回调函数
// 创建一个处理tcp的会话对象
// 要先检查限速和访问限制这两个功能模块
// 最后调用ngx_stream_init_session
// 创建ctx数组，用于存储模块的ctx数据
// 调用handler，处理tcp数据，收发等等
void
ngx_stream_init_connection(ngx_connection_t *c)
{
    int                           tcp_nodelay;
    u_char                        text[NGX_SOCKADDR_STRLEN];
    size_t                        len;
    ngx_int_t                     rc;
    ngx_uint_t                    i;
    struct sockaddr              *sa;
    ngx_stream_port_t            *port;
    struct sockaddr_in           *sin;
    ngx_stream_in_addr_t         *addr;
    ngx_stream_session_t         *s;
    ngx_stream_addr_conf_t       *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
    ngx_stream_in6_addr_t        *addr6;
#endif
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_core_main_conf_t  *cmcf;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_stream_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    // 创建一个处理tcp的会话对象
    s = ngx_pcalloc(c->pool, sizeof(ngx_stream_session_t));
    if (s == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    // 设置会话对象的标志
    s->signature = NGX_STREAM_MODULE;

    //设置会话正确的配置结构体
    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    // 设置会话关联的连接对象
    s->connection = c;

    // 连接的data指针指向会话对象
    c->data = s;

    // 获取相关的core配置
    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    ngx_set_connection_log(c, cscf->error_log);

    len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%uA client %*s connected to %V",
                  c->number, len, text, &addr_conf->addr_text);

    // log的一些参数
    c->log->connection = c->number;
    c->log->handler = ngx_stream_log_error;
    c->log->data = s;
    c->log->action = "initializing connection";
    c->log_error = NGX_ERROR_INFO;

    // 一个stream{}块只能有一个main conf
    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    // 是否有连接限速设置，在ngx_stream_limit_conn_module.c里设置
    if (cmcf->limit_conn_handler) {
        rc = cmcf->limit_conn_handler(s);

        if (rc != NGX_DECLINED) {
            ngx_stream_close_connection(c);
            return;
        }
    }

    // 是否有访问限制
    if (cmcf->access_handler) {
        rc = cmcf->access_handler(s);

        if (rc != NGX_OK && rc != NGX_DECLINED) {
            ngx_stream_close_connection(c);
            return;
        }
    }

    // 设置TCP_NODELAY，默认启用
    if (cscf->tcp_nodelay && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "tcp_nodelay");

        tcp_nodelay = 1;

        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            ngx_connection_error(c, ngx_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");
            ngx_stream_close_connection(c);
            return;
        }

        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }


#if (NGX_STREAM_SSL)
    {
    ngx_stream_ssl_conf_t  *sslcf;

    sslcf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_module);

    if (addr_conf->ssl) {
        c->log->action = "SSL handshaking";

        if (sslcf->ssl.ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no \"ssl_certificate\" is defined "
                          "in server listening on SSL port");
            ngx_stream_close_connection(c);
            return;
        }

        ngx_stream_ssl_init_connection(&sslcf->ssl, c);
        return;
    }
    }
#endif

    ngx_stream_init_session(c);
}


// 创建ctx数组，用于存储模块的ctx数据
// 调用handler，处理tcp数据，收发等等
static void
ngx_stream_init_session(ngx_connection_t *c)
{
    ngx_stream_session_t        *s;
    ngx_stream_core_srv_conf_t  *cscf;

    // 获得连接关联的会话对象
    s = c->data;
    c->log->action = "handling client connection";

    // 获取ngx_stream_core_module的配置
    // 只与每个server{}块相关的专门配置
    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    // 创建ctx数组，用于存储模块的ctx数据
    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_stream_max_module);
    if (s->ctx == NULL) {
        ngx_stream_close_connection(c);
        return;
    }

    // 调用handler，处理tcp数据，收发等等
    cscf->handler(s);
}


#if (NGX_STREAM_SSL)

static void
ngx_stream_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c)
{
    ngx_stream_session_t   *s;
    ngx_stream_ssl_conf_t  *sslcf;

    if (ngx_ssl_create_connection(ssl, c, 0) == NGX_ERROR) {
        ngx_stream_close_connection(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {

        s = c->data;

        sslcf = ngx_stream_get_module_srv_conf(s, ngx_stream_ssl_module);

        ngx_add_timer(c->read, sslcf->handshake_timeout);

        c->ssl->handler = ngx_stream_ssl_handshake_handler;

        return;
    }

    ngx_stream_ssl_handshake_handler(c);
}


static void
ngx_stream_ssl_handshake_handler(ngx_connection_t *c)
{
    if (!c->ssl->handshaked) {
        ngx_stream_close_connection(c);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_stream_init_session(c);
}

#endif


// 关闭stream连接，销毁线程池
void
ngx_stream_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "close stream connection: %d", c->fd);

#if (NGX_STREAM_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_stream_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    // 暂时保留内存池
    pool = c->pool;

    // 关闭连接
    ngx_close_connection(c);

    // 最后再销毁内存池
    ngx_destroy_pool(pool);
}


static u_char *
ngx_stream_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                *p;
    ngx_stream_session_t  *s;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = ngx_snprintf(buf, len, ", client: %V, server: %V",
                     &s->connection->addr_text,
                     &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->log_handler) {
        p = s->log_handler(log, buf, len);
    }

    return p;
}
