// annotated by chrono since 2016
//
// * ngx_event_accept
// * ngx_event_recvmsg
// * ngx_trylock_accept_mutex
// * ngx_enable_accept_events
// * ngx_disable_accept_events

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 遍历监听端口列表，删除epoll监听连接事件，不接受请求
static ngx_int_t ngx_disable_accept_events(ngx_cycle_t *cycle, ngx_uint_t all);

// 发生了错误，关闭一个连接
static void ngx_close_accepted_connection(ngx_connection_t *c);

// 仅接受tcp连接
// ngx_event_process_init里设置接受连接的回调函数为ngx_event_accept，可以接受连接
// 监听端口上收到连接请求时的回调函数，即事件handler
// 从cycle的连接池里获取连接
// 关键操作 ls->handler(c);调用其他模块的业务handler
void
ngx_event_accept(ngx_event_t *ev)
{
    socklen_t          socklen;
    ngx_err_t          err;
    ngx_log_t         *log;
    ngx_uint_t         level;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_sockaddr_t     sa;
    ngx_listening_t   *ls;
    ngx_connection_t  *c, *lc;
    ngx_event_conf_t  *ecf;
#if (NGX_HAVE_ACCEPT4)
    static ngx_uint_t  use_accept4 = 1;
#endif

    // 事件已经超时
    if (ev->timedout) {
        // 遍历监听端口列表，重新加入epoll连接事件
        if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
            return;
        }

        // 保证监听不超时
        ev->timedout = 0;
    }

    // 得到event core模块的配置，检查是否接受多个连接
    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    // rtsig在nginx 1.9.x已经删除
    if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        // epoll是否允许尽可能接受多个请求
        // 这里的ev->available仅使用1个bit的内存空间
        ev->available = ecf->multi_accept;
    }

    // 事件的连接对象
    lc = ev->data;

    // 事件对应的监听端口对象
    // 这里是一个关键，连接->事件->监听端口
    // 决定了要进入stream还是http子系统
    ls = lc->listening;

    // 此时还没有数据可读
    ev->ready = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "accept on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        socklen = sizeof(ngx_sockaddr_t);

        // 调用accept接受连接，返回socket对象
        // accept4是linux的扩展功能，可以直接把连接的socket设置为非阻塞
#if (NGX_HAVE_ACCEPT4)
        if (use_accept4) {
            s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK);
        } else {
            s = accept(lc->fd, &sa.sockaddr, &socklen);
        }
#else
        s = accept(lc->fd, &sa.sockaddr, &socklen);
#endif

        // 接受连接出错
        if (s == (ngx_socket_t) -1) {
            err = ngx_socket_errno;

            // EAGAIN，此时已经没有新的连接，用于multi_accept
            if (err == NGX_EAGAIN) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
                               "accept() not ready");
                return;
            }

            level = NGX_LOG_ALERT;

            if (err == NGX_ECONNABORTED) {
                level = NGX_LOG_ERR;

            } else if (err == NGX_EMFILE || err == NGX_ENFILE) {
                level = NGX_LOG_CRIT;
            }

#if (NGX_HAVE_ACCEPT4)
            ngx_log_error(level, ev->log, err,
                          use_accept4 ? "accept4() failed" : "accept() failed");

            if (use_accept4 && err == NGX_ENOSYS) {
                use_accept4 = 0;
                ngx_inherited_nonblocking = 0;
                continue;
            }
#else
            ngx_log_error(level, ev->log, err, "accept() failed");
#endif

            if (err == NGX_ECONNABORTED) {
                if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                    ev->available--;
                }

                if (ev->available) {
                    continue;
                }
            }

            // 系统的文件句柄数用完了
            if (err == NGX_EMFILE || err == NGX_ENFILE) {
                // 遍历监听端口列表，删除epoll监听连接事件，不接受请求
                if (ngx_disable_accept_events((ngx_cycle_t *) ngx_cycle, 1)
                    != NGX_OK)
                {
                    return;
                }

                // 解锁负载均衡，允许其他进程接受请求
                if (ngx_use_accept_mutex) {
                    if (ngx_accept_mutex_held) {
                        ngx_shmtx_unlock(&ngx_accept_mutex);
                        ngx_accept_mutex_held = 0;
                    }

                    //未持有锁，暂时不接受请求
                    ngx_accept_disabled = 1;

                } else {
                    // 不使用负载均衡
                    // 等待一下，再次尝试接受请求
                    ngx_add_timer(ev, ecf->accept_mutex_delay);
                }
            }

            return;
        } // 接受连接出错

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

        // 此时accept返回了一个socket描述符s

        // ngx_accept_disabled是总连接数的1/8-空闲连接数
        // 也就是说空闲连接数小于总数的1/8,那么就暂时停止接受连接
        ngx_accept_disabled = ngx_cycle->connection_n / 8
                              - ngx_cycle->free_connection_n;

        // 从全局变量ngx_cycle里获取空闲链接，即free_connections链表
        c = ngx_get_connection(s, ev->log);

        // 如果没有空闲连接，那么关闭socket，无法处理请求
        if (c == NULL) {
            if (ngx_close_socket(s) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                              ngx_close_socket_n " failed");
            }

            return;
        }

        // 1.10连接对象里新的字段，表示连接类型是tcp
        c->type = SOCK_STREAM;

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

        // 创建连接使用的内存池
        // stream模块设置连接的内存池是256bytes，不可配置
        // http模块可以在ngx_http_core_srv_conf_t里配置
        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
            socklen = sizeof(ngx_sockaddr_t);
        }

        // 拷贝客户端sockaddr
        c->sockaddr = ngx_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        ngx_memcpy(c->sockaddr, &sa, socklen);

        // 连接使用一个新的日志对象
        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        /* set a blocking mode for iocp and non-blocking mode for others */

        // 设置socket为非阻塞
        // ngx_inherited_nonblocking => os/unix/ngx_posix_init.c
        // 如果linux支持accept4，那么ngx_inherited_nonblocking = true
        if (ngx_inherited_nonblocking) {

            // NGX_USE_IOCP_EVENT是win32的标志
            // 这段代码在linux里不会执行，也就是说无动作
            // 因为accept4已经设置了socket非阻塞
            if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
                if (ngx_blocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_blocking_n " failed");
                    ngx_close_accepted_connection(c);
                    return;
                }
            }

        } else {
            // 如果linux不支持accept4，需要设置为非阻塞
            if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
                if (ngx_nonblocking(s) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_socket_errno,
                                  ngx_nonblocking_n " failed");
                    ngx_close_accepted_connection(c);
                    return;
                }
            }
        }

        // 从监听端口拷贝
        *log = ls->log;

        // 连接的收发数据函数
        // #define ngx_recv             ngx_io.recv
        // #define ngx_recv_chain       ngx_io.recv_chain
        // ngx_posix_init.c里初始化为linux的底层接口
        c->recv = ngx_recv;
        c->send = ngx_send;
        c->recv_chain = ngx_recv_chain;
        c->send_chain = ngx_send_chain;

        c->log = log;
        c->pool->log = log;

        // 设置其他的成员
        c->socklen = socklen;
        c->listening = ls;
        c->local_sockaddr = ls->sockaddr;
        c->local_socklen = ls->socklen;

#if (NGX_HAVE_UNIX_DOMAIN)
        if (c->sockaddr->sa_family == AF_UNIX) {
            c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
            c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
#if (NGX_SOLARIS)
            /* Solaris's sendfilev() supports AF_NCA, AF_INET, and AF_INET6 */
            c->sendfile = 0;
#endif
        }
#endif

        // 连接相关的读写事件
        rev = c->read;
        wev = c->write;

        // 建立连接后是可写的
        wev->ready = 1;

        // rtsig在nginx 1.9.x已经删除
        // linux里这段代码不执行
        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            rev->ready = 1;
        }

        // 如果listen使用了deferred，那么建立连接时就已经有数据可读了
        // 否则需要自己再加读事件，当有数据来时才能读取
        if (ev->deferred_accept) {
            rev->ready = 1;
#if (NGX_HAVE_KQUEUE || NGX_HAVE_EPOLLRDHUP)
            rev->available = 1;
#endif
        }

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        // 连接计数器增加
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

        if (ls->addr_ntop) {
            c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {
        ngx_str_t  addr;
        u_char     text[NGX_SOCKADDR_STRLEN];

        ngx_debug_accepted_connection(ecf, c);

        if (log->log_level & NGX_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
                                     NGX_SOCKADDR_STRLEN, 1);

            ngx_log_debug3(NGX_LOG_DEBUG_EVENT, log, 0,
                           "*%uA accept: %V fd:%d", c->number, &addr, s);
        }

        }
#endif

        // 如果事件机制不是epoll
        // 连接的读写事件都加入监控，即有读写都会由select/poll/kqueue等收集事件并处理
        if (ngx_add_conn && (ngx_event_flags & NGX_USE_EPOLL_EVENT) == 0) {
            if (ngx_add_conn(c) == NGX_ERROR) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

        // 在linux上通常都使用epoll，所以上面的if代码不会执行
        // 需要在后续的处理流程中自己控制读写事件的监控时机

        log->data = NULL;
        log->handler = NULL;

        // 接受连接，收到请求的回调函数
        // 在http模块里是http.c:ngx_http_init_connection
        // stream模块里是ngx_stream_init_connection
        ls->handler(c);

        // epoll不处理
        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available--;
        }

    // 如果ev->available = ecf->multi_accept;
    // epoll尽可能接受多个请求，直至accept出错EAGAIN，即无新连接请求
    // 否则epoll只接受一个请求后即退出循环
    } while (ev->available);
}


// 1.15.0 udp移动到新的ngx_event_udp.c
#if 0

// 仅支持unix
#if !(NGX_WIN32)

// 1.10新增函数，接受udp连接的handler
// 流程类似ngx_event_accept
void
ngx_event_recvmsg(ngx_event_t *ev)
{
    ssize_t            n;
    ngx_log_t         *log;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    struct iovec       iov[1];
    struct msghdr      msg;
    ngx_sockaddr_t     sa;
    ngx_listening_t   *ls;
    ngx_event_conf_t  *ecf;
    ngx_connection_t  *c, *lc;
    static u_char      buffer[65535];

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

#if (NGX_HAVE_IP_RECVDSTADDR)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_addr))];
#elif (NGX_HAVE_IP_PKTINFO)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    u_char             msg_control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif

#endif

    // 事件已经超时
    if (ev->timedout) {
        // 遍历监听端口列表，重新加入epoll连接事件
        if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
            return;
        }

        ev->timedout = 0;
    }

    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        ev->available = ecf->multi_accept;
    }

    // 事件的连接对象
    lc = ev->data;

    // 事件对应的监听端口对象
    ls = lc->listening;

    // 此时还没有数据可读
    ev->ready = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

    do {
        // 清空msghdr结构体，准备读取数据
        ngx_memzero(&msg, sizeof(struct msghdr));

        // 设置接收数据的缓冲区
        // 大小是65535字节
        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        // 客户端的地址
        msg.msg_name = &sa;

        // 设置接收数据的缓冲区
        msg.msg_namelen = sizeof(ngx_sockaddr_t);

        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {

#if (NGX_HAVE_IP_RECVDSTADDR || NGX_HAVE_IP_PKTINFO)
            if (ls->sockaddr->sa_family == AF_INET) {
                msg.msg_control = &msg_control;
                msg.msg_controllen = sizeof(msg_control);
            }
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
            if (ls->sockaddr->sa_family == AF_INET6) {
                msg.msg_control = &msg_control6;
                msg.msg_controllen = sizeof(msg_control6);
            }
#endif
        }

#endif

        // 接收udp数据
        n = recvmsg(lc->fd, &msg, 0);

        // 调用失败直接返回
        if (n == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
                               "recvmsg() not ready");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "recvmsg() failed");

            return;
        }

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "recvmsg() truncated data");
            continue;
        }
#endif

        // 负载均衡的阈值
        ngx_accept_disabled = ngx_cycle->connection_n / 8
                              - ngx_cycle->free_connection_n;

        // 接收数据成功，从连接池里获取一个新的连接
        c = ngx_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        // ？？？
        c->shared = 1;

        // udp类型的连接
        c->type = SOCK_DGRAM;
        c->socklen = msg.msg_namelen;

        if (c->socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
            c->socklen = sizeof(ngx_sockaddr_t);
        }

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

        // 为连接创建内存池
        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        c->sockaddr = ngx_palloc(c->pool, c->socklen);
        if (c->sockaddr == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        // 从msghdr里拷贝地址
        ngx_memcpy(c->sockaddr, msg.msg_name, c->socklen);

        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        *log = ls->log;

        // udp发送函数
        c->send = ngx_udp_send;
        c->send_chain = ngx_udp_send_chain;

        c->log = log;
        c->pool->log = log;

        // 监听端口
        // c->listening里包含了server配置等关键信息
        // 决定了如何处理这个连接
        c->listening = ls;

        // 服务器地址
        c->local_sockaddr = ls->sockaddr;
        c->local_socklen = ls->socklen;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {
            struct cmsghdr   *cmsg;
            struct sockaddr  *sockaddr;

            sockaddr = ngx_palloc(c->pool, c->local_socklen);
            if (sockaddr == NULL) {
                ngx_close_accepted_connection(c);
                return;
            }

            ngx_memcpy(sockaddr, c->local_sockaddr, c->local_socklen);
            c->local_sockaddr = sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {

#if (NGX_HAVE_IP_RECVDSTADDR)

                if (cmsg->cmsg_level == IPPROTO_IP
                    && cmsg->cmsg_type == IP_RECVDSTADDR
                    && sockaddr->sa_family == AF_INET)
                {
                    struct in_addr      *addr;
                    struct sockaddr_in  *sin;

                    addr = (struct in_addr *) CMSG_DATA(cmsg);
                    sin = (struct sockaddr_in *) sockaddr;
                    sin->sin_addr = *addr;

                    break;
                }

#elif (NGX_HAVE_IP_PKTINFO)

                if (cmsg->cmsg_level == IPPROTO_IP
                    && cmsg->cmsg_type == IP_PKTINFO
                    && sockaddr->sa_family == AF_INET)
                {
                    struct in_pktinfo   *pkt;
                    struct sockaddr_in  *sin;

                    pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
                    sin = (struct sockaddr_in *) sockaddr;
                    sin->sin_addr = pkt->ipi_addr;

                    break;
                }

#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)

                if (cmsg->cmsg_level == IPPROTO_IPV6
                    && cmsg->cmsg_type == IPV6_PKTINFO
                    && sockaddr->sa_family == AF_INET6)
                {
                    struct in6_pktinfo   *pkt6;
                    struct sockaddr_in6  *sin6;

                    pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
                    sin6 = (struct sockaddr_in6 *) sockaddr;
                    sin6->sin6_addr = pkt6->ipi6_addr;

                    break;
                }

#endif

            }
        }

#endif

        // 创建连接用的缓冲区
        c->buffer = ngx_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            ngx_close_accepted_connection(c);
            return;
        }

        // 把之前收到的数据拷贝到连接里的缓冲区
        // 注意这里，有数据拷贝的成本
        c->buffer->last = ngx_cpymem(c->buffer->last, buffer, n);

        // 设置读写事件
        rev = c->read;
        wev = c->write;

        wev->ready = 1;

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        // 连接计数增加
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

        // 拷贝客户端地址字符串
        if (ls->addr_ntop) {
            c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_close_accepted_connection(c);
                return;
            }

            c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                ngx_close_accepted_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {
        ngx_str_t  addr;
        u_char     text[NGX_SOCKADDR_STRLEN];

        ngx_debug_accepted_connection(ecf, c);

        if (log->log_level & NGX_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
                                     NGX_SOCKADDR_STRLEN, 1);

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                           "*%uA recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        log->data = NULL;
        log->handler = NULL;

        // 接受连接，收到请求的回调函数
        // stream模块里是ngx_stream_init_connection
        ls->handler(c);

        // epoll不处理
        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    // 如果ev->available = ecf->multi_accept;
    // epoll尽可能接受多个请求，直至accept出错EAGAIN，即无新连接请求
    // 否则epoll只接受一个请求后即退出循环
    } while (ev->available);
}

#endif

#endif // if 0

// 尝试获取负载均衡锁，监听端口
// 如未获取则不监听端口
// 锁标志ngx_accept_mutex_held
// 内部调用ngx_enable_accept_events/ngx_disable_accept_events
// 在ngx_event.c:ngx_process_events_and_timers里被调用
ngx_int_t
ngx_trylock_accept_mutex(ngx_cycle_t *cycle)
{
    // 尝试锁定共享内存锁
    // 非阻塞，会立即返回
    if (ngx_shmtx_trylock(&ngx_accept_mutex)) {

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "accept mutex locked");

        // 锁成功

        // 之前已经持有了锁，那么就直接返回，继续监听端口
        // ngx_accept_events在epoll里不使用
        // rtsig在nginx 1.9.x已经删除
        if (ngx_accept_mutex_held && ngx_accept_events == 0) {
            return NGX_OK;
        }

        // 之前没有持有锁，需要注册epoll事件监听端口

        // 遍历监听端口列表，加入epoll连接事件，开始接受请求
        if (ngx_enable_accept_events(cycle) == NGX_ERROR) {

            // 如果监听失败就需要立即解锁，函数结束
            ngx_shmtx_unlock(&ngx_accept_mutex);
            return NGX_ERROR;
        }

        // 已经成功将监听事件加入epoll

        // 设置已经获得锁的标志
        ngx_accept_events = 0;
        ngx_accept_mutex_held = 1;

        return NGX_OK;
    }

    // try失败，未获得锁，极小的消耗

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "accept mutex lock failed: %ui", ngx_accept_mutex_held);

    // 未获得锁
    // 但之前持有锁，也就是说之前在监听端口
    if (ngx_accept_mutex_held) {
        // 遍历监听端口列表，删除epoll监听连接事件，不接受请求
        if (ngx_disable_accept_events(cycle, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

        // 设置未获得锁的标志
        ngx_accept_mutex_held = 0;
    }

    return NGX_OK;
}


// 遍历监听端口列表，加入epoll连接事件，开始接受请求
ngx_int_t
ngx_enable_accept_events(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    // 遍历监听端口列表
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        // 如果连接已经监听（读事件激活）那么就跳过
        // rtsig在nginx 1.9.x已经删除
        if (c == NULL || c->read->active) {
            continue;
        }

        // #define ngx_add_event        ngx_event_actions.add
        // 加入读事件，即接受连接事件
        if (ngx_add_event(c->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


// 遍历监听端口列表，删除epoll监听连接事件，不接受请求
static ngx_int_t
ngx_disable_accept_events(ngx_cycle_t *cycle, ngx_uint_t all)
{
    ngx_uint_t         i;
    ngx_listening_t   *ls;
    ngx_connection_t  *c;

    // 遍历监听端口列表
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        c = ls[i].connection;

        // 如果连接没有监听（读事件不激活）那么就跳过
        // rtsig在nginx 1.9.x已经删除
        if (c == NULL || !c->read->active) {
            continue;
        }

#if (NGX_HAVE_REUSEPORT)

        /*
         * do not disable accept on worker's own sockets
         * when disabling accept events due to accept mutex
         */

        if (ls[i].reuseport && !all) {
            continue;
        }

#endif
        // 删除读事件，即不接受连接事件
        // NGX_DISABLE_EVENT暂时无用
        if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_DISABLE_EVENT)
            == NGX_ERROR)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


// 发生了错误，关闭一个连接
static void
ngx_close_accepted_connection(ngx_connection_t *c)
{
    ngx_socket_t  fd;

    // 释放连接，加入空闲链表
    // in core/ngx_connection.c
    ngx_free_connection(c);

    // 连接的描述符置为无效
    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    // 关闭socket
    if (ngx_close_socket(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    // 释放连接相关的所有内存
    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif
}


u_char *
ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    return ngx_snprintf(buf, len, " while accepting new connection on %V",
                        log->data);
}


#if (NGX_DEBUG)

void
ngx_debug_accepted_connection(ngx_event_conf_t *ecf, ngx_connection_t *c)
{
    struct sockaddr_in   *sin;
    ngx_cidr_t           *cidr;
    ngx_uint_t            i;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
    ngx_uint_t            n;
#endif

    cidr = ecf->debug_connection.elts;
    for (i = 0; i < ecf->debug_connection.nelts; i++) {
        if (cidr[i].family != (ngx_uint_t) c->sockaddr->sa_family) {
            goto next;
        }

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) c->sockaddr;
            for (n = 0; n < 16; n++) {
                if ((sin6->sin6_addr.s6_addr[n]
                    & cidr[i].u.in6.mask.s6_addr[n])
                    != cidr[i].u.in6.addr.s6_addr[n])
                {
                    goto next;
                }
            }
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->sockaddr;
            if ((sin->sin_addr.s_addr & cidr[i].u.in.mask)
                != cidr[i].u.in.addr)
            {
                goto next;
            }
            break;
        }

        c->log->log_level = NGX_LOG_DEBUG_CONNECTION|NGX_LOG_DEBUG_ALL;
        break;

    next:
        continue;
    }
}

#endif
