// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 1.10 实现有小调整，代码逻辑流程更清晰
//
// nginx实际调用的接收数据函数 in ngx_recv.c
// 从连接里获取读事件，使用系统调用recv读数据
// 尽量多读数据
// 如果数据长度为0，说明流已经结束，ready=0,eof=1
// 如果recv返回-1，表示出错，再检查是否是NGX_EAGAIN
ssize_t
ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;

    rev = c->read;

// freebsd kqueue，不关注
#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    ngx_set_socket_errno(rev->kq_errno);

                    return ngx_connection_error(c, rev->kq_errno,
                               "kevent() reported about an closed connection");
                }

                return 0;

            } else {
                rev->ready = 0;
                return NGX_AGAIN;
            }
        }
    }

#endif

    // 1.11.x增加了对rev->available的检查
    // 如果!rev->available则不接收数据，直接返回NGX_AGAIN
#if (NGX_HAVE_EPOLLRDHUP)

    if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            rev->ready = 0;
            return NGX_AGAIN;
        }
    }

#endif

    do {
        // 使用系统调用recv读数据
        // <0 出错， =0 连接关闭， >0 接收到数据大小
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        // n == 0，客户端关闭了连接
        if (n == 0) {
            // 置ready=0
            rev->ready = 0;

            // 如果数据长度为0，说明流已经结束，即连接被关闭，eof=1
            rev->eof = 1;

// freebsd kqueue，不关注
#if (NGX_HAVE_KQUEUE)

            /*
             * on FreeBSD recv() may return 0 on closed socket
             * even if kqueue reported about available data
             */

            if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                rev->available = 0;
            }

#endif

            // 返回0，客户端关闭了连接
            return 0;
        }

        // n > 0， 成功从socket接收了一些数据
        if (n > 0) {

// freebsd kqueue，不关注
#if (NGX_HAVE_KQUEUE)

            if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

#if (NGX_HAVE_FIONREAD)

            if (rev->available >= 0) {
                rev->available -= n;

                /*
                 * negative rev->available means some additional bytes
                 * were received between kernel notification and recv(),
                 * and therefore ev->ready can be safely reset even for
                 * edge-triggered event methods
                 */

                if (rev->available < 0) {
                    rev->available = 0;
                    rev->ready = 0;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);

            } else if ((size_t) n == size) {

                if (ngx_socket_nread(c->fd, &rev->available) == -1) {
                    n = ngx_connection_error(c, ngx_socket_errno,
                                             ngx_socket_nread_n " failed");
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);
            }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

            if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
                && ngx_use_epoll_rdhup)
            {
                if ((size_t) n < size) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

            // 在epoll模块ngx_epoll_init里已经设置了全局变量ngx_event_flags
            // NGX_USE_CLEAR_EVENT|NGX_USE_GREEDY_EVENT|NGX_USE_EPOLL_EVENT

            if ((size_t) n < size
                && !(ngx_event_flags & NGX_USE_GREEDY_EVENT))
            {
                // linux epoll不会走到这里
                rev->ready = 0;
            }

            // 不修改ready，也就是ready=1
            // 返回读取的字节数，剩余的之后可以再次读取
            // 被外部函数反复调用
            return n;
        }

        // 如果recv返回-1，表示出错，

        err = ngx_socket_errno;

        // NGX_EAGAIN socket未准备好
        // NGX_EINTR 被信号中断
        // 都不算真正的错误，下次就可以读取到数据
        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "recv() not ready");

            // 返回again，外部函数可以再次尝试读取
            // 或者再次进入循环开始的代码，再调用recv接收数据
            n = NGX_AGAIN;

        } else {
            n = ngx_connection_error(c, err, "recv() failed");
            break;
        }

    // 通常在读取到数据时函数就返回了
    // 只有收到信号被中断才退出循环
    } while (err == NGX_EINTR);

    // 发生了again/intr之外的错误，socket出错，不能继续读了
    rev->ready = 0;

    // NGX_EAGAIN不算错误
    // 看看是否真正发生了错误
    if (n == NGX_ERROR) {
        rev->error = 1;
    }

    return n;
}
