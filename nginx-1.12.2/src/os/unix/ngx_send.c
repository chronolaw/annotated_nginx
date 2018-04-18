// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// ngx_unix_send不区分linux/bsd
// 从连接里获取写事件，使用系统调用send发送数据
// 要求的数据没发送完，说明暂时不能发送，缓冲区可能满了
// 置ready标志，写事件暂时不可用，即不可写
ssize_t
ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *wev;

    // 连接里的写事件
    wev = c->write;

// freebsd kqueue不考虑
#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NGX_ERROR;
    }

#endif

    // 如果send被信号中断NGX_EINTR ，到循环开始继续尝试
    for ( ;; ) {
        // 使用系统调用send发送数据
        n = send(c->fd, buf, size, 0);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "send: fd:%d %z of %uz", c->fd, n, size);

        // 发送数据成功
        if (n > 0) {
            // 要求的数据没发送完，说明暂时不能发送，缓冲区可能满了
            if (n < (ssize_t) size) {
                // 置ready标志，写事件暂时不可用，即不可写
                wev->ready = 0;
            }

            // 连接上发送的字节数增加
            c->sent += n;

            return n;
        }

        // 发送数据失败
        err = ngx_socket_errno;

        // 完全没发送出去?
        if (n == 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, err, "send() returned zero");

            // 置ready标志，写事件暂时不可用，即不可写
            wev->ready = 0;

            // 发送了0个字节
            return n;
        }

        // NGX_EAGAIN socket未准备好
        // NGX_EINTR 被信号中断
        // 都不算真正的错误，下次就可以继续发送数据
        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            // 置ready标志，写事件暂时不可用，即不可写
            wev->ready = 0;

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "send() not ready");

            // NGX_EAGAIN socket未准备好，直接返回，等待下一次调用
            if (err == NGX_EAGAIN) {
                return NGX_AGAIN;
            }

        } else {
            // 其他的错误，是真正的发送错误
            wev->error = 1;
            (void) ngx_connection_error(c, err, "send() failed");
            return NGX_ERROR;
        }

        // NGX_EINTR 被信号中断，到循环开始继续尝试
    }   // for循环结束
}
