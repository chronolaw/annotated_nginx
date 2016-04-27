// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 发送limit长度（字节数）的数据
// limit有限制，但基本上可以说是无限大了
// 如果事件not ready，即暂不可写，那么立即返回，无动作
// 要求缓冲区必须在内存里，否则报错
// 最后返回消费缓冲区之后的链表指针
// 发送出错、遇到again、发送完毕，这三种情况函数结束
// 返回的是最后发送到的链表节点指针
ngx_chain_t *
ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ssize_t        n, sent;
    off_t          send, prev_send;
    ngx_chain_t   *cl;
    ngx_event_t   *wev;
    ngx_iovec_t    vec;
    struct iovec   iovs[NGX_IOVS_PREALLOCATE];

    // 从连接获取写事件
    wev = c->write;

    // 如果事件not ready，即暂不可写，那么立即返回，无动作
    if (!wev->ready) {
        return in;
    }

#if (NGX_HAVE_KQUEUE)

    if ((ngx_event_flags & NGX_USE_KQUEUE_EVENT) && wev->pending_eof) {
        (void) ngx_connection_error(c, wev->kq_errno,
                               "kevent() reported about an closed connection");
        wev->error = 1;
        return NGX_CHAIN_ERROR;
    }

#endif

    /* the maximum limit size is the maximum size_t value - the page size */

    // 由脚本生成，ngx_auto_config.h:#define NGX_MAX_SIZE_T_VALUE  9223372036854775807LL
    // limit有限制，但基本上可以说是无限大了
    if (limit == 0 || limit > (off_t) (NGX_MAX_SIZE_T_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_SIZE_T_VALUE - ngx_pagesize;
    }

    // 发送的字节数，初始化为0
    // 注意不是sent
    send = 0;

    // 设置iovs，指向函数内部的数组iovs，长度是NGX_IOVS_PREALLOCATE，通常是64
    vec.iovs = iovs;
    vec.nalloc = NGX_IOVS_PREALLOCATE;

    // 成功发送了limit字节，或者缓冲区链表已经结束
    // 内核发送缓冲区满，不能再发送
    // 那么发送结束
    for ( ;; ) {
        // 暂存之前发送的字节数
        prev_send = send;

        /* create the iovec and coalesce the neighbouring bufs */

        // 缓冲区链表转换为iovec结构体
        // 输出参数vec，存储iovec，输入参数in是nginx的缓冲区链表
        // limit，发送数据的限制长度
        // 要求缓冲区必须在内存里，否则报错
        // 最后返回消费缓冲区之后的链表指针
        cl = ngx_output_chain_to_iovec(&vec, in, limit - send, c->log);

        // 要求缓冲区必须在内存里，否则报错
        if (cl == NGX_CHAIN_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        // 要求缓冲区必须在内存里，否则报错
        if (cl && cl->buf->in_file) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "file buf in writev "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            ngx_debug_point();

            return NGX_CHAIN_ERROR;
        }

        // vec.size里存储的是在iovs里的总字节数
        // 增加发送的字节数
        send += vec.size;

        // 封装系统调用writev，发送多个内存块
        // again，暂时不可写，需要等待事件可写再重试，返回again
        // 被中断，需要立即重试，可能就成功了
        // 其他的就是错误
        n = ngx_writev(c, &vec);

        // 不可恢复的错误
        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        // 如果是again，发送失败，已发送字节不增加
        sent = (n == NGX_AGAIN) ? 0 : n;

        // 连接里的已发送字节数增加
        c->sent += sent;

        // 根据已经实际发送的字节数更新链表
        // 已经发送的缓冲区会清空
        // 最后返回处理之后的链表指针
        // 如果没有发送（again）就直接返回
        in = ngx_chain_update_sent(in, sent);

        // 两者相减，判断是否完全发送了数据
        // 不完全，只发送了部分，也就是说内核写缓冲区满，写不可用
        if (send - prev_send != sent) {
            // 暂时不可写，需要等待下次写事件发生才能写
            wev->ready = 0;
            return in;
        }

        // 成功发送了limit字节，或者缓冲区链表已经结束
        // 那么发送结束
        if (send >= limit || in == NULL) {
            return in;
        }

        // limit字节很多，这次没有发送完
        // 需要再从循环开头取数据发送
    }
}


// 缓冲区链表转换为iovec结构体
// 输出参数vec，存储iovec，输入参数in是nginx的缓冲区链表
// limit，发送数据的限制长度
// 要求缓冲区必须在内存里，否则报错
// 最后返回消费缓冲区之后的链表指针
ngx_chain_t *
ngx_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in, size_t limit,
    ngx_log_t *log)
{
    size_t         total, size;
    u_char        *prev;
    ngx_uint_t     n;
    struct iovec  *iov;

    // 指向vec里的某个元素
    iov = NULL;

    // 缓冲区的字节指针，由于优化
    prev = NULL;

    // 发送的总字节数
    total = 0;

    // vec里的数组序号
    n = 0;

    // 填满vec数组，或者字节数达到limit的限制
    // 每处理完一个缓冲区指针就后移
    for ( /* void */ ; in && total < limit; in = in->next) {

        // 忽略flush、sync、eof等控制用特殊缓冲区
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        // 不考虑磁盘文件
        if (in->buf->in_file) {
            break;
        }

        // 要求缓冲区必须在内存里，否则报错
        if (!ngx_buf_in_memory(in->buf)) {
            ngx_log_error(NGX_LOG_ALERT, log, 0,
                          "bad buf in output chain "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          in->buf->temporary,
                          in->buf->recycled,
                          in->buf->in_file,
                          in->buf->start,
                          in->buf->pos,
                          in->buf->last,
                          in->buf->file,
                          in->buf->file_pos,
                          in->buf->file_last);

            ngx_debug_point();

            return NGX_CHAIN_ERROR;
        }

        // 获得缓冲区内数据长度
        size = in->buf->last - in->buf->pos;

        // 如果当前缓冲区的大小超过了最后的限制，那么只发一部分
        if (size > limit - total) {
            size = limit - total;
        }

        // 这里是一种特殊情况，也可能很常见
        // 两个buf，它们实际上指向了一块连续的内存
        // 即buf1的last是buf2的pos
        // 所以nginx进行优化，不需要赋值，直接加上长度
        // 节约一个iov数组元素
        if (prev == in->buf->pos) {
            iov->iov_len += size;

        } else {
            // 不是连续的内存，就要使用一个iov结构体

            // vec里的数组已经填满了
            if (n == vec->nalloc) {
                break;
            }

            // iov指针指向vec里的第n个数组，然后n加1
            iov = &vec->iovs[n++];

            // iov结构里的数据指针和数据长度
            iov->iov_base = (void *) in->buf->pos;
            iov->iov_len = size;
        }

        // prev指针移动
        prev = in->buf->pos + size;

        // 总字节数增加，当大于等于limit时就结束循环
        total += size;
    }

    // 如果不连续的内存很多，那么n就是vec->nalloc
    // 如果limit比较小，那么n就小于vec->nalloc
    vec->count = n;

    // size是总字节数，受limit和n的限制
    // 不一定正好是limit
    vec->size = total;

    // 最后返回消费缓冲区之后的链表指针
    return in;
}


// 封装系统调用writev，发送多个内存块
// again，暂时不可写，需要等待事件可写再重试，返回again
// 被中断，需要立即重试，可能就成功了
// 其他的就是错误
ssize_t
ngx_writev(ngx_connection_t *c, ngx_iovec_t *vec)
{
    ssize_t    n;
    ngx_err_t  err;

// 这个goto标签可以改用for+continue来实现
// 即发生EINTR错误就重试发送数据
eintr:

    // 系统调用writev，发送多个内存块
    n = writev(c->fd, vec->iovs, vec->count);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "writev: %z of %uz", n, vec->size);

    // n < 0 出错，检查errno
    if (n == -1) {
        err = ngx_errno;

        switch (err) {
        // again，暂时不可写，需要等待事件可写再重试，返回again
        case NGX_EAGAIN:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "writev() not ready");
            return NGX_AGAIN;

        // 被中断，需要立即重试，可能就成功了
        case NGX_EINTR:
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "writev() was interrupted");
            goto eintr;

        // 其他的就是错误
        default:
            c->write->error = 1;
            ngx_connection_error(c, err, "writev() failed");
            return NGX_ERROR;
        }
    }

    return n;
}
