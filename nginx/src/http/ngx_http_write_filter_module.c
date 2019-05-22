// annotated by chrono since 2016
//
// * ngx_http_write_filter

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 初始化body过滤链表头节点，保证链表末尾不是空指针
// 此时头节点是ngx_http_write_filter
static ngx_int_t ngx_http_write_filter_init(ngx_conf_t *cf);


// 函数表里只有一个init函数，初始化链表指针
static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


// 没有其他配置相关的信息
ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 真正的向客户端发送数据，调用send_chain
// 也由ngx_http_set_write_handler设置epoll的写事件触发
// 如果数据发送不完，就保存在r->out里，返回again
// 需要再次发生可写事件才能发送
// 不是last、flush，且数据量较小（默认1460）
// 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
// 在此函数里处理限速
ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    ngx_uint_t                 last, flush, sync;
    ngx_msec_t                 delay;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    // 获取连接对象
    c = r->connection;

    // 如果连接有错误就不能发送数据
    if (c->error) {
        return NGX_ERROR;
    }

    // 数据的长度，
    size = 0;

    // 是否flush的标志
    flush = 0;

    // 是否sync的标志
    sync = 0;

    // 是否是最后一块数据，即数据全部发送完毕
    last = 0;

    // 请求里存储的待发送的数据链表
    // 可能是之前因为again而未能发送出去
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    // 先遍历当前请求里待发送的数据链表，计算长度
    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        // 缓冲区0长度，但不是flush、sync等控制用缓冲区，报错
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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
            return NGX_ERROR;
        }

        if (ngx_buf_size(cl->buf) < 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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
            return NGX_ERROR;
        }

        // 累计数据长度
        size += ngx_buf_size(cl->buf);

        // flush标志
        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        // sync标志
        if (cl->buf->sync) {
            sync = 1;
        }

        // 发送结束的标志
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    // 遍历新的数据链表，计算长度
    // 把in链表里的数据挂到r->out链表后面
    for (ln = in; ln; ln = ln->next) {

        // 分配一个新的链表节点
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        // 拷贝缓冲区，然后挂到out后面
        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        // 缓冲区0长度，但不是flush、sync等控制用缓冲区，报错
        if (ngx_buf_size(cl->buf) == 0 && !ngx_buf_special(cl->buf)) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
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
            return NGX_ERROR;
        }

        if (ngx_buf_size(cl->buf) < 0) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
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
            return NGX_ERROR;
        }

        // 累计数据长度
        size += ngx_buf_size(cl->buf);

        // flush标志
        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        // sync标志
        if (cl->buf->sync) {
            sync = 1;
        }

        // 发送结束的标志
        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    // 链表的最后节点，必须设置为空指针
    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    // 不是last、flush，且数据量较小（默认1460）
    // 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

    // flush，用户要求立即发送
    // last，所有的数据都集齐了，之后不会有新数据
    // size > postpone_output，数据已经积累的足够多，应该发送了

    // delayed表示需要限速，那么就暂不发送
    if (c->write->delayed) {
        // 置标志位，表示连接有数据缓冲待发送
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    // 数据长度为0
    if (size == 0
        && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        // 释放r->out里的节点
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    // 处理限速，不研究
    if (!r->limit_rate_set) {
        r->limit_rate = ngx_http_complex_value_size(r, clcf->limit_rate, 0);
        r->limit_rate_set = 1;
    }

    if (r->limit_rate) {

        if (!r->limit_rate_after_set) {
            r->limit_rate_after = ngx_http_complex_value_size(r,
                                                    clcf->limit_rate_after, 0);
            r->limit_rate_after_set = 1;
        }

        limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (ngx_msec_t) (- limit * 1000 / r->limit_rate + 1);
            ngx_add_timer(c->write, delay);

            c->buffered |= NGX_HTTP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        // 不限速，使用配置的参数，默认是0，即不限制，尽量多发
        limit = clcf->sendfile_max_chunk;
    }

    // 已经发送的字节数
    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    // 调用send_chain发送out链表
    // 实际上调用的是ngx_writev_chain
    //
    // 发送limit长度（字节数）的数据
    // 如果事件not ready，即暂不可写，那么立即返回，无动作
    // 要求缓冲区必须在内存里，否则报错
    // 最后返回消费缓冲区之后的链表指针
    // 发送出错、遇到again、发送完毕，这三种情况函数结束
    // 返回的是最后发送到的链表节点指针
    chain = c->send_chain(c, r->out, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    // 处理限速，不研究
    if (r->limit_rate) {

        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (ngx_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    // 处理限速，不研究
    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    // 在out链表里把已经发送过的节点都回收，供以后复用
    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    // out指向新的位置
    r->out = chain;

    // 不是空指针，表明还有数据没发完
    if (chain) {
        // 置标志位，表示连接有数据缓冲待发送
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    // 已经发送完了
    // 清除缓冲标志位
    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    // NGX_LOWLEVEL_BUFFERED目前似乎在nginx里还没有用到
    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


// 初始化body过滤链表头节点，保证链表末尾不是空指针
// 此时头节点是ngx_http_write_filter
static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}
