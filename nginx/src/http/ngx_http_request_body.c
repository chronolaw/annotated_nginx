// annotated by chrono since 2016
//
// * ngx_http_discard_request_body
// * ngx_http_read_discarded_request_body
// * ngx_http_discarded_request_body_handler
//
// * ngx_http_read_client_request_body
// * ngx_http_read_client_request_body_handler
// * ngx_http_do_read_client_request_body

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 读取请求体的handler
// 首先检查超时，实际功能在ngx_http_do_read_client_request_body
static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);

// 在rb->buf里读取数据
// 如果已经读完了所有剩余数据，那么就挂到bufs指针，结束函数
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);

// 请求体写入临时文件，不研究
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);

// 读取请求体数据并丢弃
// 使用固定的4k缓冲区接受丢弃的数据
// 一直读数据并解析，检查content_length_n,如果无数据可读就返回NGX_AGAIN
// 因为使用的是et模式，所以必须把数据读完
// 需要使用回调ngx_http_discarded_request_body_handler读取数据
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);

// 检查请求结构体里的缓冲区数据，丢弃
// 有content_length_n指定确切长度，那么只接收，不处理，移动缓冲区指针
// chunked数据需要解析数据
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r,
    ngx_buf_t *b);

static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

// 分为chunked和确定长度两种
// 简单起见只研究确定长度，即ngx_http_request_body_length_filter
static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

// 处理确定长度的请求体数据，参数in是已经读取的数据链表
// 先看free里是否有空闲节点，有则直接使用
// 如果没有，就从内存池的空闲链表里获取
// 创建新的链表节点，加入到out链表里
// 这里只是指针操作，没有内存拷贝
// 调用请求体过滤链表，对数据进行过滤处理
// 实际上是ngx_http_request_body_save_filter
// 拷贝in链表里的buf到rb->bufs里，不是直接连接
// 最后把用完的ngx_chaint_t挂到free里供复用，提高效率
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r,
    ngx_chain_t *in);


// 要求nginx读取请求体，传入一个post_handler
// 引用计数器增加，表示此请求还有关联的操作，不能直接销毁
// 所以post_handler里需要调用ngx_http_finalize_request来结束请求
ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    // 引用计数器增加，表示此请求还有关联的操作，不能直接销毁
    r->main->count++;

    // 删除了原spdy的代码
    // 子请求不与客户端直接通信，不会有请求体的读取
    // 已经设置了discard_body标志，表示已经开始丢弃请求体
    // request_body指针不空，表示已经开始读取请求体
    if (r != r->main || r->request_body || r->discard_body) {
        r->request_body_no_buffering = 0;

        // 不需要再读取数据了，直接回调handler
        // 相当于触发写事件，继续之前中断的处理流程
        post_handler(r);

        return NGX_OK;
    }

//#if (NGX_HTTP_V2)
//    if (r->stream) {
//        rc = ngx_http_v2_read_request_body(r, post_handler);
//        goto done;
//    }
//#endif
//
//    // 如果要求不缓存请求体数据
//    // 那么请求体就不会存在磁盘文件里
//    // if (r->request_body_no_buffering) {
//    //     r->request_body_in_file_only = 0;
//    // }

    if (ngx_http_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    // 创建请求体数据结构体
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     */

    // -1表示未初始化
    rb->rest = -1;

    // 当读取完毕后的回调函数
    // 即ngx_http_read_client_request_body的第二个参数
    rb->post_handler = post_handler;

    r->request_body = rb;

    // 数据长度不对，直接回调handler
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        r->request_body_no_buffering = 0;

        // 不需要再读取数据了，直接回调handler
        // 相当于触发写事件，继续之前中断的处理流程
        post_handler(r);
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_request_body(r);
        goto done;
    }
#endif

    // 查看已经读取的数据，即缓冲区里头之后的数据
    preread = r->header_in->last - r->header_in->pos;

    // 已经读取了部分body
    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        // 链表的第一个节点指向r->header_in
        out.buf = r->header_in;
        out.next = NULL;

        // 分为chunked和确定长度两种
        // 简单起见只研究确定长度，即ngx_http_request_body_length_filter
        //
        // 处理确定长度的请求体数据，参数是已经读取的数据链表
        // 先看free里是否有空闲节点，有则直接使用
        // 如果没有，就从内存池的空闲链表里获取
        // 这里只是指针操作，没有内存拷贝
        // 调用请求体过滤链表，对数据进行过滤处理
        // 实际上是ngx_http_request_body_save_filter
        // 拷贝in链表里的buf到rb->bufs里，不是直接连接
        // 最后把用完的ngx_chaint_t挂到free里供复用，提高效率
        rc = ngx_http_request_body_filter(r, &out);

        if (rc != NGX_OK) {
            goto done;
        }

        // 增加已经读取的数据长度，但因为
        // preread = r->header_in->last - r->header_in->pos;
        // 实际上是没有增加
        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        // 不是chunked，有确定长度
        // 还有剩余数据要读取
        // header_in缓冲区里还有空间，足够容纳rest字节的数据
        // 所以不需要再另外分配内存了,header_in缓冲区可以存下所有请求数据
        // 特别优化处理
        // 设置读事件handler为ngx_http_read_client_request_body_handler
        // 要求继续读取
        if (!r->headers_in.chunked
            && rb->rest > 0
            && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* the whole request body may be placed in r->header_in */

            // 创建一个缓冲区对象
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            // 指向header_in里的请求头后的所有空间
            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            // 请求体使用此缓冲区
            rb->buf = b;

            // 设置读事件handler为ngx_http_read_client_request_body_handler
            // 注意，读事件的handler实际上是ngx_http_request_handler
            // 但最终会调用r->read_event_handler

            // 读取请求体的handler
            // 首先检查超时，实际功能在ngx_http_do_read_client_request_body
            r->read_event_handler = ngx_http_read_client_request_body_handler;

            // 写事件阻塞
            r->write_event_handler = ngx_http_request_empty_handler;

            // 在rb->buf里读取数据
            // 如果已经读完了所有剩余数据，那么就挂到bufs指针，结束函数
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

        // 这里表示rest==0，一次就已经全部读取了header+body
        // 不需要再关心读事件
        // 走下面的if (rb->rest == 0)

    } else {
        /* set rb->rest */
        // 没有读取body数据

        // 分为chunked和确定长度两种
        // 简单起见只研究确定长度，即ngx_http_request_body_length_filter
        // 因为参数是null，所以函数里只会设置rb->rest，即剩余要读取的字节数
        if (ngx_http_request_body_filter(r, NULL) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }

        // 走下面的clcf = ngx_http_get_module_loc_conf
    }

    // rb->rest == 0 body已经读取完毕
    // preread >= content length
    if (rb->rest == 0) {
        /* the whole request body was pre-read */

        // body已经读取完毕，可以调用post_handler继续处理流程
        r->request_body_no_buffering = 0;
        post_handler(r);
        return NGX_OK;
    }

    // 错误，负数body
    if (rb->rest < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    // 没读到body数据，但知道了确定的body长度

    // 取模块的loc配置
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    // 查看body的缓冲区大小
    size = clcf->client_body_buffer_size;

    // 增加1/4的长度
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    // 长度确定，且在size里可以容纳剩余字节数
    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        // 要求body在一块缓冲区里，长度增加
        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    // 内存池里分配一个缓冲区，大小为size
    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    // 设置读事件handler为ngx_http_read_client_request_body_handler
    // 注意，读事件的handler实际上是ngx_http_request_handler
    // 但最终会调用r->read_event_handler

    // 读取请求体的handler
    // 首先检查超时，实际功能在ngx_http_do_read_client_request_body
    r->read_event_handler = ngx_http_read_client_request_body_handler;

    // 写事件阻塞
    r->write_event_handler = ngx_http_request_empty_handler;

    // 在rb->buf里读取数据
    // 如果已经读完了所有剩余数据，那么就挂到bufs指针，结束函数
    rc = ngx_http_do_read_client_request_body(r);

done:

    if (r->request_body_no_buffering
        && (rc == NGX_OK || rc == NGX_AGAIN))
    {
        if (rc == NGX_OK) {
            r->request_body_no_buffering = 0;

        } else {
            /* rc == NGX_AGAIN */
            r->reading_body = 1;
        }

        r->read_event_handler = ngx_http_block_reading;
        post_handler(r);
    }

    // 出错，减少引用计数
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }

    // 返回错误码
    return rc;
}


ngx_int_t
ngx_http_read_unbuffered_request_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

#if (NGX_HTTP_V2)
    if (r->stream) {
        rc = ngx_http_v2_read_unbuffered_request_body(r);

        if (rc == NGX_OK) {
            r->reading_body = 0;
        }

        return rc;
    }
#endif

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        return NGX_HTTP_REQUEST_TIME_OUT;
    }

    rc = ngx_http_do_read_client_request_body(r);

    if (rc == NGX_OK) {
        r->reading_body = 0;
    }

    return rc;
}


// 读取请求体的handler
// 首先检查超时，实际功能在ngx_http_do_read_client_request_body
static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    // 首先检查超时
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;

        // 读取body超时错误，返回408
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    // 实际功能在ngx_http_do_read_client_request_body
    rc = ngx_http_do_read_client_request_body(r);

    // 出错直接结束请求
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}


// 在rb->buf里读取数据
// 如果已经读完了所有剩余数据，那么就挂到bufs指针，结束函数
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_chain_t                out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    // 获取读事件相关的连接对象和请求对象
    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {

        // 在rb->buf里读取数据
        // 如果已经读完了所有剩余数据，那么就挂到bufs指针，结束函数
        for ( ;; ) {

            // 检查请求体结构里的缓冲区
            // 是否已经满了
            if (rb->buf->last == rb->buf->end) {

                if (rb->buf->pos != rb->buf->last) {

                    /* pass buffer to request body filter chain */

                    out.buf = rb->buf;
                    out.next = NULL;

                    rc = ngx_http_request_body_filter(r, &out);

                    if (rc != NGX_OK) {
                        return rc;
                    }

                } else {

                    /* update chains */

                    rc = ngx_http_request_body_filter(r, NULL);

                    if (rc != NGX_OK) {
                        return rc;
                    }
                }

                if (rb->busy != NULL) {
                    if (r->request_body_no_buffering) {
                        if (c->read->timer_set) {
                            ngx_del_timer(c->read);
                        }

                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        return NGX_AGAIN;
                    }

                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }   // if (rb->buf->last == rb->buf->end)

            // 缓冲区没有满，还可以存放数据

            // 计算剩余空间的大小
            size = rb->buf->end - rb->buf->last;

            // 减去缓冲区里已经读取的长度
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            // 计算实际应该读取的长度，两者的小值
            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            // 调用recv，读取数据，放入缓冲区
            // <0 出错， =0 连接关闭， >0 接收到数据大小
            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            // again，暂时无数据，中断内层循环
            if (n == NGX_AGAIN) {
                break;
            }

            // 读到了0字节，即连接被客户端关闭，client abort
            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            // 读到了0字节，即连接被客户端关闭，client abort
            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            // n>0，读取了一些数据

            // 调整buf的last指针，有效数据增加
            rb->buf->last += n;

            // 总请求数据长度增加
            r->request_length += n;

            // 已经读完了所有剩余数据
            if (n == rest) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                // 分为chunked和确定长度两种
                // 简单起见只研究确定长度，即ngx_http_request_body_length_filter
                //
                // 处理确定长度的请求体数据，参数是已经读取的数据链表
                // 先看free里是否有空闲节点，有则直接使用
                // 如果没有，就从内存池的空闲链表里获取
                // 这里只是指针操作，没有内存拷贝
                // 调用请求体过滤链表，对数据进行过滤处理
                // 实际上是ngx_http_request_body_save_filter
                // 拷贝in链表里的buf到rb->bufs里，不是直接连接
                // 最后把用完的ngx_chaint_t挂到free里供复用，提高效率
                rc = ngx_http_request_body_filter(r, &out);

                // 出错则结束函数
                if (rc != NGX_OK) {
                    return rc;
                }
            }

            // ngx_http_request_body_filter里计算了rest剩余字节数
            // 读取完毕则结束内层循环
            if (rb->rest == 0) {
                break;
            }

            // 缓冲区没有用完，也结束内层循环
            // 在后面调用ngx_http_request_body_filter处理读取到的数据
            if (rb->buf->last < rb->buf->end) {
                break;
            }

            // 回到内层循环开头，即缓冲区已满

        }   // 内层for

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

        // ngx_http_request_body_filter里计算了rest剩余字节数
        // 读取完毕则结束外层循环
        if (rb->rest == 0) {
            break;
        }

        // 还有数据要读，且已经无数据可读
        if (!c->read->ready) {

            if (r->request_body_no_buffering
                && rb->buf->pos != rb->buf->last)
            {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                // 分为chunked和确定长度两种
                // 简单起见只研究确定长度，即ngx_http_request_body_length_filter
                //
                // 处理确定长度的请求体数据，参数是已经读取的数据链表
                // 先看free里是否有空闲节点，有则直接使用
                // 如果没有，就从内存池的空闲链表里获取
                // 这里只是指针操作，没有内存拷贝
                // 调用请求体过滤链表，对数据进行过滤处理
                // 实际上是ngx_http_request_body_save_filter
                // 拷贝in链表里的buf到rb->bufs里，不是直接连接
                // 最后把用完的ngx_chaint_t挂到free里供复用，提高效率
                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            // 读取body的超时时间
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            // 读事件加入epoll，可读会调用ngx_http_read_client_request_body_handler
            // 即再次进入本函数
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }   // 外层for

    // 只有rest==0，即读取完毕才会走到这里

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    // 要求缓存请求体
    if (!r->request_body_no_buffering) {
        r->read_event_handler = ngx_http_block_reading;

        // body已经读取完毕，可以调用post_handler继续处理流程
        rb->post_handler(r);
    }

    return NGX_OK;
}


// 请求体写入临时文件，不研究
static ngx_int_t
ngx_http_write_request_body(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl, *ln;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (rb->bufs == NULL) {
            /* empty body with r->request_body_in_file_only */

            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    if (rb->bufs == NULL) {
        return NGX_OK;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; /* void */) {

        cl->buf->pos = cl->buf->last;

        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    rb->bufs = NULL;

    return NGX_OK;
}


// 要求nginx丢弃请求体数据
// 子请求不与客户端直接通信，不会有请求体的读取
// 已经设置了discard_body标志，表示已经调用了此函数
// request_body指针不空，表示已经调用了此函数
// 这三种情况就无需再启动读取handler，故直接返回成功
// 因为要丢弃数据，所以不需要检查超时，也就是说即使超时也不算是错误
// 如果头里的长度是0且不是chunked
// 说明没有请求体数据，那么就无需再读，直接返回成功
// *一直*读数据并解析，检查content_length_n,如果无数据可读就返回NGX_AGAIN
// 因为使用的是et模式，所以必须把数据读完
// 调用ngx_http_discard_request_body_filter检查收到的数据
// 使用回调ngx_http_discarded_request_body_handler读取数据
ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;

    // 子请求不与客户端直接通信，不会有请求体的读取
    // 已经设置了discard_body标志，表示已经调用了此函数
    // request_body指针不空，表示已经调用了此函数
    // 这三种情况就无需再启动读取handler，故直接返回成功
    // discard_body在本函数最末尾设置，防止重入
    if (r != r->main || r->discard_body || r->request_body) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NGX_OK;
    }
#endif

    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 从请求获取连接对象，再获得读事件
    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    // 因为要丢弃数据，所以不需要检查超时，也就是说即使超时也不算是错误
    // 不检查读事件的超时，有数据就读
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    // 如果头里的长度未设置、或者是0且不是chunked
    // 说明没有请求体数据，那么就无需再读，直接返回成功
    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }

    // 头里声明了body的数据长度
    // 或者body是chunked，即长度不确定
    // 这两种情况都需要读取数据并丢弃

    // 检查缓冲区里在解析完头后是否还有数据
    // 也就是说之前可能读取了部分请求体数据
    size = r->header_in->last - r->header_in->pos;

    // 有数据，或者是chunked数据
    // 有可能已经读取了一些请求体数据，所以先检查一下
    if (size || r->headers_in.chunked) {
        // 检查请求结构体里的缓冲区数据，丢弃
        // 有content_length_n指定确切长度，那么只接收，不处理，移动缓冲区指针
        // chunked数据需要解析数据
        rc = ngx_http_discard_request_body_filter(r, r->header_in);

        // 不是ok表示出错，不能再读取数据
        if (rc != NGX_OK) {
            return rc;
        }

        // content_length_n==0表示数据已经全部读完
        // 就已经完成了丢弃任务，否则就要加入epoll读事件继续读
        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }

    // 走到这里，表明content_length_n>=0，还有数据要读取
    // 接下来就读取请求体数据并丢弃
    // 使用固定的4k缓冲区接受丢弃的数据
    // 一直读数据并解析，检查content_length_n,如果无数据可读就返回NGX_AGAIN
    // 因为使用的是et模式，所以必须把数据读完
    // 需要使用回调ngx_http_discarded_request_body_handler读取数据
    rc = ngx_http_read_discarded_request_body(r);

    // ok表示一次就成功读取了全部的body，完成丢弃工作
    if (rc == NGX_OK) {
        r->lingering_close = 0;
        return NGX_OK;
    }

    // 出错
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NGX_AGAIN */

    // 读事件not ready，无数据可读，那么就要在epoll里加入读事件和handler
    // 注意，不再需要加入定时器
    // 之后再有数据来均由ngx_http_discarded_request_body_handler处理
    // 里面还是调用ngx_http_read_discarded_request_body读数据

    r->read_event_handler = ngx_http_discarded_request_body_handler;

    // 注意，读事件的handler实际上是ngx_http_request_handler
    // 但最终会调用r->read_event_handler
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 引用计数器增加，表示此请求还有关联的操作，不能直接销毁
    r->count++;

    // 设置丢弃标志，防止再次进入本函数
    r->discard_body = 1;

    return NGX_OK;
}


// 丢弃请求体读事件处理，在epoll里加入读事件和handler
// 这时epoll通知socket上有数据可以读取
// ngx_http_read_discarded_request_body ok表示数据已经读完
// 传递done给ngx_http_finalize_request，并不是真正结束请求
// 因为有引用计数器r->count，所以在ngx_http_close_request里只是减1的效果
void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    // 获取读事件相关的连接对象和请求对象
    c = r->connection;
    rev = c->read;

    // 检查超时，使用的是lingering_timeout
    // 普通的丢弃不会进入这里
    // 用在keepalive，见ngx_http_set_keepalive
    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    // 设置延时关闭时间，那么就会设置超时时间timer
    // 如果是一开始就丢弃请求体，那么就不会走这里， timer=0
    if (r->lingering_time) {

        // 计算当前事件，是否要关闭
        timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();

        // 延时关闭时间已到，不需要再接收数据了
        // 清除标志，调用ngx_http_finalize_request结束请求
        if ((ngx_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    // 这时epoll通知socket上有数据可以读取
    // 读取请求体数据并丢弃
    // 使用固定的4k缓冲区接受丢弃的数据
    // 一直读数据并解析，检查content_length_n,如果无数据可读就返回NGX_AGAIN
    rc = ngx_http_read_discarded_request_body(r);

    // ok表示数据已经读完
    // 传递done给ngx_http_finalize_request，并不是真正结束请求
    // 因为有引用计数器r->count，所以在ngx_http_close_request里只是减1的效果
    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    // 出错
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* rc == NGX_AGAIN */

    // again则需要再次加入epoll事件，等有数据来再次进入
    // rev的handler不变，直接加入
    // 注意，读事件的handler实际上是ngx_http_request_handler
    // 但最终会调用r->read_event_handler，即本函数
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    // 如果是一开始就丢弃请求体，那么就不会走这里， timer=0
    // 设置读事件的超时时间
    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        // 等待时间不能超过配置的lingering_timeout
        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        // 把读事件加入定时器红黑树，等待超时事件
        ngx_add_timer(rev, timer);
    }
}


// 读取请求体数据并丢弃
// 使用固定的4k缓冲区接受丢弃的数据
// 一直读数据并解析，检查content_length_n,如果无数据可读就返回NGX_AGAIN
// 因为使用的是et模式，所以必须把数据读完
// 需要使用回调ngx_http_discarded_request_body_handler读取数据
static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;

    // 使用固定的4k缓冲区接受丢弃的数据
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    // 读取用的缓冲区对象
    ngx_memzero(&b, sizeof(ngx_buf_t));

    // 标记为可写
    b.temporary = 1;

    // 一直读数据并解析，检查content_length_n
    // 如果无数据可读就返回NGX_AGAIN
    // 需要使用回调ngx_http_discarded_request_body_handler读取数据
    for ( ;; ) {

        // 判断content_length_n，为0就是已经读取完请求体
        // 就不需要再读了，读事件设置为block，返回成功
        if (r->headers_in.content_length_n == 0) {
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        // content_length_n大于0，表示还有数据需要读取
        // 看读事件是否ready，即是否有数据可读
        // 如果没数据那么就返回again
        // 需要使用回调ngx_http_discarded_request_body_handler读取数据
        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        // 决定要读取的数据长度，不能超过4k
        // #define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
        size = (size_t) ngx_min(r->headers_in.content_length_n,
                                NGX_HTTP_DISCARD_BUFFER_SIZE);

        // 调用底层recv读取数据
        // 每次都从buffer的0位置放置数据，也就是丢弃之前读取的全部数据
        n = r->connection->recv(r->connection, buffer, size);

        // 出错也允许，因为丢弃数据不需要关心
        // 但需要置error标记
        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;
        }

        // again表示无数据可读
        // 需要使用回调ngx_http_discarded_request_body_handler读取数据
        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        // 读到了0字节，即连接被客户端关闭，client abort
        // 也是ok
        if (n == 0) {
            return NGX_OK;
        }

        // 读取了n字节的数据，但不使用
        // 交给ngx_http_discard_request_body_filter来检查
        b.pos = buffer;
        b.last = buffer + n;

        // 检查请求结构体里的缓冲区数据，丢弃
        // 有content_length_n指定确切长度，那么只接收，不处理，移动缓冲区指针
        // chunked数据需要解析数据
        // content_length_n==0表示数据已经全部读完
        // 就已经完成了丢弃任务，否则就要加入epoll读事件继续读
        rc = ngx_http_discard_request_body_filter(r, &b);

        if (rc != NGX_OK) {
            return rc;
        }

        // 如果是ok，那么在for开始的地方检查content_length_n
    }
}


// 检查请求结构体里的缓冲区数据，丢弃
// 有content_length_n指定确切长度，那么只接收，不处理，移动缓冲区指针
// chunked数据需要解析数据
// content_length_n==0表示数据已经全部读完
// 就已经完成了丢弃任务，否则就要加入epoll读事件继续读
static ngx_int_t
ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                    size;
    ngx_int_t                 rc;
    ngx_http_request_body_t  *rb;

    // chunked数据长度不确定，需要特殊处理
    if (r->headers_in.chunked) {

        // 获取专门的请求体数据结构
        rb = r->request_body;

        // 如果还没有就创建
        if (rb == NULL) {

            rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (rb == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
            if (rb->chunked == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->request_body = rb;
        }

        for ( ;; ) {

            // in ngx_http_parse.c
            // 解析chunked数据
            rc = ngx_http_parse_chunked(r, b, rb->chunked);

            // ok表示一个chunk解析完成
            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                // 计算实际数据的长度
                size = b->last - b->pos;

                // 实际长度大于chunk长度，可能有下一个的数据已经读了
                if ((off_t) size > rb->chunked->size) {

                    // 移动缓冲区指针，消费读取的chunk数据
                    b->pos += (size_t) rb->chunked->size;

                    // chunk长度归0
                    rb->chunked->size = 0;

                } else {
                    // chunk数据不完整，没读取完
                    // 减去已经读取的长度，剩下的就是还要读取的长度
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }

                // 继续解析读取的数据，直至非ok
                continue;
            }

            // done所有的chunk数据均读取完毕
            // content_length_n置0，表示无数据，丢弃成功
            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                r->headers_in.content_length_n = 0;
                break;
            }

            // again表示数据不完整，需要继续读取
            if (rc == NGX_AGAIN) {

                /* set amount of data we want to see next time */

                r->headers_in.content_length_n = rb->chunked->length;
                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }

    } else {
        // 不是chunked，请求体数据有确定的长度

        // 检查缓冲区里头之后的数据，即收到的请求体数据
        size = b->last - b->pos;

        // 收到的数据大于头里的content_length_n
        if ((off_t) size > r->headers_in.content_length_n) {

            // 缓冲区指针移动，即消费content_length_n的数据
            b->pos += (size_t) r->headers_in.content_length_n;

            // content_length_n置0，表示无数据，丢弃成功
            r->headers_in.content_length_n = 0;

        } else {

            // 收到的数据不足，即还没有收完content_length_n字节数
            // 如果正好收完，也是在这里处理

            // 指针直接移动到最后，即消费所有收到的数据
            b->pos = b->last;

            // 头里的content_length_n减少，即还将要收多少数据
            // 如果正好收完，那么值就是0，丢弃成功
            r->headers_in.content_length_n -= size;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11
#if (NGX_HTTP_V2)
        || r->stream != NULL
#endif
       )
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    r->connection->error = 1;

    return NGX_ERROR;
}


// 分为chunked和确定长度两种
// 简单起见只研究确定长度，即ngx_http_request_body_length_filter
static ngx_int_t
ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) {
        return ngx_http_request_body_chunked_filter(r, in);

    } else {
        return ngx_http_request_body_length_filter(r, in);
    }
}


// 处理确定长度的请求体数据，参数in是已经读取的数据链表
// 先看free里是否有空闲节点，有则直接使用
// 如果没有，就从内存池的空闲链表里获取
// 创建新的链表节点，加入到out链表里
// 这里只是指针操作，没有内存拷贝
// 调用请求体过滤链表，对数据进行过滤处理
// 实际上是ngx_http_request_body_save_filter
// 拷贝in链表里的buf到rb->bufs里，不是直接连接
// 最后把用完的ngx_chaint_t挂到free里供复用，提高效率
static ngx_int_t
ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    // 请求体数据的结构体
    rb = r->request_body;

    // -1表示无效，即还没有开始读取
    // 那么剩余字节数就是content_length_n
    if (rb->rest == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;
    }

    out = NULL;
    ll = &out;

    // 遍历已经读取的数据链表
    // 创建新的链表节点，加入到out链表里
    // 这里只是指针操作，没有内存拷贝
    for (cl = in; cl; cl = cl->next) {

        // 已经读完，无剩余字节，那么就结束循环
        if (rb->rest == 0) {
            break;
        }

        // 先看free里是否有空闲节点，有则直接使用
        // 如果没有，就从内存池的空闲链表里获取
        // 最开始rb->free是空的，所以要从内存池里获取
        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // 这个缓冲区对象并不持有实际的内存块
        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        // 调整缓冲区的指针，指向链表节点里的地址
        b->temporary = 1;
        b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;
        b->flush = r->request_body_no_buffering;

        // 计算此缓冲区里的数据长度
        size = cl->buf->last - cl->buf->pos;

        // 剩余的数据还很多
        // 这里处理的是in链表，不是out
        // 消费的是in链表里的缓冲区
        if ((off_t) size < rb->rest) {
            // 消费缓冲区里的数据
            cl->buf->pos = cl->buf->last;

            // 剩余字节数减少
            rb->rest -= size;

        } else {
            // 这里rest字节已经读取足够了

            // 消费缓冲区里的数据
            cl->buf->pos += (size_t) rb->rest;

            // 剩余数据全部读取完毕，rest=0
            rb->rest = 0;

            // 如果还有多余的数据也不再考虑，调整last
            b->last = cl->buf->pos;

            // 标记为最后一块数据，重要
            b->last_buf = 1;
        }

        // 加入链表
        *ll = tl;
        ll = &tl->next;
    }

    // 这里调用请求体过滤链表，对数据进行过滤处理
    // 实际上是ngx_http_request_body_save_filter

    // 从内存池里分配节点
    // 拷贝in链表里的buf到rb->bufs里，不是直接连接
    // 同样是指针操作，没有内存拷贝
    // 如果要求写磁盘文件，那么调用ngx_http_write_request_body
    rc = ngx_http_top_request_body_filter(r, out);

    // 用于处理请求体数据，更新free/busy几个链表指针
    // 先把out链表挂到busy指针上
    // 遍历busy链表
    // 缓冲区为空，说明可以复用，应该挂到free链表里
    // 把缓冲区复位，都指向start，即完全可用
    // 此节点不应该在busy里，从busy链表摘除
    // 加入到free链表里，供以后复用
    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


// 解析分块传输的body数据
static ngx_int_t
ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body chunked filter");

        rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
        if (rb->chunked == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_in.content_length_n = 0;
        rb->rest = 3;
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        for ( ;; ) {

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %O",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            // in ngx_http_parse.c
            // 解析chunked数据
            rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked);

            // ok表示一个chunk解析完成
            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->client_max_body_size
                    && clcf->client_max_body_size
                       - r->headers_in.content_length_n < rb->chunked->size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large chunked "
                                  "body: %O+%O bytes",
                                  r->headers_in.content_length_n,
                                  rb->chunked->size);

                    r->lingering_close = 1;

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->temporary = 1;
                b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;
                b->flush = r->request_body_no_buffering;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += (size_t) rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                rb->rest = 0;

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NGX_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                rb->rest = rb->chunked->length;

                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_top_request_body_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


// 参数in实际上是ngx_http_request_body_length_filter里的out，即读取到的数据
// 从内存池里分配节点
// 拷贝in链表里的buf到rb->bufs里，不是直接连接
// 同样是指针操作，没有内存拷贝
// 如果要求写磁盘文件，那么调用ngx_http_write_request_body
ngx_int_t
ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                 *b;
    ngx_chain_t               *cl;
    ngx_http_request_body_t   *rb;

    // 请求体数据的结构体
    rb = r->request_body;

#if (NGX_DEBUG)

#if 0
    for (cl = rb->bufs; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }
#endif

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    /* TODO: coalesce neighbouring buffers */

    // 从内存池里分配节点
    // 拷贝in链表里的buf到rb->bufs里，不是直接连接
    // 同样是指针操作，没有内存拷贝
    if (ngx_chain_add_copy(r->pool, &rb->bufs, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->request_body_no_buffering) {
        return NGX_OK;
    }

    if (rb->rest > 0) {

        if (rb->buf && rb->buf->last == rb->buf->end
            && ngx_http_write_request_body(r) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_OK;
    }

    /* rb->rest == 0 */

    // 如果要求写磁盘文件，那么调用ngx_http_write_request_body
    if (rb->temp_file || r->request_body_in_file_only) {

        if (ngx_http_write_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;
        }
    }

    return NGX_OK;
}
