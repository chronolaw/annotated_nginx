// annotated by chrono since 2016
//
// * ngx_chain_update_sent

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


// 从内存池里分配一块size大小的内存
// 并使用buf管理，注意temporary是1，可以修改
ngx_buf_t *
ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t *b;

    b = ngx_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = ngx_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by ngx_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}


// 从内存池的空闲链表里取一个对象
// 如果空闲链表是空才真正创建对象
// 这是对象池模式，提高运行效率
ngx_chain_t *
ngx_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    cl = ngx_palloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


// 创建多个链表节点
ngx_chain_t *
ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs)
{
    u_char       *p;
    ngx_int_t     i;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, **ll;

    p = ngx_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = ngx_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by ngx_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


// 从内存池里分配节点
// 拷贝in链表里的buf到chain里，不是直接连接
// 同样是指针操作，没有内存拷贝
ngx_int_t
ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain, ngx_chain_t *in)
{
    ngx_chain_t  *cl, **ll;

    ll = chain;

    // 找到chain链表的末尾
    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    // 从内存池里分配节点
    // 拷贝buf到chain里，不是直接连接
    while (in) {
        cl = ngx_alloc_chain_link(pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return NGX_OK;
}


// 先看free里是否有空闲节点，有则直接使用
// 如果没有，就从内存池的空闲链表里获取
ngx_chain_t *
ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free)
{
    ngx_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


// 用于处理请求体数据，更新free/busy几个链表指针
// 先把out链表挂到busy指针上
// 遍历busy链表
// 缓冲区为空，说明可以复用，应该挂到free链表里
// 把缓冲区复位，都指向start，即完全可用
// 此节点不应该在busy里，从busy链表摘除
// 加入到free链表里，供以后复用
void
ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;

    // 1.11.x增加了空指针检查
    if (*out) {
        // 把out链表挂到busy指针上
        if (*busy == NULL) {

            // busy是空直接挂
            *busy = *out;

        } else {
            // 否则找到busy的链表末尾再挂上
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    // 遍历busy链表
    while (*busy) {
        // 取当前节点
        cl = *busy;

        // 缓冲区里有数据，停止遍历，结束函数
        if (ngx_buf_size(cl->buf) != 0) {
            break;
        }

        // 缓冲区为空，说明可以复用，应该挂到free链表里

        // 检查tag，如果不是本功能相关的buf就归还给内存池
        // 跳过此节点，继续检查下一个
        if (cl->buf->tag != tag) {
            *busy = cl->next;
            ngx_free_chain(p, cl);
            continue;
        }

        // 把缓冲区复位，都指向start，即完全可用
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        // 此节点不应该在busy里，从busy链表摘除
        *busy = cl->next;

        // 加入到free链表里，供以后复用
        cl->next = *free;
        *free = cl;
    }
}


off_t
ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    ngx_fd_t      fd;
    ngx_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + ngx_pagesize - 1)
                       & ~((off_t) ngx_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


// 根据已经实际发送的字节数更新链表
// 已经发送的缓冲区会清空
// 最后返回处理之后的链表指针
ngx_chain_t *
ngx_chain_update_sent(ngx_chain_t *in, off_t sent)
{
    off_t  size;

    // sent字节数处理完结束循环
    for ( /* void */ ; in; in = in->next) {

        // 忽略flush、sync、eof等控制用特殊缓冲区
        if (ngx_buf_special(in->buf)) {
            continue;
        }

        // 优化，0不做任何处理
        if (sent == 0) {
            break;
        }

        // 计算当前链表节点里缓冲区的大小
        size = ngx_buf_size(in->buf);

        // 总发送字节数大于此缓冲区
        // 也就是说会有多于一个的链表节点
        if (sent >= size) {
            // sent数减少
            sent -= size;

            // 内存缓冲区，直接清空，指针pos指向last
            if (ngx_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            // 文件缓冲区，直接清空，指针pos指向last
            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            // 链表指针后移，继续处理下一个节点
            continue;
        }

        // 此缓冲区的大小多于剩余的sent字节
        // 即此缓冲区只发送了一部分，还有一些没有发送出去


        // 调整内存缓冲区的指针，剩下的是未发送的
        if (ngx_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        // 调整文件缓冲区的指针，剩下的是未发送的
        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        // sent字节数已经处理完，结束循环
        // 其实也可以令sent=0，然后在循环开头结束
        break;
    }

    // 最后返回处理之后的链表指针
    return in;
}
