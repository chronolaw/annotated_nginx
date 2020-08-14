// annotated by chrono since 2016
//
// * ngx_buf_s
// * ngx_chain_s

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 用于ngx_buf_t，关联任意的数据
typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

// 表示一个单块的缓冲区，既可以是内存也可以是文件
// start和end两个成员变量标记了数据所在内存块的边界
// 如果内存块是可以修改的，在操作时必须参考这两个成员防止越界
struct ngx_buf_s {
    u_char          *pos;           //内存数据的起始位置
    u_char          *last;          //内存数据的结束位置

    off_t            file_pos;      //文件数据的起始偏移量
    off_t            file_last;     //文件数据的结束偏移量

    u_char          *start;         /* start of buffer */   //内存数据的上界
    u_char          *end;           /* end of buffer */     //内存数据的下界

    ngx_buf_tag_t    tag;           //void*指针，可以是任意数据

    ngx_file_t      *file;          //存储数据的文件对象

    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    unsigned         temporary:1;   //内存块临时数据，可以修改

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1;      //内存块数据，不允许修改

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;        //内存映射数据，不允许修改

    unsigned         recycled:1;
    unsigned         in_file:1;     //缓冲区在文件里
    unsigned         flush:1;       //要求Nginx立即输出本缓冲区
    unsigned         sync:1;        //要求Nginx同步操作本缓冲区
    unsigned         last_buf:1;    //最后一块缓冲区
    unsigned         last_in_chain:1;   //链里的最后一块缓冲区

    unsigned         last_shadow:1;
    unsigned         temp_file:1;       //缓冲区在临时文件里

    /* STUB */ int   num;
};


// 把缓冲区块简单地组织为一个单向链表
// 如果节点是链表的尾节点就必须要把next置为nullptr，表示链表结束
// ngx_chain_t (ngx_core.h)
struct ngx_chain_s {
    ngx_buf_t    *buf;      //缓冲区指针
    ngx_chain_t  *next;     //下一个链表节点
};


//创建链表的参数结构
typedef struct {
    ngx_int_t    num;       //缓冲区的数量，即节点数量
    size_t       size;      //缓冲区的大小
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


// 强制转换-1，作为发送chain失败的返回错误值
// 注意，nullptr不是错误
#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


// 检查多个标志位，确定缓冲区是否在内存里
#define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)

// 起控制作用的特殊缓冲区
#define ngx_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_sync_only(b)                                                 \
    ((b)->sync && !ngx_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

// 计算缓冲区的大小，会根据是否在内存里使用恰当的指针
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

// 从内存池里分配一块size大小的缓冲区
// 并使用buf管理，注意temporary是1，可以修改
ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);

// 一次创建多个缓冲区，返回一个连接好的链表
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


// 直接从内存池创建一个ngx_buf_t结构
#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

// 从内存池里获取释放chain
// 从内存池的空闲链表里取一个对象
// 如果空闲链表是空才真正创建对象
// 这是对象池模式，提高运行效率
ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);

// 释放链表节点，挂在空闲链表里
#define ngx_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

// 从内存池里分配节点
// 拷贝in链表里的buf到chain里，不是直接连接
// 同样是指针操作，没有内存拷贝
ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);

// 先看free里是否有空闲节点，有则直接使用
// 如果没有，就从内存池的空闲链表里获取
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);

// 用于处理请求体数据，更新free/busy几个链表指针
// 先把out链表挂到busy指针上
// 遍历busy链表
// 缓冲区为空，说明可以复用，应该挂到free链表里
// 把缓冲区复位，都指向start，即完全可用
// 此节点不应该在busy里，从busy链表摘除
// 加入到free链表里，供以后复用
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

// 根据已经实际发送的字节数更新链表
// 已经发送的缓冲区会清空
// 最后返回处理之后的链表指针
ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
