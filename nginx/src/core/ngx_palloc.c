// annotated by chrono since 2016
//
// * ngx_create_pool
// * ngx_palloc_small
// * ngx_palloc_large
// * ngx_palloc_block

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

// 如果编译时指定宏NGX_DEBUG_PALLOC
// 则不会启用内存池机制，都使用malloc分配内存
// 方便使用valgrind等来检测内存问题
// 此宏自1.9.x开始出现

// 在本内存池内分配小块内存
// 不超过NGX_MAX_ALLOC_FROM_POOL,即4k-1
static ngx_inline void *ngx_palloc_small(ngx_pool_t *pool, size_t size,
    ngx_uint_t align);

// 所有内存池节点都空间不足
// 创建一个新的节点，即内存块
// 跳过内存池描述信息的长度
// 后面的max,current等没有意义，所以可以被利用
static void *ngx_palloc_block(ngx_pool_t *pool, size_t size);

// 分配大块内存(>4k),直接调用malloc
// 挂到大块链表里方便后续的回收
static void *ngx_palloc_large(ngx_pool_t *pool, size_t size);


// 字节对齐分配一个size - sizeof(ngx_pool_t)80字节内存
// 内存池的大小可以超过4k
// 一开始只有一个内存池节点
ngx_pool_t *
ngx_create_pool(size_t size, ngx_log_t *log)
{
    ngx_pool_t  *p;

    // 字节对齐分配内存,16字节的倍数
    // os/unix/ngx_alloc.c
    p = ngx_memalign(NGX_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    // 设置可用的内存，减去了自身的大小80字节
    p->d.last = (u_char *) p + sizeof(ngx_pool_t);
    p->d.end = (u_char *) p + size;

    // 一开始只有一个内存池节点
    p->d.next = NULL;

    // 失败次数初始化为0
    p->d.failed = 0;

    // 池内可用的内存空间，减去了自身的大小80字节
    size = size - sizeof(ngx_pool_t);

    // #define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)
    // 不能超过NGX_MAX_ALLOC_FROM_POOL,即4k-1
    p->max = (size < NGX_MAX_ALLOC_FROM_POOL) ? size : NGX_MAX_ALLOC_FROM_POOL;

    // 刚创建，就使用自己
    p->current = p;

    // 未开始分配，链表都是空
    p->chain = NULL;
    p->large = NULL;

    p->cleanup = NULL;
    p->log = log;

    return p;
}


// 销毁内存池
// 调用清理函数链表
// 检查大块内存链表，直接free
// 遍历内存池节点，逐个free
void
ngx_destroy_pool(ngx_pool_t *pool)
{
    ngx_pool_t          *p, *n;
    ngx_pool_large_t    *l;
    ngx_pool_cleanup_t  *c;

    // 调用清理函数链表
    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (NGX_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    // 检查大块内存链表，直接free
    // in os/unix/ngx_alloc.h
    // #define ngx_free          free
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    // 遍历内存池节点，逐个free
    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        ngx_free(p);

        if (n == NULL) {
            break;
        }
    }
}


// 重置内存池，释放内存，但没有free归还给系统
// 之前已经分配的内存块仍然保留
// 遍历内存池节点，逐个重置空闲指针位置
// 注意cleanup链表没有清空
// 只有destroy时才会销毁
void
ngx_reset_pool(ngx_pool_t *pool)
{
    ngx_pool_t        *p;
    ngx_pool_large_t  *l;

    // 检查大块内存链表，直接free
    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            ngx_free(l->alloc);
        }
    }

    // 遍历内存池节点，逐个重置空闲指针位置
    // 相当于释放了已经分配的内存
    //
    // 这里有一个问题，其他节点的块实际上只用了ngx_pool_data_t
    // reset指针移动了ngx_pool_t大小
    // 就浪费了80-32字节的内存
    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(ngx_pool_t);
        p->d.failed = 0;
    }

    // 当前内存池指针
    pool->current = pool;

    // 指针置空，之前的内存都已经释放了
    pool->chain = NULL;
    pool->large = NULL;

    // 注意cleanup链表没有清空
    // 只有destroy时才会销毁
}


// 分配对齐的内存，速度快，可能有少量浪费
// 多用于创建结构体
void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    // 如果要求小于4k的内存，对齐分配
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 1);
    }
#endif

    // 分配大块内存(>4k),直接调用malloc
    return ngx_palloc_large(pool, size);
}


// 分配未对齐的内存
// 多用于字符串等不规则内存需求
void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    // 如果要求小于4k的内存，不对齐分配
#if !(NGX_DEBUG_PALLOC)
    if (size <= pool->max) {
        return ngx_palloc_small(pool, size, 0);
    }
#endif

    // 分配大块内存(>4k),直接调用malloc
    return ngx_palloc_large(pool, size);
}


// 在本内存池内分配小块内存
// 不超过NGX_MAX_ALLOC_FROM_POOL,即4k-1
static ngx_inline void *
ngx_palloc_small(ngx_pool_t *pool, size_t size, ngx_uint_t align)
{
    u_char      *m;
    ngx_pool_t  *p;

    // 使用当前节点
    p = pool->current;

    do {
        // 空闲内存的起始位置
        m = p->d.last;

        // 要求对齐，所以会有少量浪费，但cpu处理速度快
        // 64位上最多浪费7字节
        // 向上对齐到8字节(64位), in ngx_config.h
        // #define NGX_ALIGNMENT   sizeof(unsigned long)    /* platform word */
        // #define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
        // #define ngx_align_ptr(p, a)
        //     (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))
        if (align) {
            m = ngx_align_ptr(m, NGX_ALIGNMENT);
        }

        // 看空间是否足够
        // 即内存块的末尾是否能够容纳size大小
        if ((size_t) (p->d.end - m) >= size) {
            // 移动空闲内存的位置
            p->d.last = m + size;

            return m;
        }

        // 空闲不足，找下一个内存池节点
        p = p->d.next;

    } while (p);

    // 所有当前的内存池节点都空间不足
    // 需要创建一个新的节点
    return ngx_palloc_block(pool, size);
}


// 所有内存池节点都空间不足
// 创建一个新的节点，即内存块
// 跳过内存池描述信息的长度
// 后面的max,current等没有意义，所以可以被利用
static void *
ngx_palloc_block(ngx_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    ngx_pool_t  *p, *new;

    // 计算当前内存池的大小
    // 即当初创建时的大小
    psize = (size_t) (pool->d.end - (u_char *) pool);

    // 创建一个新节点
    // 字节对齐分配内存,16字节的倍数
    m = ngx_memalign(NGX_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    // 新的内存块
    new = (ngx_pool_t *) m;

    // 设置节点的空闲空间
    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    // 跳过内存池描述信息的长度, 64位系统是32字节
    // 后面的max,current等没有意义，所以可以被利用
    // 新的内存块比头节点多80-32=48字节可用
    m += sizeof(ngx_pool_data_t);

    // 成功分配内存
    // 向上对齐到8字节(64位), in ngx_config.h
    m = ngx_align_ptr(m, NGX_ALIGNMENT);

    // 移动空闲内存的位置
    new->d.last = m + size;

    // 重新设置当前节点
    // 把前面的节点失败次数增加
    for (p = pool->current; p->d.next; p = p->d.next) {
        // 分配失败次数超过5次的节点
        // 它的下一个节点作为current
        // 也就是说之前的节点都已经满了，不会再做分配
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    // p必定是链表的最后一个，挂到末尾
    p->d.next = new;

    // 返回分配的内存
    return m;
}


// 分配大块内存(>4k),直接调用malloc
// 挂到大块链表里方便后续的回收
// 所以可以用jemalloc来优化
static void *
ngx_palloc_large(ngx_pool_t *pool, size_t size)
{
    void              *p;
    ngx_uint_t         n;
    ngx_pool_large_t  *large;

    // 封装C库函数malloc，可以记录错误日志
    p = ngx_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    // 挂到大块链表里
    for (large = pool->large; large; large = large->next) {
        // 找到一个空闲的节点，避免再分配内存
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        // 只找三次，避免低效查找
        // 3是一个“经验”数据
        if (n++ > 3) {
            break;
        }
    }

    // 三次没有空节点则新建一个
    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    // 挂到链表最前面
    // 可以理解为先进先出
    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


// 字节对齐分配大块内存
void *
ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    ngx_pool_large_t  *large;

    // 字节对齐分配内存,16字节的倍数
    // os/unix/ngx_alloc.c
    p = ngx_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    // 新建一个管理节点
    large = ngx_palloc_small(pool, sizeof(ngx_pool_large_t), 1);
    if (large == NULL) {
        ngx_free(p);
        return NULL;
    }

    // 加入大块内存链表
    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


// 把内存归还给内存池，通常无需调用
// 实际上只释放大块内存
ngx_int_t
ngx_pfree(ngx_pool_t *pool, void *p)
{
    ngx_pool_large_t  *l;

    // 遍历大块链表，找到则释放
    // 如果多次申请大块内存需要当心效率
    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            ngx_free(l->alloc);

            // 指针置为空，之后可以复用节点
            l->alloc = NULL;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


// 使用ngx_palloc分配内存，并将内存块清零
void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    p = ngx_palloc(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


// 创建一个清理结构体，size是ngx_pool_cleanup_t::data分配的大小
// size可以为0,用户需要自己设置ngx_pool_cleanup_t::data指针
ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t  *c;

    // 内存池拿一块内存
    c = ngx_palloc(p, sizeof(ngx_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    // 如果要求额外数据就再分配一块
    // 注意都是对齐的
    if (size) {
        c->data = ngx_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    // handler清空，之后用户自己设置
    c->handler = NULL;

    // 挂到内存池的清理链表里
    c->next = p->cleanup;

    p->cleanup = c;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd)
{
    ngx_pool_cleanup_t       *c;
    ngx_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == ngx_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


void
ngx_pool_cleanup_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


void
ngx_pool_delete_file(void *data)
{
    ngx_pool_cleanup_file_t  *c = data;

    ngx_err_t  err;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (ngx_delete_file(c->name) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, c->log, err,
                          ngx_delete_file_n " \"%s\" failed", c->name);
        }
    }

    if (ngx_close_file(c->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
ngx_get_cached_block(size_t size)
{
    void                     *p;
    ngx_cached_block_slot_t  *slot;

    if (ngx_cycle->cache == NULL) {
        return NULL;
    }

    slot = &ngx_cycle->cache[(size + ngx_pagesize - 1) / ngx_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
