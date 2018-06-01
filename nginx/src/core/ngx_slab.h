// annotated by chrono since 2018
//
// * ngx_slab_pool_t

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

// slab页
struct ngx_slab_page_s {
    uintptr_t         slab;

    // 前后链表指针
    ngx_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    ngx_uint_t        total;
    ngx_uint_t        used;

    ngx_uint_t        reqs;
    ngx_uint_t        fails;
} ngx_slab_stat_t;


// 管理共享内存的池
// 但也可以直接管理内部的非共享内存
// 不使用锁即可
typedef struct {
    // 互斥锁
    ngx_shmtx_sh_t    lock;

    size_t            min_size;
    size_t            min_shift;

    // 页数组
    ngx_slab_page_t  *pages;

    // 页链表指针
    ngx_slab_page_t  *last;
    ngx_slab_page_t   free;

    ngx_slab_stat_t  *stats;

    // 空闲页数量
    ngx_uint_t        pfree;

    // 共享内存的开始地址
    // 经过了多次计算，前面有很多管理信息
    u_char           *start;

    // 共享内存的末尾地址
    u_char           *end;

    // 互斥锁
    ngx_shmtx_t       mutex;

    // 指向zero
    u_char           *log_ctx;

    // 0字符
    u_char            zero;

    // 是否记录无内存异常
    unsigned          log_nomem:1;

    // 无用的数据？？
    void             *data;
    void             *addr;
} ngx_slab_pool_t;


void ngx_slab_sizes_init(void);
void ngx_slab_init(ngx_slab_pool_t *pool);

// 加锁分配内存
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);

// 不加锁分配内存
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);

// 加锁分配内存并清空
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);

// 不加锁分配内存并清空
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);

// 加锁释放内存
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);

// 不加锁释放内存
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
