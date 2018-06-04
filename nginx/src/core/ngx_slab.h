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

// slab页信息，在梅页的最前面
struct ngx_slab_page_s {
    // 指示联系空闲页的数量
    // 标记页面的状态：busy
    // 位图方式标记页面内部的使用情况
    uintptr_t         slab;

    // 前后链表指针
    ngx_slab_page_t  *next;

    // prev的后两位标记页类型
    uintptr_t         prev;
};


// 统计信息
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

    // 最小分配数量，通常是8字节
    size_t            min_size;

    // 最小左移，通常是3
    // ngx_init_zone_pool里设置
    // 在shm_zone[i].init之前，不能自己修改
    size_t            min_shift;

    // 页数组
    ngx_slab_page_t  *pages;

    // 页链表指针
    ngx_slab_page_t  *last;

    // 空闲页链表头节点
    // 注意不是指针
    ngx_slab_page_t   free;

    // 统计信息数组
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

    // 记录日志的额外字符串，用户可以指定
    // 共享内存错误记录日志时区分不同的共享内存
    // 不指定则指向zera，即无特殊字符串
    // 被ngx_slab_error使用，外界不能用
    u_char           *log_ctx;

    // 0字符
    u_char            zero;

    // 是否记录无内存异常
    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} ngx_slab_pool_t;


// 1.14.0新增
// 初始化上面的三个数字
// 在main里调用
void ngx_slab_sizes_init(void);

// 初始化slab结构
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
