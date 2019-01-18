// annotated by chrono since 2018
//
// * ngx_slab_page_s
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

// ngx_slab_page_t
// slab页信息
// 管理每个内存页
// 只有三个指针大小，64位系统上是3*8=24字节
struct ngx_slab_page_s {
    // 有多种含义：
    // 指示连续空闲页的数量,NGX_SLAB_PAGE
    // 标记页面的状态：busy
    // 位图方式标记页面内部的使用情况
    uintptr_t         slab;

    // 后链表指针，串联多个可分配内存页
    // 全满页的next是null
    ngx_slab_page_t  *next;

    // 半满页指向管理头节点
    // prev的后两位标记页类型
    // 全满页低位作为页标记
    // ngx_slab_page_prev计算
    uintptr_t         prev;
};


// ngx_slab_stat_t
// 各个slot分配内存的统计信息
// 目前供商业模块ngx_api来调用
// 目前暂无公开接口使用
// 只能自己定位获取信息
// 四个整数，64位系统上是4*8=32字节
typedef struct {
    ngx_uint_t        total;
    ngx_uint_t        used;

    ngx_uint_t        reqs;
    ngx_uint_t        fails;
} ngx_slab_stat_t;


// ngx_slab_pool_t
// 管理共享内存的池
// 存放page管理信息、空闲页数量、共享内存的开始地址等
// 64位系统上占用200个字节
// 使用best fit算法
// 分成8/16/32...2k/4k的多个slot，找最合适的分配
// 但也可以直接管理内部的非共享内存
// 不使用锁即可
typedef struct {
    // 互斥锁使用的两个原子变量
    ngx_shmtx_sh_t    lock;

    // 最小分配数量，通常是8字节
    size_t            min_size;

    // 最小左移，通常是3，即2^3=8
    // ngx_init_zone_pool里设置
    // 在shm_zone[i].init之前，不能自己修改
    size_t            min_shift;

    // 页数组
    // 4k大小，对齐管理内存
    ngx_slab_page_t  *pages;

    // 页链表指针，最后一页
    // 用于合并空闲页的末尾计算
    ngx_slab_page_t  *last;

    // 空闲页链表头节点
    // 也作为链表的尾节点哨兵
    // 注意不是指针
    ngx_slab_page_t   free;

    // 统计信息数组
    // 在slots之后
    // 目前供商业模块ngx_api来调用
    // 目前暂无公开接口使用
    // 只能自己定位获取信息
    ngx_slab_stat_t  *stats;

    // 空闲页数量
    ngx_uint_t        pfree;

    // 共享内存的开始地址
    // 经过了多次计算，前面有很多管理信息
    u_char           *start;

    // 共享内存的末尾地址
    // 使用start和end来判断指针是否属于本内存
    u_char           *end;

    // 互斥锁
    // mtx.lock指向sh.lock
    // ngx_shmtx_create():mtx->lock = &addr->lock;
    ngx_shmtx_t       mutex;

    // 记录日志的额外字符串，用户可以指定
    // 共享内存错误记录日志时区分不同的共享内存
    // 不指定则指向zero，即无特殊字符串
    // 被ngx_slab_error使用，外界不能用
    u_char           *log_ctx;

    // '\0'字符
    u_char            zero;

    // 是否记录无内存异常
    // 可以置为0,减少记录日志的操作
    unsigned          log_nomem:1;

    // 供用户使用，关联任意数据
    // 方便使用本内存里最常用的数据
    // 例如红黑树指针
    void             *data;

    // 内存的起始地址
    // 在ngx_init_zone_pool时检测内存是否正确
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
