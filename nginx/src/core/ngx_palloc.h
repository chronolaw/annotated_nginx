// annotated by chrono since 2016
//
// * ngx_pool_data_t
// * ngx_pool_s

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

// 如果编译时指定宏NGX_DEBUG_PALLOC
// 则不会启用内存池机制，都使用malloc分配内存
// 方便使用valgrind等来检测内存问题

/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
// 在内存池可直接分配的最大块，通常是4k-1
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

// 默认一个内存池块大小是16k
// 用于cycle->pool
// 注意，默认池大小与pagesize无关
#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

// 内存池对齐数，16字节，即128位
#define NGX_POOL_ALIGNMENT       16

// 内存池最小的大小
// 首先要能够容纳ngx_pool_t结构体
// 然后还要至少能分配两个大内存块
// 最后16字节对齐
// 用于配置内存池时的参数检查
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


// 内存池销毁时调用的清理函数
// 相当于析构函数，必要的清理动作
typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

// 清理结构体，类似于lambda，绑定了函数指针和参数
// ngx_pool_t::cleanup指向所有清理函数
struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;      //清理函数
    void                 *data;         //传递给handler，清理用

    ngx_pool_cleanup_t   *next;         //链表指针，所有的清理结构体为一个链表
};


// 大块内存节点
typedef struct ngx_pool_large_s  ngx_pool_large_t;

// 大块内存节点, 大于4k
// 保存成链表方便回收利用
struct ngx_pool_large_s {
    // 多个大块内存串成链表，方便回收利用
    ngx_pool_large_t     *next;

    // 指向malloc分配的大块内存
    void                 *alloc;
};


// 描述内存池的信息
// 每个内存块都有，在最开头的部分，管理本块内存
// 64位系统大小为32字节
typedef struct {
    // 可用内存的起始位置
    // last的意思是分配内存后的最后位置
    // 小块内存每次都从这里分配
    u_char               *last;

    // 可用内存的结束位置
    // 即此内存块的末地址
    u_char               *end;

    // 下一个内存池节点
    ngx_pool_t           *next;

    // 本节点分配失败次数
    // 失败超过4次则本节点认为满，不再参与分配
    // 注意满的内存块不会主动回收
    ngx_uint_t            failed;
} ngx_pool_data_t;


// nginx内存池结构体
// 实际是由多个节点串成的单向链表
// 每个节点分配小块内存
// 但max、current、大块内存链表只在头节点
// 64位系统大小为80字节
// 结构体里没有保存块大小的字段，由d.end-p得到
struct ngx_pool_s {
    // 描述本内存池节点的信息
    ngx_pool_data_t       d;

    // 下面的字段仅在第一个块中有意义
    // 其他块中不存在，被用于分配内存

    // 可分配的最大块
    // 不能超过NGX_MAX_ALLOC_FROM_POOL,即4k-1
    size_t                max;

    // 当前使用的内存池节点
    ngx_pool_t           *current;

    // 为chain做的优化，空闲缓冲区链表
    ngx_chain_t          *chain;

    // 大块的内存，串成链表
    ngx_pool_large_t     *large;

    ngx_pool_cleanup_t   *cleanup;      //清理链表头指针

    ngx_log_t            *log;
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;

// 分配内存,不用内存池，使用malloc
// 实现在os/unix/ngx_alloc.c
// void *ngx_alloc(size_t size, ngx_log_t *log);
// void *ngx_calloc(size_t size, ngx_log_t *log);

// 创建/销毁内存池

// 字节对齐分配一个size - sizeof(ngx_pool_t)内存
// 内存池的大小可以超过4k
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);

// 销毁内存池
// 调用清理函数链表
// 检查大块内存链表，直接free
// 遍历内存池节点，逐个free
void ngx_destroy_pool(ngx_pool_t *pool);

// 重置内存池，释放内存，但没有free归还给系统
// 之前已经分配的内存块仍然保留
// 遍历内存池节点，逐个重置空闲指针位置
// 注意cleanup链表没有清空
// 只有destroy时才会销毁
void ngx_reset_pool(ngx_pool_t *pool);

// 分配8字节对齐的内存，速度快，可能有少量浪费
// 分配大块内存(>4k),直接调用malloc
// 所以可以用jemalloc来优化
void *ngx_palloc(ngx_pool_t *pool, size_t size);

// 分配未对齐的内存
// 分配大块内存(>4k),直接调用malloc
// 所以可以用jemalloc来优化
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);

// 使用ngx_palloc分配内存，并将内存块清零
// 分配大块内存(>4k),直接调用malloc
// 所以可以用jemalloc来优化
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);

// 字节对齐分配大块内存
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);

// 把内存归还给内存池，通常无需调用
// 实际上只释放大块内存
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


// 创建一个清理结构体，size是ngx_pool_cleanup_t::data分配的大小
// size可以为0,用户需要自己设置ngx_pool_cleanup_t::data指针
ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);

void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);

// 清理文件用
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
