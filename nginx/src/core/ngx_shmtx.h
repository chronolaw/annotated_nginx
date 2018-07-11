// annotated by chrono since 2018

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

// 通常会有下面两个条件编译宏
// NGX_HAVE_POSIX_SEM
// NGX_HAVE_GCC_ATOMIC=>NGX_HAVE_ATOMIC_OPS

// ngx_shmtx_sh_t
// 互斥锁使用的两个原子变量
typedef struct {

    // 锁变量
    // 使用原子操作实现锁
    ngx_atomic_t   lock;

    // 信号量等待变量
    // 标记等待的进程数量
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;


// ngx_shmtx_t
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    // 指向ngx_shmtx_sh_t.lock
    ngx_atomic_t  *lock;

    // 使用进程间信号量

#if (NGX_HAVE_POSIX_SEM)
    // 指向ngx_shmtx_sh_t.wait
    ngx_atomic_t  *wait;

    // 是否使用信号量的标志
    // 可以手动置0强制不使用信号量
    ngx_uint_t     semaphore;

    // unix信号量对象
    sem_t          sem;
#endif

    // 不会使用文件锁
#else
    ngx_fd_t       fd;
    u_char        *name;
#endif

    // 类似自旋锁的等待周期
    // spin是-1则不使用信号量
    // 只会自旋，不会导致进程睡眠等待
    // 目前只有accept_mutex使用了-1
    ngx_uint_t     spin;
} ngx_shmtx_t;


// 初始化互斥锁
// spin是-1则不使用信号量
// 只会自旋，不会导致进程睡眠等待
ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);

// 销毁使用的信号量
// spin是-1则不使用信号量
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);

// 无阻塞尝试锁，使用cas
// 值使用pid，保证只能自己才能解锁
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);

// 阻塞获取锁
// 自旋或信号量睡眠等待
void ngx_shmtx_lock(ngx_shmtx_t *mtx);

// 解锁
// 解锁成功则信号量唤醒其他睡眠等待的进程
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);

// 强制解锁，指定了pid
// 解锁成功则信号量唤醒其他睡眠等待的进程
// 用于某些worker进程异常的情况，解除互斥锁
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
