// annotated by chrono since 2016

/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


// 必须支持原子操作，否则无法编译
#if (NGX_HAVE_ATOMIC_OPS)


// 读写锁也使用自旋，默认是2^11
#define NGX_RWLOCK_SPIN   2048

// 写锁的写入值
#define NGX_RWLOCK_WLOCK  ((ngx_atomic_uint_t) -1)


// 写锁，相当于自旋
void
ngx_rwlock_wlock(ngx_atomic_t *lock)
{
    ngx_uint_t  i, n;

    for ( ;; ) {

        // 检查lock值，为0表示没有被锁
        // 使用cas操作赋值-1，成功则获得锁
        // 不会阻塞,失败则继续后续代码
        // 相当于try_lock
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK)) {
            return;
        }

        // 多核cpu，不必让出cpu，等待一下
        if (ngx_ncpu > 1) {

            for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1) {

                // cpu等待的时间逐步加长
                for (i = 0; i < n; i++) {
                    // #define ngx_cpu_pause()             __asm__ ("pause")
                    // 自旋等待，降低功耗，不会引起性能下降
                    ngx_cpu_pause();
                }

                // 再次try_lock
                if (*lock == 0
                    && ngx_atomic_cmp_set(lock, 0, NGX_RWLOCK_WLOCK))
                {
                    return;
                }
            }
        }

        // 占用cpu过久，让出cpu
        // 单cpu必须让出cpu让其他进程运行
        // 之后继续try_lock，直至lock成功
        // yield不会进入睡眠
        ngx_sched_yield();
    }
}


// 读锁，相当于自旋
void
ngx_rwlock_rlock(ngx_atomic_t *lock)
{
    ngx_uint_t         i, n;
    ngx_atomic_uint_t  readers;

    for ( ;; ) {

        // 现有的读者数量
        readers = *lock;

        // 使用cas操作读者加1，成功则获得锁
        // 不会阻塞,失败则继续后续代码
        // 相当于try_lock
        // 已经加写锁则直接失败
        if (readers != NGX_RWLOCK_WLOCK
            && ngx_atomic_cmp_set(lock, readers, readers + 1))
        {
            return;
        }

        // 多核cpu，不必让出cpu，等待一下
        if (ngx_ncpu > 1) {

            for (n = 1; n < NGX_RWLOCK_SPIN; n <<= 1) {

                // cpu等待的时间逐步加长
                for (i = 0; i < n; i++) {
                    // #define ngx_cpu_pause()             __asm__ ("pause")
                    // 自旋等待，降低功耗，不会引起性能下降
                    ngx_cpu_pause();
                }

                // 必须重新取读者数量
                readers = *lock;

                // 再次try_lock
                if (readers != NGX_RWLOCK_WLOCK
                    && ngx_atomic_cmp_set(lock, readers, readers + 1))
                {
                    return;
                }
            }
        }

        // 占用cpu过久，让出cpu
        // 单cpu必须让出cpu让其他进程运行
        // 之后继续try_lock，直至lock成功
        // yield不会进入睡眠
        ngx_sched_yield();
    }
}


// 解锁
void
ngx_rwlock_unlock(ngx_atomic_t *lock)
{
    ngx_atomic_uint_t  readers;

    // 现有的读者数量
    readers = *lock;

    // -1表示写锁
    // 直接解锁，置0
    if (readers == NGX_RWLOCK_WLOCK) {
        (void) ngx_atomic_cmp_set(lock, NGX_RWLOCK_WLOCK, 0);
        return;
    }

    // 读锁则减少读者数量
    // 循环保证减少成功
    for ( ;; ) {

        // 尝试减少值
        if (ngx_atomic_cmp_set(lock, readers, readers - 1)) {
            return;
        }

        // 不成功重新取读者数
        readers = *lock;
    }
}


// 锁降级，由写锁变成读锁
void
ngx_rwlock_downgrade(ngx_atomic_t *lock)
{
    if (*lock == NGX_RWLOCK_WLOCK) {
        *lock = 1;
    }
}


#else

#if (NGX_HTTP_UPSTREAM_ZONE || NGX_STREAM_UPSTREAM_ZONE)

#error ngx_atomic_cmp_set() is not defined!

#endif

#endif
