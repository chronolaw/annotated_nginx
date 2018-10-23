// annotated by chrono since 2018

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


// 自旋锁，尽量不让出cpu抢锁
// 操作原子变量，设置为值value
// spin通常是2048,即2^11
// 目前仅在线程池里需要使用自旋锁
void
ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

    // 必须支持原子操作，否则无法编译
#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  i, n;

    for ( ;; ) {

        // 检查lock值，为0表示没有被锁
        // 使用cas操作赋值，成功则获得锁
        // 不会阻塞,失败则继续后续代码
        // 相当于try_lock
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        // 多核cpu，不必让出cpu，等待一下
        if (ngx_ncpu > 1) {

            // n按2的幂增加
            for (n = 1; n < spin; n <<= 1) {

                // cpu等待的时间逐步加长
                for (i = 0; i < n; i++) {
                    // #define ngx_cpu_pause()             __asm__ ("pause")
                    // 自旋等待，降低功耗，不会引起性能下降
                    ngx_cpu_pause();
                }

                // 再次try_lock
                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
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

// not NGX_HAVE_ATOMIC_OPS
#else

// 使用了--with-threads开启多线程功能
// 但没有原子操作，则无法通过编译
// 因为线程池需要使用自旋锁
#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

// 不使用线程池，则自旋锁是空实现

#endif

}
