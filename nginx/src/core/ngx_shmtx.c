// annotated by chrono since 2018
//
// * ngx_shmtx_create
// * ngx_shmtx_trylock
// * ngx_shmtx_unlock

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

// 通常会有下面两个条件编译宏
// NGX_HAVE_POSIX_SEM
// NGX_HAVE_GCC_ATOMIC=>NGX_HAVE_ATOMIC_OPS

#if (NGX_HAVE_ATOMIC_OPS)


static void ngx_shmtx_wakeup(ngx_shmtx_t *mtx);


// 初始化互斥锁
// spin是-1则不使用信号量
// 只会自旋，不会导致进程睡眠等待
ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    mtx->lock = &addr->lock;

    // spin是-1则不使用信号量
    // 只会自旋，不会导致进程睡眠等待
    if (mtx->spin == (ngx_uint_t) -1) {
        return NGX_OK;
    }

    // 默认spin是2048
    // 即2^11=2048
    mtx->spin = 2048;

#if (NGX_HAVE_POSIX_SEM)

    // 初始化等待的原子量
    mtx->wait = &addr->wait;

    // 初始化信号量，1表示进程间同步，初始值是0
    if (sem_init(&mtx->sem, 1, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_init() failed");
    } else {
        // 信号量初始化成功，置标志位
        mtx->semaphore = 1;
    }

#endif

    return NGX_OK;
}


// 销毁使用的信号量
void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    // spin是-1则不使用信号量
    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


// 无阻塞尝试锁，使用cas
// 值使用pid，保证只能自己才能解锁
ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
}


// 阻塞获取锁
// 自旋或信号量睡眠等待
void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    // 不断尝试直至获得锁
    for ( ;; ) {

        // 无阻塞尝试锁，使用cas
        // 值使用pid，保证只能自己才能解锁
        // 锁成功则退出循环
        if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
            return;
        }

        // 多核cpu，不必让出cpu，等待一下
        // 自旋
        if (ngx_ncpu > 1) {

            // n按2的幂增加
            // 默认spin是2048
            // 即2^11=2048，循环11次
            for (n = 1; n < mtx->spin; n <<= 1) {

                // cpu等待的时间逐步加长
                for (i = 0; i < n; i++) {
                    // #define ngx_cpu_pause()             __asm__ ("pause")
                    // 自旋等待，降低功耗，不会引起性能下降
                    ngx_cpu_pause();
                }

                // 再次try_lock
                // 锁成功则退出循环
                if (*mtx->lock == 0
                    && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid))
                {
                    return;
                }
            }
        }

        // 一个cpu就不能自旋占用cpu了

#if (NGX_HAVE_POSIX_SEM)

        // spin是-1则不使用信号量

        // 使用信号量则睡眠等待唤醒
        if (mtx->semaphore) {
            // wait++
            (void) ngx_atomic_fetch_add(mtx->wait, 1);

            // 再尝试一下
            // 锁成功则wait--
            if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
                (void) ngx_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

            // 信号量等待，进入睡眠
            while (sem_wait(&mtx->sem) == -1) {
                ngx_err_t  err;

                err = ngx_errno;

                if (err != NGX_EINTR) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            // 到这里是其他进程调用sem_post唤醒

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                           "shmtx awoke");

            // 回到循环开头，尝试锁
            // 锁不了继续自旋再睡眠
            continue;
        }

#endif

        // 使用信号量不会走这里
        // spin是-1则不使用信号量
        // 占用cpu过久，让出cpu
        // 之后继续try_lock，直至lock成功
        ngx_sched_yield();
    }
}


// 解锁
void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

    // cas操作值为0
    // 值使用pid，保证只能自己才能解锁
    if (ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
        // 解锁成功则信号量唤醒其他睡眠等待的进程
        ngx_shmtx_wakeup(mtx);
    }
}


// 强制解锁，指定了pid
// 用于某些worker进程异常的情况，解除互斥锁
ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx forced unlock");

    if (ngx_atomic_cmp_set(mtx->lock, pid, 0)) {
        // 解锁成功则信号量唤醒其他睡眠等待的进程
        ngx_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


// 解锁成功则信号量唤醒其他睡眠等待的进程
static void
ngx_shmtx_wakeup(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_uint_t  wait;

    // spin是-1则不使用信号量
    // 不需要唤醒任何进程
    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        // 检查正在等待的进程数量
        wait = *mtx->wait;

        // 负数表示无等待进程，不需要唤醒
        if ((ngx_atomic_int_t) wait <= 0) {
            return;
        }

        // wait--
        // 在循环里执行，保证有一次成功
        if (ngx_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "shmtx wake %uA", wait);

    // sem_post通知，唤醒一个进程
    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


// 不会使用文件锁
// 下面的代码可以不看
#else


ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {

        if (ngx_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return NGX_OK;
        }

        ngx_shmtx_destroy(mtx);
    }

    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}


void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == NGX_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCES) {
        return 0;
    }

#endif

    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    return 0;
}

#endif
