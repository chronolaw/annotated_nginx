// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


// 计算得到系统的cpu数量
ngx_int_t   ngx_ncpu;

// 使用系统调用getrlimit(RLIMIT_NOFILE, &rlmt)
// 是nginx能够打开的最多描述数量，但似乎并没有使用
ngx_int_t   ngx_max_sockets;

// 在接受连接时使用accept4调用
ngx_uint_t  ngx_inherited_nonblocking;

ngx_uint_t  ngx_tcp_nodelay_and_tcp_nopush;


struct rlimit  rlmt;


// unix基本的数据收发接口
// 屏蔽linux/bsd/darwin等的差异
ngx_os_io_t ngx_os_io = {
    ngx_unix_recv,
    ngx_readv_chain,
    ngx_udp_unix_recv,
    ngx_unix_send,
    ngx_udp_unix_send,
    ngx_udp_unix_sendmsg_chain,
    ngx_writev_chain,
    0
};


// 在nginx.c的main()调用
// 初始化ngx_os_io结构体，设置基本的收发函数
// 基本的页大小,ngx_pagesize = getpagesize()
// 初始化随机数
// 实际工作在ngx_linux_init.c的ngx_os_specific_init()完成
// 关键操作ngx_os_io = ngx_linux_io;设置为linux的接口函数
ngx_int_t
ngx_os_init(ngx_log_t *log)
{
    ngx_time_t  *tp;
    ngx_uint_t   n;
#if (NGX_HAVE_LEVEL1_DCACHE_LINESIZE)
    long         size;
#endif

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    // in ngx_linux_init.c
    // 初始化ngx_os_io结构体，设置为linux的收发函数
    if (ngx_os_specific_init(log) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    if (ngx_init_setproctitle(log) != NGX_OK) {
        return NGX_ERROR;
    }

    // 基本的页大小,ngx_pagesize = getpagesize()
    // 通常是4k
    ngx_pagesize = getpagesize();

    // 宏定义为64
    // 然后由ngx_cpuinfo（ngx_cpuinfo.c）来探测
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;

    // 计算左移数,4k即2^12,值12
    for (n = ngx_pagesize; n >>= 1; ngx_pagesize_shift++) { /* void */ }

#if (NGX_HAVE_SC_NPROCESSORS_ONLN)
    if (ngx_ncpu == 0) {
        ngx_ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    }
#endif

    if (ngx_ncpu < 1) {
        ngx_ncpu = 1;
    }

#if (NGX_HAVE_LEVEL1_DCACHE_LINESIZE)
    size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    if (size > 0) {
        ngx_cacheline_size = size;
    }
#endif

    ngx_cpuinfo();

    // 最多描述符数量，ngx_max_sockets
    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, log, errno,
                      "getrlimit(RLIMIT_NOFILE) failed");
        return NGX_ERROR;
    }

    ngx_max_sockets = (ngx_int_t) rlmt.rlim_cur;

    // 在接受连接时使用accept4调用
#if (NGX_HAVE_INHERITED_NONBLOCK || NGX_HAVE_ACCEPT4)
    ngx_inherited_nonblocking = 1;
#else
    ngx_inherited_nonblocking = 0;
#endif

    tp = ngx_timeofday();
    srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);

    return NGX_OK;
}


// 仅打印notice日志，暂无意义
void
ngx_os_status(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0, NGINX_VER_BUILD);

#ifdef NGX_COMPILER
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "built by " NGX_COMPILER);
#endif

#if (NGX_HAVE_OS_SPECIFIC_INIT)
    // 仅打印notice日志，暂无意义
    ngx_os_specific_status(log);
#endif

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "getrlimit(RLIMIT_NOFILE): %r:%r",
                  rlmt.rlim_cur, rlmt.rlim_max);
}


#if 0

ngx_int_t
ngx_posix_post_conf_init(ngx_log_t *log)
{
    ngx_fd_t  pp[2];

    if (pipe(pp) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "pipe() failed");
        return NGX_ERROR;
    }

    if (dup2(pp[1], STDERR_FILENO) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, errno, "dup2(STDERR) failed");
        return NGX_ERROR;
    }

    if (pp[1] > STDERR_FILENO) {
        if (close(pp[1]) == -1) {
            ngx_log_error(NGX_LOG_EMERG, log, errno, "close() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#endif
