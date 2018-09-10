// annotated by chrono since 2016
//
// * ngx_random
// * NGX_ALIGNMENT
// * ngx_align
// * ngx_align_ptr

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONFIG_H_INCLUDED_
#define _NGX_CONFIG_H_INCLUDED_


#include <ngx_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (NGX_FREEBSD)
#include <ngx_freebsd_config.h>


#elif (NGX_LINUX)
#include <ngx_linux_config.h>


#elif (NGX_SOLARIS)
#include <ngx_solaris_config.h>


#elif (NGX_DARWIN)
#include <ngx_darwin_config.h>


#elif (NGX_WIN32)
#include <ngx_win32_config.h>


#else /* POSIX */
#include <ngx_posix_config.h>

#endif


#ifndef NGX_HAVE_SO_SNDLOWAT
#define NGX_HAVE_SO_SNDLOWAT     1
#endif


// 非win32，即unix
#if !(NGX_WIN32)

// 拼接宏
#define ngx_signal_helper(n)     SIG##n
#define ngx_signal_value(n)      ngx_signal_helper(n)

// 产生随机数
// 种子在ngx_worker_process_init里初始化
// srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);
#define ngx_random               random

// 重定义unix信号，名字更易读
/* TODO: #ifndef */
#define NGX_SHUTDOWN_SIGNAL      QUIT
#define NGX_TERMINATE_SIGNAL     TERM
#define NGX_NOACCEPT_SIGNAL      WINCH
#define NGX_RECONFIGURE_SIGNAL   HUP

#if (NGX_LINUXTHREADS)
#define NGX_REOPEN_SIGNAL        INFO
#define NGX_CHANGEBIN_SIGNAL     XCPU
#else
#define NGX_REOPEN_SIGNAL        USR1
#define NGX_CHANGEBIN_SIGNAL     USR2
#endif

#define ngx_cdecl
#define ngx_libc_cdecl

#endif

// nginx内部标准整数定义
// ngx_rbtree_key_t = ngx_uint_t (ngx_rbtree.h)
// ngx_rbtree_key_int_t = ngx_int_t(ngx_rbtree.h)
// ngx_msec_t = ngx_rbtree_key_t = ngx_uint_t (ngx_time.h)
// ngx_msec_int_t = ngx_rbtree_key_int_t ngx_int_t(ngx_time.h)
typedef intptr_t        ngx_int_t;      //有符号整数
typedef uintptr_t       ngx_uint_t;     //无符号整数
typedef intptr_t        ngx_flag_t;     //相当于bool，标志量用


// 整数的字符串形式长度
#define NGX_INT32_LEN   (sizeof("-2147483648") - 1)
#define NGX_INT64_LEN   (sizeof("-9223372036854775808") - 1)

// 指针长度是4字节，32位cpu
#if (NGX_PTR_SIZE == 4)
#define NGX_INT_T_LEN   NGX_INT32_LEN
#define NGX_MAX_INT_T_VALUE  2147483647

#else
// 指针长度是8字节，64位cpu
#define NGX_INT_T_LEN   NGX_INT64_LEN
#define NGX_MAX_INT_T_VALUE  9223372036854775807
#endif


// 分配内存时的字节对齐
// 长整型，64位上是8字节
#ifndef NGX_ALIGNMENT
#define NGX_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

// 计算字节对齐的宏
// 上对齐到a的倍数，a是2的幂
#define ngx_align(d, a)     (((d) + (a - 1)) & ~(a - 1))

// 指针上对齐到a的倍数
#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define ngx_abort       abort


/* TODO: platform specific: array[NGX_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define NGX_INVALID_ARRAY_INDEX 0x80000000


// ngx_inline通常需要配合static使用
// 在nginx unit里的定义是：
// static inline __attribute__((always_inline))

/* TODO: auto_conf: ngx_inline   inline __inline __inline__ */
#ifndef ngx_inline
#define ngx_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifdef MAXHOSTNAMELEN
#define NGX_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define NGX_MAXHOSTNAMELEN  256
#endif


#define NGX_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define NGX_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#if (NGX_COMPAT)

#define NGX_COMPAT_BEGIN(slots)  uint64_t spare[slots];
#define NGX_COMPAT_END

#else

#define NGX_COMPAT_BEGIN(slots)
#define NGX_COMPAT_END

#endif


#endif /* _NGX_CONFIG_H_INCLUDED_ */
