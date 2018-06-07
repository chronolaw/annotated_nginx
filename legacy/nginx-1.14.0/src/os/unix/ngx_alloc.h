// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ALLOC_H_INCLUDED_
#define _NGX_ALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 封装C库函数malloc，可以记录错误日志
void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

#define ngx_free          free


/*
 * Linux has memalign() or posix_memalign()
 * Solaris has memalign()
 * FreeBSD 7.0 has posix_memalign(), besides, early version's malloc()
 * aligns allocations bigger than page size at the page boundary
 */

#if (NGX_HAVE_POSIX_MEMALIGN || NGX_HAVE_MEMALIGN)

// 对齐分配内存
void *ngx_memalign(size_t alignment, size_t size, ngx_log_t *log);

#else

#define ngx_memalign(alignment, size, log)  ngx_alloc(size, log)

#endif


// 基本的页大小,ngx_pagesize = getpagesize()
extern ngx_uint_t  ngx_pagesize;

// 页大小的左移数
// 左移数,4k即2^12,值12
extern ngx_uint_t  ngx_pagesize_shift;

// 宏定义为64
// 然后由ngx_cpuinfo（ngx_cpuinfo.c）来探测
extern ngx_uint_t  ngx_cacheline_size;


#endif /* _NGX_ALLOC_H_INCLUDED_ */
