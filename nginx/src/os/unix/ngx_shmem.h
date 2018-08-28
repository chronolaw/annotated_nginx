// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 真正操作共享内存的对象
typedef struct {
    // 共享内存的开始地址
    // 通常就是ngx_slab_pool_t
    u_char      *addr;

    // 共享内存的大小
    size_t       size;

    // 共享内存的名字
    ngx_str_t    name;

    ngx_log_t   *log;

    // 是否存在，即已经创建过了
    // 依据nginx官方文档，此字段仅用于windows
    ngx_uint_t   exists;   /* unsigned  exists:1;  */
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
