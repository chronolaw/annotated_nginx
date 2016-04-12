// annotated by chrono since 2016

/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_THREAD_POOL_H_INCLUDED_
#define _NGX_THREAD_POOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

// 编译时需使用选项--with-threads
// thread_pool指令需要在main域配置，定义一个线程池供使用

// 线程执行的任务结构体，handler是真正被线程执行的函数
struct ngx_thread_task_s {
    // 链表指针，多个task形成一个链表
    ngx_thread_task_t   *next;

    // task的id，由全局计数器ngx_thread_pool_task_id生成
    // task->id = ngx_thread_pool_task_id++;
    ngx_uint_t           id;

    // 用户使用的数据，也就是handl的data参数
    void                *ctx;

    // 由线程里的线程执行的函数，真正的工作
    void               (*handler)(void *data, ngx_log_t *log);

    ngx_event_t          event;
};


// 线程池结构体
typedef struct ngx_thread_pool_s  ngx_thread_pool_t;


// 根据配置创建线程池结构体对象,添加进线程池模块配置结构体里的数组
ngx_thread_pool_t *ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);

// 根据名字获取线程池
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);

// 创建一个线程任务结构体
ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size);

// 把任务放入线程池，由线程执行
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task);


#endif /* _NGX_THREAD_POOL_H_INCLUDED_ */
