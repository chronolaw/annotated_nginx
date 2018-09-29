// annotated by chrono since 2016
//
// * ngx_thread_task_s
// * ngx_thread_task_alloc
// * ngx_thread_task_post

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

// 在http请求里使用线程池，需要设置请求的阻塞成员
// ++r->main->blocked;
// ++r->main->count;
// 回调时需要--r->main->blocked


// 涉及两个handler
// 1.任务的执行handler，在线程池里执行，使用task->ctx
// 2.任务的完成handler，由ngx_notify触发，在主线程里执行，使用ev->data

// 线程执行的任务结构体，handler是真正被线程执行的函数
// 线程的执行函数是ngx_thread_pool_cycle，参数是线程池结构体
// 必须设置好event成员的handler和data，才能正确完成回调
//
// ngx_thread_task_post把任务加入线程池
// ngx_thread_pool_cycle执行任务
// ngx_thread_pool_handler完成任务
struct ngx_thread_task_s {
    // 链表指针，多个task形成一个链表
    ngx_thread_task_t   *next;

    // task的id，由全局计数器ngx_thread_pool_task_id生成
    // task->id = ngx_thread_pool_task_id++;
    // 在线程运行时用户的handler看不到
    ngx_uint_t           id;

    // 用户使用的数据，也就是handler的data参数
    // 用这个参数传递给线程要处理的各种数据
    // 比较灵活的方式是传递一个指针，而不是真正的数据结构内容
    // 例如 struct ctx {xxx *params;};
    //
    // 由ngx_thread_task_alloc分配内存空间并赋值
    // 不需要自己手工分配内存
    void                *ctx;

    // 由线程里的线程执行的函数，真正的工作
    // 执行用户定义的操作，通常是阻塞的
    // 参数data就是上面的ctx
    // handler不能直接看到task，但可以在ctx里存储task指针
    void               (*handler)(void *data, ngx_log_t *log);

    // 任务关联的事件对象
    // event.active表示任务是否已经放入任务队列
    // 这里的event并不关联任何socket读写或定时器对象
    // 仅用到它的handler/data成员，当线程完成任务时回调
    //
    // event->data要存储足够的信息，才能够完成请求
    // 可以使用r->ctx，里面存储请求r、连接c等
    ngx_event_t          event;
};


// 线程池结构体
// 此结构体的实际定义在c文件里，外部不可见，深度定制则不方便
// 线程的数量默认为32个线程
// 任务等待队列默认是65535
typedef struct ngx_thread_pool_s  ngx_thread_pool_t;


// 根据配置创建线程池结构体对象,添加进线程池模块配置结构体里的数组
ngx_thread_pool_t *ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name);

// 根据名字获取线程池
// 遍历线程池数组，找到名字对应的结构体
ngx_thread_pool_t *ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name);

// 创建一个线程任务结构体
// 参数size是用户数据ctx的大小，位于task之后
// 因为C的内存布局是平坦的，所以使用这种hack的方法来扩展task结构体
ngx_thread_task_t *ngx_thread_task_alloc(ngx_pool_t *pool, size_t size);

// 把任务放入线程池，由线程执行
// 锁定互斥量，防止多线程操作的竞态
// 如果等待处理的任务数大于设置的最大队列数,那么添加任务失败
// 操作完waiting、queue、ngx_thread_pool_task_id后解锁
ngx_int_t ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task);


#endif /* _NGX_THREAD_POOL_H_INCLUDED_ */
