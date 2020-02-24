// annotated by chrono since 2016
//
// * ngx_post_event
// * ngx_delete_posted_event
// * ngx_posted_accept_events
// * ngx_posted_events

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

// 如果使用了reuseport，或者不使用负载均衡
// 那么这两个post队列就完全不会用到

// 函数宏，加入队列
#define ngx_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        ngx_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }


// 函数宏，从队列里移除
#define ngx_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    ngx_queue_remove(&(ev)->queue);                                           \
                                                                              \
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);



// 遍历队列，取出队列里的事件，调用对应的handler
// cycle参数只用于记录日志
void ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted);
void ngx_event_move_posted_next(ngx_cycle_t *cycle);

// 保存accept事件，即客户端发起的连接请求
extern ngx_queue_t  ngx_posted_accept_events;

// 读写事件和通知事件

// 1.17.5新增,处理ngx_posted_next_events
extern ngx_queue_t  ngx_posted_next_events;

extern ngx_queue_t  ngx_posted_events;


#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
