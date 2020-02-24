// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 两个双端队列，保存epoll获取的事件
//
// 如果使用了reuseport，或者不使用负载均衡
// 那么这两个队列就完全不会用到

// 保存accept事件，即客户端发起的连接请求
ngx_queue_t  ngx_posted_accept_events;

// 读写事件和通知事件

// 1.17.5新增,处理ngx_posted_next_events
ngx_queue_t  ngx_posted_next_events;

ngx_queue_t  ngx_posted_events;


// 遍历队列，取出队列里的事件，调用对应的handler
// cycle参数只用于记录日志
void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    while (!ngx_queue_empty(posted)) {

        // 取队列头节点
        q = ngx_queue_head(posted);

        // 获取头节点元素，即事件
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        // in ngx_event_posted.h
        // 函数宏，从队列里移除
        ngx_delete_posted_event(ev);

        // 执行事件的回调函数
        ev->handler(ev);
    }
}


void
ngx_event_move_posted_next(ngx_cycle_t *cycle)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    for (q = ngx_queue_head(&ngx_posted_next_events);
         q != ngx_queue_sentinel(&ngx_posted_next_events);
         q = ngx_queue_next(q))
    {
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_next_events);
}
