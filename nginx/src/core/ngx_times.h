// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 专用的时间数据结构
typedef struct {
    time_t      sec;        //自epoch以来的秒数，即时间戳
    ngx_uint_t  msec;       //秒数后的小数部分，单位是毫秒

    // 缺少微秒，可以像tengine一样加入一个新字段
    // ngx_uint_t  usec;

    ngx_int_t   gmtoff;     //GMT时区偏移量，以分钟为单位
} ngx_time_t;


void ngx_time_init(void);

//要求Nginx更新缓存的时间,需要使用锁，成本较高，所以不应该频繁调用
void ngx_time_update(void);

void ngx_time_sigsafe_update(void);

// time_t转换为日期字符串
u_char *ngx_http_time(u_char *buf, time_t t);

u_char *ngx_http_cookie_time(u_char *buf, time_t t);

// 把time_t转换为格林威治标准时间（GMT）
void ngx_gmtime(time_t t, ngx_tm_t *tp);

time_t ngx_next_time(time_t when);
#define ngx_next_time_n      "mktime()"


// cache机制存放时间值，使用指示当前缓存的时间
extern volatile ngx_time_t  *ngx_cached_time;

// 当前时间的秒数（时间戳）
#define ngx_time()           ngx_cached_time->sec

// 当前完整的时间数据结构
#define ngx_timeofday()      (ngx_time_t *) ngx_cached_time

// 全局变量提供缓存好的日期字符串，减少频繁调用的成本
extern volatile ngx_str_t    ngx_cached_err_log_time;
extern volatile ngx_str_t    ngx_cached_http_time;
extern volatile ngx_str_t    ngx_cached_http_log_time;
extern volatile ngx_str_t    ngx_cached_http_log_iso8601;
extern volatile ngx_str_t    ngx_cached_syslog_time;

/*
 * milliseconds elapsed since some unspecified point in the past
 * and truncated to ngx_msec_t, used in event timers
 */
// 表示自epoch以来的毫秒数，即sec * 1000 + msec
// 1.13.10改为使用单调时间，不再是日历时间
// 只用于定时器
extern volatile ngx_msec_t  ngx_current_msec;


#endif /* _NGX_TIMES_H_INCLUDED_ */
