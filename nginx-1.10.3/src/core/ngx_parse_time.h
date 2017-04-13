// annotated by chrono since 2016
//
// 由原http目录迁移而来
// 原文件是ngx_http_parse_time.c

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PARSE_TIME_H_INCLUDED_
#define _NGX_PARSE_TIME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 解析http格式日期，不仅供http模块使用
time_t ngx_parse_http_time(u_char *value, size_t len);

/* compatibility */
// 使用宏保留了之前版本的名字
//
// 之前的版本定义在http/ngx_http.h
// time_t ngx_http_parse_time(u_char *value, size_t len);
#define ngx_http_parse_time(value, len)  ngx_parse_http_time(value, len)


#endif /* _NGX_PARSE_TIME_H_INCLUDED_ */
