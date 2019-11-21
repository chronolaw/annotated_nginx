// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CORE_H_INCLUDED_
#define _NGX_CORE_H_INCLUDED_


// 定义基本的整数类型、unix信号等
#include <ngx_config.h>


// 对核心的数据结构定义为_t类型，方便使用
typedef struct ngx_module_s          ngx_module_t;      // ngx_conf_file.h
typedef struct ngx_conf_s            ngx_conf_t;        // ngx_conf_file.h
typedef struct ngx_cycle_s           ngx_cycle_t;       // ngx_cycle.h
typedef struct ngx_pool_s            ngx_pool_t;        // ngx_palloc.h
typedef struct ngx_chain_s           ngx_chain_t;       // ngx_buf.h
typedef struct ngx_log_s             ngx_log_t;
typedef struct ngx_open_file_s       ngx_open_file_t;
typedef struct ngx_command_s         ngx_command_t;     // ngx_conf_file.h
typedef struct ngx_file_s            ngx_file_t;
typedef struct ngx_event_s           ngx_event_t;       // event/ngx_event.h
typedef struct ngx_event_aio_s       ngx_event_aio_t;
typedef struct ngx_connection_s      ngx_connection_t;  // ngx_connection.h


// 1.8版开始正式支持线程，比旧版有较大的改动，使用传统的线程池
// 一个task队列，一个done队列，使用条件变量等待task
typedef struct ngx_thread_task_s     ngx_thread_task_t;

// ssl相关数据结构
typedef struct ngx_ssl_s             ngx_ssl_t;
typedef struct ngx_proxy_protocol_s  ngx_proxy_protocol_t;
typedef struct ngx_ssl_connection_s  ngx_ssl_connection_t;

// 1.15.0新增的管理udp会话数据结构
// in event/ngx_event_udp.c
// 作为ngx_connection_t的一个成员
// 串进红黑树，缓冲区里是客户端发送的数据
typedef struct ngx_udp_connection_s  ngx_udp_connection_t;

// 事件发生时调用的函数
// 例如监听端口时会回调ngx_event_accept
typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);

typedef void (*ngx_connection_handler_pt)(ngx_connection_t *c);


// 通用的nginx错误码，也可以自己定义新错误码，但必须是负数
#define  NGX_OK          0      //无错误
#define  NGX_ERROR      -1      //最常见的错误，含义不明确
#define  NGX_AGAIN      -2      //未准备好，需要重试
#define  NGX_BUSY       -3      //设备忙
#define  NGX_DONE       -4      //已经完成部分工作，但还未完成，需后续操作
#define  NGX_DECLINED   -5      //请求已经处理，拒绝执行,在nginx模块里返回表示模块不处理，引擎查找下一个模块来处理
#define  NGX_ABORT      -6      //严重错误


// 必须的nginx头文件

// os/unix下，各种操作系统相关头文件
#include <ngx_errno.h>
#include <ngx_atomic.h>
#include <ngx_thread.h>
#include <ngx_rbtree.h>
#include <ngx_time.h>
#include <ngx_socket.h>

#include <ngx_string.h>
#include <ngx_files.h>
#include <ngx_shmem.h>
#include <ngx_process.h>
#include <ngx_user.h>

// 加载动态库
#include <ngx_dlopen.h>

#include <ngx_parse.h>
#include <ngx_parse_time.h>

#include <ngx_log.h>
#include <ngx_alloc.h>
#include <ngx_palloc.h>

// 核心数据结构头文件
#include <ngx_buf.h>
#include <ngx_queue.h>
#include <ngx_array.h>
#include <ngx_list.h>
#include <ngx_hash.h>
#include <ngx_file.h>

// crc和摘要算法，未包含md5/sha1
#include <ngx_crc.h>
#include <ngx_crc32.h>
#include <ngx_murmurhash.h>

// pcre，正则表达式
#if (NGX_PCRE)
#include <ngx_regex.h>
#endif

#include <ngx_radix_tree.h>
#include <ngx_times.h>
#include <ngx_rwlock.h>
#include <ngx_shmtx.h>
#include <ngx_slab.h>
#include <ngx_inet.h>
#include <ngx_cycle.h>
#include <ngx_resolver.h>

#if (NGX_OPENSSL)
#include <ngx_event_openssl.h>
#endif

#include <ngx_process_cycle.h>
#include <ngx_conf_file.h>
#include <ngx_module.h>
#include <ngx_open_file_cache.h>
#include <ngx_os.h>
#include <ngx_connection.h>
#include <ngx_syslog.h>
#include <ngx_proxy_protocol.h>


// 回车换行定义，用于http解析
#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"


// 宏定义三个简单的数学函数
#define ngx_abs(value)       (((value) >= 0) ? (value) : - (value))
#define ngx_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define ngx_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))

void ngx_cpuinfo(void);

#if (NGX_HAVE_OPENAT)
#define NGX_DISABLE_SYMLINKS_OFF        0
#define NGX_DISABLE_SYMLINKS_ON         1
#define NGX_DISABLE_SYMLINKS_NOTOWNER   2
#endif

#endif /* _NGX_CORE_H_INCLUDED_ */
