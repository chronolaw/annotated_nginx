// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

// nginx共享内存结构体
struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
};


// nginx核心数据结构，表示nginx的生命周期，含有许多重要参数
// conf_ctx, 存储所有模块的配置结构体，是个二维数组
// free_connections,空闲连接，使用指针串成单向链表
// listening,监听的端口数组
// connections/read_events/write_events,连接池,大小是connection_n
// 启动nginx时的环境参数，配置文件，工作路径等
// 每个进程都有这个结构
struct ngx_cycle_s {

    // 存储所有模块的配置结构体，是个二维数组
    // 0 = ngx_core_module
    // 1 = ngx_errlog_module
    // 3 = ngx_event_module
    // 4 = ngx_event_core_module
    // 5 = ngx_epoll_module
    // 7 = ngx_http_module
    // 8 = ngx_http_core_module
    void                  ****conf_ctx;

    // 内存池
    ngx_pool_t               *pool;

    ngx_log_t                *log;
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;

    // 空闲连接，使用指针串成单向链表
    // 指向第一个空闲连接，即头节点
    ngx_connection_t         *free_connections;

    // 空闲连接的数量
    ngx_uint_t                free_connection_n;

    // 复用连接对象队列
    ngx_queue_t               reusable_connections_queue;

    // 监听的端口数组, in ngx_connection.h
    // 主要成员: fd,backlog,rcvbuf,sndbuf
    ngx_array_t               listening;

    // 打开的目录
    ngx_array_t               paths;

    // 打开的文件
    ngx_list_t                open_files;

    // 共享内存
    ngx_list_t                shared_memory;

    // 连接数组的数量
    // 由worker_connections指定，在event模块里设置
    ngx_uint_t                connection_n;

    ngx_uint_t                files_n;

    // 连接池,大小是connection_n
    // 每个连接都有一个读事件和写事件，使用数组序号对应
    // 由ngx_event_core_module的ngx_event_process_init()创建
    ngx_connection_t         *connections;

    // 读事件数组，大小与connections相同，并且一一对应
    // 由ngx_event_core_module的ngx_event_process_init()创建
    ngx_event_t              *read_events;

    // 写事件数组，大小与connections相同，并且一一对应
    // 由ngx_event_core_module的ngx_event_process_init()创建
    ngx_event_t              *write_events;

    // 保存之前的cycle，如init_cycle
    ngx_cycle_t              *old_cycle;

    // 启动nginx时的配置文件
    ngx_str_t                 conf_file;

    // 启动nginx时的-g参数
    ngx_str_t                 conf_param;

    // 如果使用了-p，那么conf_prefix==prefix
    // 否则两者是不同的，见ngx_process_options

    // #define NGX_CONF_PREFIX  "conf/"
    ngx_str_t                 conf_prefix;

    // #define NGX_PREFIX  "/usr/local/nginx/"
    ngx_str_t                 prefix;

    ngx_str_t                 lock_file;
    ngx_str_t                 hostname;
};


// ngx_core_module的配置结构体，在nginx.c里设置
typedef struct {
     ngx_flag_t               daemon;       //守护进程
     ngx_flag_t               master;       //启动master/worker进程机制

     //调用time_update的时间分辨率，毫秒，在event模块里使用
     ngx_msec_t               timer_resolution;

     ngx_int_t                worker_processes;     //worker进程的数量
     ngx_int_t                debug_points;         //是否使用debug point

     ngx_int_t                rlimit_nofile;
     ngx_int_t                rlimit_sigpending;
     off_t                    rlimit_core;

     int                      priority;

     ngx_uint_t               cpu_affinity_n;
     uint64_t                *cpu_affinity;

     char                    *username;
     ngx_uid_t                user;
     ngx_gid_t                group;

     ngx_str_t                working_directory;
     ngx_str_t                lock_file;

     ngx_str_t                pid;                  //master进程的pid文件名
     ngx_str_t                oldpid;

     ngx_array_t              env;
     char                   **environment;

// 旧的线程实现，1.9.x已经删除，不应该使用
#if (NGX_OLD_THREADS)
     ngx_int_t                worker_threads;
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


// 旧的线程实现，1.9.x已经删除，不应该使用
#if (NGX_OLD_THREADS)

typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;

#endif


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


// 在main里调用,太长，以后可能会简化
// 从old_cycle(init_cycle)里复制必要的信息，创建新cycle
// 当reconfigure的时候old_cycle就是当前的cycle
// 初始化core模块
ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);

// 写pid到文件
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);

void ngx_delete_pidfile(ngx_cycle_t *cycle);

// main()里调用，如果用了-s参数，那么就要发送reload/stop等信号
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);

void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


// nginx生命周期使用的超重要对象
extern volatile ngx_cycle_t  *ngx_cycle;

extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_OLD_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
