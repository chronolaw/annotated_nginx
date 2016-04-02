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
// 每个进程都有这个结构
struct ngx_cycle_s {

    // 存储所有模块的配置结构体，是个二维数组
    void                  ****conf_ctx;

    // 内存池
    ngx_pool_t               *pool;

    ngx_log_t                *log;
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    ngx_connection_t        **files;

    // 空闲连接
    ngx_connection_t         *free_connections;
    ngx_uint_t                free_connection_n;

    ngx_queue_t               reusable_connections_queue;

    // 监听的端口数组
    ngx_array_t               listening;
    ngx_array_t               paths;
    ngx_list_t                open_files;
    ngx_list_t                shared_memory;

    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

    // 连接池,大小是connection_n
    ngx_connection_t         *connections;

    // 读事件数组，大小与connections相同，并且一一对应
    ngx_event_t              *read_events;

    // 写事件数组，大小与connections相同，并且一一对应
    ngx_event_t              *write_events;

    ngx_cycle_t              *old_cycle;

    //启动nginx时的环境参数，配置文件，工作路径等
    ngx_str_t                 conf_file;
    ngx_str_t                 conf_param;
    ngx_str_t                 conf_prefix;
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

#if (NGX_OLD_THREADS)
     ngx_int_t                worker_threads;       //旧的线程实现，不应该使用
     size_t                   thread_stack_size;
#endif

} ngx_core_conf_t;


#if (NGX_OLD_THREADS)

typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;

#endif


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_OLD_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */
