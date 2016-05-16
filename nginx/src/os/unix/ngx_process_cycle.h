// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
#define _NGX_PROCESS_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_CMD_OPEN_CHANNEL   1
#define NGX_CMD_CLOSE_CHANNEL  2
#define NGX_CMD_QUIT           3
#define NGX_CMD_TERMINATE      4
#define NGX_CMD_REOPEN         5


// 用于ngx_process，标记进程的状态
#define NGX_PROCESS_SINGLE     0
#define NGX_PROCESS_MASTER     1
#define NGX_PROCESS_SIGNALLER  2
#define NGX_PROCESS_WORKER     3
#define NGX_PROCESS_HELPER     4


typedef struct {
    ngx_event_handler_pt       handler;
    char                      *name;
    ngx_msec_t                 delay;
} ngx_cache_manager_ctx_t;


// main()函数里调用，启动worker进程
// 监听信号
// 核心操作是sigsuspend，暂时挂起进程，不占用CPU，只有收到信号时才被唤醒
void ngx_master_process_cycle(ngx_cycle_t *cycle);

// main()函数里调用，仅启动一个进程，没有fork
// master_process off;
void ngx_single_process_cycle(ngx_cycle_t *cycle);


// 声明为extern，供其他文件使用

// 创建的进程都在ngx_processes数组里
// 此数组仅在master进程里使用，worker进程不使用
extern ngx_uint_t      ngx_process;

// 1.10，worker进程的序号
extern ngx_uint_t      ngx_worker;

// 记录nginx master进程的pid，在main()里使用
extern ngx_pid_t       ngx_pid;

extern ngx_pid_t       ngx_new_binary;
extern ngx_uint_t      ngx_inherited;
extern ngx_uint_t      ngx_daemonized;

// 进程正在退出,即quit
extern ngx_uint_t      ngx_exiting;

// 声明为extern，供其他文件使用
extern sig_atomic_t    ngx_reap;
extern sig_atomic_t    ngx_sigio;
extern sig_atomic_t    ngx_sigalrm;
extern sig_atomic_t    ngx_quit;
extern sig_atomic_t    ngx_debug_quit;
extern sig_atomic_t    ngx_terminate;
extern sig_atomic_t    ngx_noaccept;
extern sig_atomic_t    ngx_reconfigure;
extern sig_atomic_t    ngx_reopen;
extern sig_atomic_t    ngx_change_binary;


#endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
