// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


// 重命名pid_t
typedef pid_t       ngx_pid_t;

// 使用-1表示无效的pid
#define NGX_INVALID_PID  -1

// 进程的执行函数，在ngx_spawn_process()里调用
typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

// 存储进程信息
typedef struct {
    // 进程id
    ngx_pid_t           pid;

    // waitpid()返回的状态
    int                 status;

    // 进程间通信用的channle
    ngx_socket_t        channel[2];

    // 进程执行的函数
    ngx_spawn_proc_pt   proc;

    // proc函数的参数
    // 对于worker进程data是workerid，即进程的序号
    void               *data;

    char               *name;

    // 进程当前的状态，用于关闭时用
    unsigned            respawn:1;      //重新生成的新进程
    unsigned            just_spawn:1;   //进程刚刚产生
    unsigned            detached:1;     //进程已经与父进程分离
    unsigned            exiting:1;      //进程正在退出
    unsigned            exited:1;       //进程已经退出
} ngx_process_t;


// 执行二进制可执行文件
typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


// nginx最多支持1024个worker进程
#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1
#define NGX_PROCESS_JUST_SPAWN    -2

// 产生worker进程时使用此宏
#define NGX_PROCESS_RESPAWN       -3
#define NGX_PROCESS_JUST_RESPAWN  -4

// 用于执行外部程序
// 不与worker发生关系，没有channel通信
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


// 被ngx_start_worker_processes()调用，产生worker进程
// 参数proc = ngx_worker_process_cycle
// data = (void *) (intptr_t) i，即worker id
// name = "worker process"
ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);

// 执行外部程序
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);

// 初始化signals数组
ngx_int_t ngx_init_signals(ngx_log_t *log);

void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


// 在core/nginx.c ngx_save_argv()里存储命令行参数
extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

// 记录nginx 进程的pid，在main()里使用
// in os/unix/ngx_process_cycle.c
extern ngx_pid_t      ngx_pid;

// 1.13.8新增，记录父进程pid
// in os/unix/ngx_process_cycle.c
extern ngx_pid_t      ngx_parent;

// in os/unix/ngx_process.c

// 进程间通信的channel
extern ngx_socket_t   ngx_channel;

// 全局变量，用于传出创建的进程索引号
// 用在ngx_start_worker_processes()里
extern ngx_int_t      ngx_process_slot;

// 产生进程的计数器，初始值为0
// 标记数组ngx_processes的最后使用的位置，遍历用
extern ngx_int_t      ngx_last_process;

// 创建的进程都在ngx_processes数组里
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
