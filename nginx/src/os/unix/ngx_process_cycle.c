// annotated by chrono since 2016
//
// * ngx_master_process_cycle
// * ngx_single_process_cycle
// * ngx_worker_process_cycle
// * ngx_signal_worker_processes
// * ngx_worker_process_init
// * ngx_reap_children

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


// 被ngx_master_process_cycle()调用
// 启动worker进程，数量由配置决定，即worker_processes指令
// 调用时传递的是#define NGX_PROCESS_RESPAWN       -3
static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
    ngx_int_t type);

// cache相关的暂不研究
static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle,
    ngx_uint_t respawn);

static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch);

// master进程调用，遍历ngx_processes数组，用kill发送信号
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);

// 重新产生子进程
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);

// 删除pid，模块清理，关闭监听端口
static void ngx_master_process_exit(ngx_cycle_t *cycle);

// 传递给ngx_spawn_process()，是worker进程的核心功能
// 调用ngx_worker_process_init()/ngx_worker_process_exit()
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);

// 读取核心配置，设置cpu优先级,core dump信息,unix运行的group/user
// 切换工作路径,根据pid设置随机数种子
// 调用所有模块的init_process,让模块进程初始化
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker);

// 被ngx_worker_process_cycle()调用
// 调用所有模块的exit_process，进程结束hook
// 内部直接exit(0)退出
static void ngx_worker_process_exit(ngx_cycle_t *cycle);

// 处理channel发送来的消息
static void ngx_channel_handler(ngx_event_t *ev);

// cache相关的暂不研究
static void ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_cache_manager_process_handler(ngx_event_t *ev);
static void ngx_cache_loader_process_handler(ngx_event_t *ev);


// 标记nginx进程的状态
// NGX_PROCESS_MASTER/NGX_PROCESS_WORKER/NGX_PROCESS_SINGLE
// 一开始是0，也就是NGX_PROCESS_SINGLE
ngx_uint_t    ngx_process;

// nginx 1.9.x增加新全局变量ngx_worker，即进程id号
// 从0开始计数，至ccf->worker_processes
ngx_uint_t    ngx_worker;

// 记录master/worker进程的pid
// master在main()里获取
// worker在fork之后重新获取
ngx_pid_t     ngx_pid;

// 1.13.8，父进程的pid
// worker在fork之后重新获取
ngx_pid_t     ngx_parent;

// 原子变量，用于进程中检查信号
sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_sigalrm;      //更新时间的信号
sig_atomic_t  ngx_terminate;    //结束进程
sig_atomic_t  ngx_quit;         //处理完所有请求再结束进程
sig_atomic_t  ngx_debug_quit;
ngx_uint_t    ngx_exiting;      //nginx进程正在退出过程中
sig_atomic_t  ngx_reconfigure;  //重新加载配置文件，也就是reload
sig_atomic_t  ngx_reopen;       //重新打开所有文件

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


// master进程的名字
static u_char  master_process[] = "master process";


static ngx_cache_manager_ctx_t  ngx_cache_manager_ctx = {
    ngx_cache_manager_process_handler, "cache manager process", 0
};

static ngx_cache_manager_ctx_t  ngx_cache_loader_ctx = {
    ngx_cache_loader_process_handler, "cache loader process", 60000
};


static ngx_cycle_t      ngx_exit_cycle;
static ngx_log_t        ngx_exit_log;
static ngx_open_file_t  ngx_exit_log_file;


// main()函数里调用，启动worker进程
// 监听信号
// 核心操作是sigsuspend，暂时挂起进程，不占用CPU，只有收到信号时才被唤醒
void
ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    ngx_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_listening_t   *ls;
    ngx_core_conf_t   *ccf;

    // 添加master进程关注的信号
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    // 阻塞信号，避免信号丢失
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    // 信号集清空
    sigemptyset(&set);


    // static u_char  master_process[] = "master process";
    // 计算master进程的名字
    size = sizeof(master_process);

    // 加上命令行参数，注意使用的是nginx拷贝后的参数
    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    // 分配名字的内存
    title = ngx_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    // 拷贝字符串
    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ngx_argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
    }

    // 设置进程名
    ngx_setproctitle(title);


    // 取core模块配置
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // 启动worker进程，数量由配置决定，即worker_processes指令
    // #define NGX_PROCESS_RESPAWN       -3
    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);

    // cache进程
    ngx_start_cache_manager_processes(cycle, 0);

    ngx_new_binary = 0;
    delay = 0;      //延时的计数器
    sigio = 0;
    live = 1;       //是否有存活的子进程

    // master进程的无限循环，只处理信号
    // 主要调用ngx_signal_worker_processes()发送信号
    // ngx_start_worker_processes()产生新子进程
    for ( ;; ) {
        // 延时等待子进程关闭，每次进入加倍等待
        if (delay) {
            if (ngx_sigalrm) {
                sigio = 0;
                delay *= 2;     //延时加倍
                ngx_sigalrm = 0;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            // 系统调用，设置发送SIGALRM的时间间隔
            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        // 核心操作是sigsuspend，暂时挂起进程，不占用CPU，只有收到信号时才被唤醒
        // 收到SIGALRM就检查子进程是否都已经处理完了
        sigsuspend(&set);

        // 更新一下时间
        ngx_time_update();

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "wake up, sigio %i", sigio);

        // 子进程可能发生了意外结束
        // 在os/unix/ngx_process.c ngx_signal_handler()里设置
        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            // 重新产生子进程
            live = ngx_reap_children(cycle);
        }

        // 无存活子进程且收到stop/quit信号
        if (!live && (ngx_terminate || ngx_quit)) {
            // 删除pid，模块清理，关闭监听端口
            // 内部直接exit(0)退出
            ngx_master_process_exit(cycle);
        }

        // 收到了-s stop，停止进程
        if (ngx_terminate) {
            // 延时等待子进程关闭
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            if (delay > 1000) {
                // 超时太多，直接发送SIGKILL杀死进程
                // master进程调用，遍历ngx_processes数组，用kill发送信号
                ngx_signal_worker_processes(cycle, SIGKILL);
            } else {
                // master进程调用，遍历ngx_processes数组，用kill发送信号
                // 走到worker进程的ngx_signal_handler()
                // 然后再是ngx_worker_process_cycle()的ngx_terminate
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            // 等待SIGALRM信号，检查子进程是否都结束
            continue;
        }

        // 收到了-s quit，关闭监听端口后再停止进程（优雅关闭）
        if (ngx_quit) {
            // master进程调用，遍历ngx_processes数组，用kill发送信号
            // 走到worker进程的ngx_signal_handler()
            // 然后再是ngx_worker_process_cycle()的ngx_quit
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

            // 关闭所有监听端口
            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (ngx_close_socket(ls[n].fd) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;

            continue;
        }

        // 收到了-s reload重新配置
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;

            // 启动新的nginx二进制
            if (ngx_new_binary) {
                // 启动worker进程，数量由配置决定，即worker_processes指令
                // 调用时传递的是#define NGX_PROCESS_RESPAWN       -3
                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_RESPAWN);
                ngx_start_cache_manager_processes(cycle, 0);
                ngx_noaccepting = 0;

                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            // nginx可执行程序不变，以当前cycle重新初始化
            // 重新读取加载配置文件，并拷贝当前cycle的一些数据
            // 如端口、日志文件、共享内存等
            cycle = ngx_init_cycle(cycle);

            // 可能配置文件不正确，初始化失败
            // 使用原有的cycle继续运行，不会停止服务
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            // ngx_cycle指针指向新的cycle
            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);

            // 启动worker进程，数量由配置决定，即worker_processes指令
            // 调用时传递的是#define NGX_PROCESS_JUST_RESPAWN       -2
            // 这样新启动的进程不会发送shutdown信号
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            // 阻塞等待100毫秒
            ngx_msleep(100);

            // 设置进程存活标志
            live = 1;

            // 关闭原来的worker进程
            // 新启动的进程不会发送shutdown信号
            // master进程调用，遍历ngx_processes数组，用kill发送信号
            // 走到worker进程的ngx_signal_handler()
            // 然后再是ngx_worker_process_cycle()的ngx_quit
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_restart) {
            ngx_restart = 0;

            // 启动worker进程，数量由配置决定，即worker_processes指令
            // 调用时传递的是#define NGX_PROCESS_RESPAWN       -3
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 0);

            // 设置进程存活标志
            live = 1;
        }

        // sigusr1， 重新打开日志文件，用来rotate日志
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));
        }

        // 热更新nginx可执行文件
        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");

            // 函数在core/nginx.c里
            ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
        }

        // 停止监听端口
        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    }   //master进程无限循环结束
}


// main()函数里调用，仅启动一个进程，没有fork
// master_process off;
void
ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    // 调用所有模块的init_process，即进程启动时hook
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    // 无限循环，对外提供服务
    // ngx_signal_handler处理unix信号
    // 收到信号后设置ngx_quit/ngx_sigalrm/ngx_reconfigue等全局变量
    // 由无限循环检查这些变量再处理
    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        // 处理事件的核心函数, event模块里
        // 处理socket读写事件和定时器事件
        // 获取负载均衡锁，监听端口接受连接
        // 调用epoll模块的ngx_epoll_process_events
        // 然后处理超时事件和在延后队列里的所有事件
        // nginx大部分的工作量都在这里
        ngx_process_events_and_timers(cycle);

        // 检查是否处于退出状态
        // 这里不使用ngx_exiting变量，直接关闭端口退出
        if (ngx_terminate || ngx_quit) {

            // 所有模块的退出hook
            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            // 删除pid，模块清理，关闭监听端口
            // 内部直接exit(0)退出
            ngx_master_process_exit(cycle);
        }

        // 重新配置，以当前cycle重新初始化，即reload
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;    //标志量清零
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            // 以当前cycle重新初始化
            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            // ngx_cycle指针指向新的cycle
            ngx_cycle = cycle;
        }

        // 重新打开所有文件
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    } // 无限循环，对外提供服务
}


// 被ngx_master_process_cycle()调用
// 启动worker进程，数量由配置决定，即worker_processes指令
// 调用时传递的是#define NGX_PROCESS_RESPAWN       -3
static void
ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
{
    ngx_int_t      i;
    ngx_channel_t  ch;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    // unix channel
    ch.command = NGX_CMD_OPEN_CHANNEL;

    for (i = 0; i < n; i++) {

        // os/unix/ngx_process.c产生进程，执行ngx_worker_process_cycle
        // 创建的进程都在ngx_processes数组里
        // 定义在os/unix/ngx_process.c
        // ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];
        ngx_spawn_process(cycle, ngx_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        // 设置channel信息
        ch.pid = ngx_processes[ngx_process_slot].pid;
        ch.slot = ngx_process_slot;
        ch.fd = ngx_processes[ngx_process_slot].channel[0];

        // 建立channel，用于进程间通信
        ngx_pass_open_channel(cycle, &ch);
    }
}


static void
ngx_start_cache_manager_processes(ngx_cycle_t *cycle, ngx_uint_t respawn)
{
    ngx_uint_t       i, manager, loader;
    ngx_path_t     **path;
    ngx_channel_t    ch;

    manager = 0;
    loader = 0;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            manager = 1;
        }

        if (path[i]->loader) {
            loader = 1;
        }
    }

    if (manager == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_manager_ctx, "cache manager process",
                      respawn ? NGX_PROCESS_JUST_RESPAWN : NGX_PROCESS_RESPAWN);

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);

    if (loader == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_loader_ctx, "cache loader process",
                      respawn ? NGX_PROCESS_JUST_SPAWN : NGX_PROCESS_NORESPAWN);

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);
}


// 建立channel，用于进程间通信
static void
ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch)
{
    ngx_int_t  i;

    // 遍历进程数组，逐个发送子进程消息
    for (i = 0; i < ngx_last_process; i++) {

        // 新子进程，结束的子进程不发送
        if (i == ngx_process_slot
            || ngx_processes[i].pid == -1
            || ngx_processes[i].channel[0] == -1)
        {
            continue;
        }

        ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch->slot, ch->pid, ch->fd,
                      i, ngx_processes[i].pid,
                      ngx_processes[i].channel[0]);

        /* TODO: NGX_AGAIN */

        // 发送信息
        // 在其他进程的ngx_channel_handler里处理
        ngx_write_channel(ngx_processes[i].channel[0],
                          ch, sizeof(ngx_channel_t), cycle->log);
    }
}


// master进程调用，遍历ngx_processes数组，用kill发送信号
// 但通常是使用channel(socket pair)发送信号
static void
ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

#if (NGX_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    // 把信号转换为nginx自己的channel命令
    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    // 遍历ngx_processes数组，用kill发送信号
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        // 无效的进程直接跳过
        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

        // 新启动的进程不会发送信号
        if (ngx_processes[i].just_spawn) {
            ngx_processes[i].just_spawn = 0;
            continue;
        }

        // 正在退出的进程不会发送信号
        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        // 通常是使用channel发送信号
        if (ch.command) {
            // channel发送成功就不会走下面的kill发送
            if (ngx_write_channel(ngx_processes[i].channel[0],
                                  &ch, sizeof(ngx_channel_t), cycle->log)
                == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;
                }

                // 跳过下面的kill发送代码
                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", ngx_processes[i].pid, signo);

        // kill发送信号
        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}


// 重新产生子进程
static ngx_uint_t
ngx_reap_children(ngx_cycle_t *cycle)
{
    ngx_int_t         i, n;
    ngx_uint_t        live;
    ngx_channel_t     ch;
    ngx_core_conf_t  *ccf;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;

    // 遍历进程数组，检查所有有效的进程
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        // -1表示进程无效，忽略
        if (ngx_processes[i].pid == -1) {
            continue;
        }

        // 找到被意外结束的进程
        // ngx_process_get_status()里设置, os/unix/ngx_process.c
        if (ngx_processes[i].exited) {

            if (!ngx_processes[i].detached) {
                // 清理进程相关的channel信息
                ngx_close_channel(ngx_processes[i].channel, cycle->log);

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < ngx_last_process; n++) {
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, ngx_processes[n].pid);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

            // 检查respawn，如果是异常结束则不重启子进程
            if (ngx_processes[i].respawn
                // 已经发送信号正在退出，不能重启
                && !ngx_processes[i].exiting

                // master进程也不能是退出状态
                && !ngx_terminate
                && !ngx_quit)
            {
                // 使用进程数组里保存的信息重新产生新的进程
                // 仍然在原来的位置
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                      ngx_processes[i].data,
                                      ngx_processes[i].name, i)
                    == NGX_INVALID_PID)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                  "could not respawn %s",
                                  ngx_processes[i].name);
                    continue;
                }


                // 创建子进程成功，设置channle信息，通知其他worker
                ch.command = NGX_CMD_OPEN_CHANNEL;
                ch.pid = ngx_processes[ngx_process_slot].pid;
                ch.slot = ngx_process_slot;
                ch.fd = ngx_processes[ngx_process_slot].channel[0];

                // 建立channel，用于进程间通信
                ngx_pass_open_channel(cycle, &ch);

                live = 1;

                continue;
            }

            // 不重启进程，其他处理

            // 检查是不是new_binary进程
            if (ngx_processes[i].pid == ngx_new_binary) {

                ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                       ngx_core_module);

                if (ngx_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == NGX_FILE_ERROR)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                  ngx_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
                }

                ngx_new_binary = 0;
                if (ngx_noaccepting) {
                    ngx_restart = 1;
                    ngx_noaccepting = 0;
                }
            }

            // 其他情况，进程数量减少

            // 最后一个，末尾计数器减少
            if (i == ngx_last_process - 1) {
                ngx_last_process--;

            } else {
                // 中间的某个进程，置为无效pid
                ngx_processes[i].pid = -1;
            }

        // 非exited，正在退出状态
        } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


// 删除pid，模块清理，关闭监听端口
// 内部直接exit(0)退出
static void
ngx_master_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    // in ngx_connection.c
    // 遍历监听端口列表，逐个删除监听事件
    ngx_close_listening_sockets(cycle);

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */


    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    exit(0);
}


// 传递给ngx_spawn_process()，是worker进程的核心功能
// data实际上是进程号, (void *) (intptr_t) i
static void
ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    // 把data再转换为进程序号
    ngx_int_t worker = (intptr_t) data;

    // 设置进程状态
    ngx_process = NGX_PROCESS_WORKER;

    // 这里把进程号赋值给全局变量
    ngx_worker = worker;

    // nginx 1.9.x
    //ngx_worker = worker;

    // 读取核心配置，设置cpu优先级,core dump信息,unix运行的group/user
    // 切换工作路径,根据pid设置随机数种子
    // 调用所有模块的init_process,让模块进程初始化
    ngx_worker_process_init(cycle, worker);

    // 设置进程名字
    // 这里可以改进一下，增加workerid，或者其他特殊标记
    // 例如设置一个特殊的32字节字符串
    // 注意是在init_worker阶段之后，所以模块的init_process操作是无效的
    // 可以在init_process里放个定时器，在稍后的时刻操作
    ngx_setproctitle("worker process");

    // 无限循环，处理事件和信号
    for ( ;; ) {

        // 进程正在退出,即quit
        // 收到了-s quit，关闭监听端口后再停止进程（优雅关闭）
        if (ngx_exiting) {
            // 1.11.11之前
            // 取消定时器，调用handler处理
            // ngx_event_cancel_timers();
            // if (ngx_event_timer_rbtree.root == ngx_event_timer_rbtree.sentinel)
            //
            // 1.11.11改成了ngx_event_no_timers_left()
            // 解决了"is shutting down"进程的问题

            // 定时器红黑树为空，即已经没有任何事件
            // 否则表示还有事件未处理，暂不退出
            if (ngx_event_no_timers_left() == NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");

                // 调用所有模块的exit_process，进程结束hook
                // 内部直接exit(0)退出
                ngx_worker_process_exit(cycle);
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        // 处理事件的核心函数, event模块里
        // 处理socket读写事件和定时器事件
        // 获取负载均衡锁，监听端口接受连接
        // 调用epoll模块的ngx_epoll_process_events
        // 然后处理超时事件和在延后队列里的所有事件
        // nginx大部分的工作量都在这里
        ngx_process_events_and_timers(cycle);

        // 收到了-s stop，直接停止进程
        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");

            // 调用所有模块的exit_process，进程结束hook
            // 内部直接exit(0)退出
            ngx_worker_process_exit(cycle);
        }

        // 收到了-s quit，关闭监听端口后再停止进程（优雅关闭）
        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");

            // 改进程名字
            ngx_setproctitle("worker process is shutting down");

            if (!ngx_exiting) {
                // 这里1.10的代码与1.8.1不同

                // 设置ngx_exiting标志，继续走循环
                // 等所有事件都处理完了才能真正退出
                ngx_exiting = 1;

                // 1.11.11新增
                // 设置关闭的定时器，由指令worker_shutdown_timeout确定
                ngx_set_shutdown_timer(cycle);

                // in ngx_connection.c
                // 遍历监听端口列表，逐个删除监听事件
                // 不再接受新的连接请求
                ngx_close_listening_sockets(cycle);

                ngx_close_idle_connections(cycle);

            }
        }

        // 收到了-s reopen，重新打开文件
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }
    } // 无限循环，处理事件和信号
}


// 被ngx_worker_process_cycle()调用
// 参数worker是进程的序号
// 设置cpu优先级,core dump信息,unix运行的group/user
// 切换工作路径,根据pid设置随机数种子
// 调用所有模块的init_process,让模块进程初始化
static void
ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker)
{
    sigset_t          set;
    ngx_int_t         n;
    ngx_time_t       *tp;
    ngx_uint_t        i;
    ngx_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    ngx_core_conf_t  *ccf;
    ngx_listening_t  *ls;

    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    // 获取核心配置
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // 设置cpu优先级
    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

    // 设置core dump信息
    if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    // 设置unix运行的group/user
    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

#if (NGX_HAVE_PR_SET_KEEPCAPS && NGX_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }

#if (NGX_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            ngx_memzero(&header, sizeof(struct __user_cap_header_struct));
            ngx_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    // 绑定cpu
    if (worker >= 0) {
        // 根据worker id得到cpu掩码
        // 由指令worker_cpu_affinity确定
        cpu_affinity = ngx_get_cpu_affinity(worker);

        // 绑定cpu
        if (cpu_affinity) {
            ngx_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (NGX_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    // 切换工作路径
    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    // 根据pid设置随机数种子
    // 旧实现：srandom((ngx_pid << 16) ^ ngx_time());
    tp = ngx_timeofday();
    srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    // 调用所有模块的init_process,模块进程初始化hook
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    // 初始化worker进程的进程数组
    for (n = 0; n < ngx_last_process; n++) {

        if (ngx_processes[n].pid == -1) {
            continue;
        }

        // 本进程的不处理
        if (n == ngx_process_slot) {
            continue;
        }

        if (ngx_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(ngx_processes[n].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "close() channel failed");
        }
    }

    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() channel failed");
    }

#if 0
    ngx_last_process = 0;
#endif

    // epoll处理channel消息，调用ngx_channel_handler
    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                              ngx_channel_handler)
        == NGX_ERROR)
    {
        /* fatal */
        exit(2);
    }
}


// 被ngx_worker_process_cycle()调用
// 调用所有模块的exit_process，进程结束hook
// 内部直接exit(0)退出
static void
ngx_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

    // 调用所有模块的exit_process，进程结束hook
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    // 检查是否还有未关闭的连接
    // 有则需要debug，断点检查
    if (ngx_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
                ngx_debug_quit = 1;
            }
        }

        if (ngx_debug_quit) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "aborting");
            ngx_debug_point();
        }
    }

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */

    // ngx_cycle指向ngx_exit_cycle，生命期结束
    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "exit");

    exit(0);
}


// epoll处理channel消息，调用ngx_channel_handler
static void
ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

        // 读取消息
        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NGX_ERROR) {

            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
                ngx_del_conn(c, 0);
            }

            ngx_close_connection(c);
            return;
        }

        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return;
            }
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        // 区分消息的类型
        switch (ch.command) {

        // 发送了quit，相当于kill -s quit
        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;

        // 发送了term，相当于kill -s stop
        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;

        // 重新打开日志文件
        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        // 有子进程重启
        case NGX_CMD_OPEN_CHANNEL:

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            // 在进程数组里填写对应的pid等信息
            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;

        // 有子进程关闭
        case NGX_CMD_CLOSE_CHANNEL:

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                           ngx_processes[ch.slot].channel[0]);

            if (close(ngx_processes[ch.slot].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "close() channel failed");
            }

            ngx_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}


static void
ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    ngx_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    ngx_process = NGX_PROCESS_HELPER;

    ngx_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    // 读取核心配置，设置cpu优先级,core dump信息,unix运行的group/user
    // 切换工作路径,根据pid设置随机数种子
    // 调用所有模块的init_process,让模块进程初始化
    ngx_worker_process_init(cycle, -1);

    ngx_memzero(&ev, sizeof(ngx_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    ngx_use_accept_mutex = 0;

    ngx_setproctitle(ctx->name);

    ngx_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        // 处理事件的核心函数, event模块里
        // 处理socket读写事件和定时器事件
        // 获取负载均衡锁，监听端口接受连接
        // 调用epoll模块的ngx_epoll_process_events
        // 然后处理超时事件和在延后队列里的所有事件
        // nginx大部分的工作量都在这里
        ngx_process_events_and_timers(cycle);
    }
}


static void
ngx_cache_manager_process_handler(ngx_event_t *ev)
{
    ngx_uint_t    i;
    ngx_msec_t    next, n;
    ngx_path_t  **path;

    next = 60 * 60 * 1000;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            ngx_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    ngx_add_timer(ev, next);
}


static void
ngx_cache_loader_process_handler(ngx_event_t *ev)
{
    ngx_uint_t     i;
    ngx_path_t   **path;
    ngx_cycle_t   *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (ngx_terminate || ngx_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            ngx_time_update();
        }
    }

    exit(0);
}
