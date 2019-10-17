// annotated by chrono since 2016
//
// * ngx_debug_point
// * ngx_spawn_process
// * ngx_signal_handler
// * ngx_init_signals
// * ngx_process_get_status

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


// 标记unix信号，handler=ngx_signal_handler
typedef struct {
    int     signo;
    char   *signame;
    char   *name;

    // 原接口：void  (*handler)(int signo);
    // 1.13.0 变动了函数接口
    // 可以多获取一些信号的信息
    void  (*handler)(int signo, siginfo_t *siginfo, void *ucontext);
} ngx_signal_t;



static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);


// 1.13.0 变动了函数接口
// 原接口：static void ngx_signal_handler(int signo);
//
// 处理unix信号
// 收到信号后设置ngx_quit/ngx_sigalrm/ngx_reconfigue等全局变量
// 由进程里的无限循环检查这些变量再处理
// 检查子进程结束，设置进程数组ngx_processes里的状态
static void ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);

// 检查子进程结束，设置进程数组ngx_processes里的状态
static void ngx_process_get_status(void);

// 解除子进程相关的共享内存锁
static void ngx_unlock_mutexes(ngx_pid_t pid);


// 在core/nginx.c ngx_save_argv()里存储命令行参数
int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;

// 全局变量，用于传出创建的进程索引号
// 用在ngx_start_worker_processes()里
ngx_int_t        ngx_process_slot;

// 进程间通信的channel
ngx_socket_t     ngx_channel;

// 产生进程的计数器，初始值为0
// 标记数组ngx_processes的最后使用的位置，遍历用
ngx_int_t        ngx_last_process;

// 创建的进程都在ngx_processes数组里
// 此数组主要在master进程里使用
// worker进程也用来维护其他worker进程的状态信息
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];

// 命令行-s参数关联数组
// 所有信号都用ngx_signal_handler处理
ngx_signal_t  signals[] = {
    // #define NGX_RECONFIGURE_SIGNAL   HUP
    // 即sighup
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      "reload",
      ngx_signal_handler },

    // #define NGX_REOPEN_SIGNAL        USR1
    // 即sigusr1
    { ngx_signal_value(NGX_REOPEN_SIGNAL),
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      "reopen",
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
      "",
      ngx_signal_handler },

    // #define NGX_TERMINATE_SIGNAL     TERM
    // sigterm
    { ngx_signal_value(NGX_TERMINATE_SIGNAL),
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      "stop",
      ngx_signal_handler },

    // #define NGX_SHUTDOWN_SIGNAL      QUIT
    // sigquit
    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "quit",
      ngx_signal_handler },

    // ngx_config.h
    // #define NGX_CHANGEBIN_SIGNAL     USR2
    // hot upgrade, kill -s SIGUSR2 masterpid
    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      "",
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", "", ngx_signal_handler },

    { SIGINT, "SIGINT", "", ngx_signal_handler },

    { SIGIO, "SIGIO", "", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", NULL },

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", NULL },

    { 0, NULL, "", NULL }
};


// 被ngx_start_worker_processes()调用，产生worker进程
// 参数proc = ngx_worker_process_cycle
// data = (void *) (intptr_t) i，即worker id
// name = "worker process"
// respawn = NGX_PROCESS_RESPAWN 即-3
// #define NGX_PROCESS_JUST_SPAWN    -2
ngx_pid_t
ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,
    char *name, ngx_int_t respawn)
{
    u_long     on;
    ngx_pid_t  pid;
    ngx_int_t  s;

    // 决定进程在ngx_processes数组里的位置
    // 产生新进程时respawn < 0
    if (respawn >= 0) {
        s = respawn;

    } else {
        // 遍历进程数组，找到第一个“空”的位置，也就是pid无效的
        for (s = 0; s < ngx_last_process; s++) {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }

        // 序号不能超过nginx的最大值，即1024
        if (s == NGX_MAX_PROCESSES) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "no more than %d processes can be spawned",
                          NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }


    // 创建进程间通信用的channel
    if (respawn != NGX_PROCESS_DETACHED) {

        /* Solaris 9 still has no AF_LOCAL */

        // 创建socketpair，进程间通信用
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "channel %d:%d",
                       ngx_processes[s].channel[0],
                       ngx_processes[s].channel[1]);

        // 进程间通信非阻塞
        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_nonblocking_n " failed while spawning \"%s\"",
                          name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        on = 1;
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",
                           name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }

        ngx_channel = ngx_processes[s].channel[1];

    } else {
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }

    // 设置全局变量，当前进程在数组ngx_processes里的位置
    ngx_process_slot = s;


    // 调用fork产生子进程
    pid = fork();

    switch (pid) {

    // -1产生子进程出错
    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;

    // 0是子进程，开始执行worker进程的核心函数
    // ngx_worker_process_cycle，即无限循环处理事件
    case 0:
        // 1.14.0,获取父进程pid，即masterpid
        ngx_parent = ngx_pid;

        // worker进程重新获取进程id
        ngx_pid = ngx_getpid();

        // 这里是子进程的真正工作，无限循环
        // proc = ngx_worker_process_cycle
        // data = (void *) (intptr_t) i，即worker id
        proc(cycle, data);
        break;

    // 父进程得到子进程的pid
    default:
        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);

    // 把子进程的pid存入数组，记录状态
    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;

    if (respawn >= 0) {
        return pid;
    }

    // 填充worker进程的其他状态
    // name = "worker process"
    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;

    switch (respawn) {

    case NGX_PROCESS_NORESPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_SPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;

    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }

    // ngx_last_process增加，用于之后产生新进程用
    if (s == ngx_last_process) {
        ngx_last_process++;
    }

    return pid;
}


// 执行外部程序
ngx_pid_t
ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    // 产生进程执行ngx_execute_proc
    // 不与worker发生关系，没有channel通信
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name,
                             NGX_PROCESS_DETACHED);
}


static void
ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;

    // 系统调用execve()
    if (execve(ctx->path, ctx->argv, ctx->envp) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "execve() failed while executing %s \"%s\"",
                      ctx->name, ctx->path);
    }

    exit(1);
}


// 初始化signals数组
ngx_int_t
ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        ngx_memzero(&sa, sizeof(struct sigaction));

        // 设置信号处理函数
        // 大多是ngx_signal_handler
        if (sig->handler) {
            sa.sa_sigaction = sig->handler;
            sa.sa_flags = SA_SIGINFO;

        } else {
            sa.sa_handler = SIG_IGN;
        }

        sigemptyset(&sa.sa_mask);

        // 安装信号处理函数
        if (sigaction(sig->signo, &sa, NULL) == -1) {
#if (NGX_VALGRIND)
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          "sigaction(%s) failed, ignored", sig->signame);
#else
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                          "sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
#endif
        }
    }

    return NGX_OK;
}


// 1.13.0 变动了函数接口
// static void ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext);
//
// 处理unix信号
// 收到信号后设置ngx_quit/ngx_sigalrm/ngx_reconfigue等全局变量
// 由进程里的无限循环检查这些变量再处理
// 检查子进程结束，设置进程数组ngx_processes里的状态
static void
ngx_signal_handler(int signo, siginfo_t *siginfo, void *ucontext)
{
    char            *action;
    ngx_int_t        ignore;
    ngx_err_t        err;
    ngx_signal_t    *sig;

    ignore = 0;

    err = ngx_errno;

    // 遍历信号数组，因为数量少，所以不太影响效率
    for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }

    ngx_time_sigsafe_update();

    action = "";

    switch (ngx_process) {

    // master/single进程可以处理的信号
    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {

        // 优雅关闭, -s quit
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        // 直接关闭, -s stop
        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (ngx_daemonized) {
                ngx_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;

        // 重新加载配置文件, -s reload
        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;

        // 重新打开文件， -s reopen
        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        // hot upgrade, kill -s SIGUSR2 masterpid
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            if (ngx_getppid() == ngx_parent || ngx_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not changed, i.e. the old binary's process is still
                 * running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }

            // 标志位，热更新二进制文件
            ngx_change_binary = 1;
            action = ", changing binary";
            break;

        // SIGALRM,更新时间
        case SIGALRM:
            ngx_sigalrm = 1;
            break;

        case SIGIO:
            ngx_sigio = 1;
            break;

        // 子进程结束，可能发生了意外
        case SIGCHLD:
            // 将导致master进程ngx_master_process_cycle()调用ngx_reap_children()
            // 重新产生子进程
            ngx_reap = 1;
            break;
        }

        break;

    // worker能够处理的信号较少
    case NGX_PROCESS_WORKER:
    case NGX_PROCESS_HELPER:
        switch (signo) {

        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (!ngx_daemonized) {
                break;
            }
            ngx_debug_quit = 1;

            /* fall through */

        // 优雅关闭, -s quit
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;

        // 直接关闭, -s stop
        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;

        // 重新打开文件， -s reopen
        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;

        // 重新加载配置文件, -s reload
        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }

        break;
    }

    if (siginfo && siginfo->si_pid) {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                      "signal %d (%s) received from %P%s",
                      signo, sig->signame, siginfo->si_pid, action);

    } else {
        ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                      "signal %d (%s) received%s",
                      signo, sig->signame, action);
    }

    if (ignore) {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }

    // 父进程收到了子进程结束的信号
    if (signo == SIGCHLD) {
        ngx_process_get_status();
    }

    ngx_set_errno(err);
}


// 检查子进程结束，设置进程数组ngx_processes里的状态
static void
ngx_process_get_status(void)
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;

    for ( ;; ) {
        // 系统调用，获得结束的子进程
        // WNOHANG 若pid指定的子进程没有结束，则waitpid()函数返回0，不予以等待。
        // 若结束，则返回该子进程的ID。
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        one = 1;
        process = "unknown process";

        // 在进程数组里找到结束的进程
        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {

                // 设置结束进程的结束状态
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        // WTERMSIG宏测试被执行后，若成功返回被终止的子进程的信号值。
        // 只记录log，无其他动作
        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        // 获取子进程的非正常返回值
        // 如果worker进程使用exit(2)，那么不重启子进程
        // 在master cycle里的ngx_reap里判断
        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }

        // 解除子进程相关的共享内存锁
        ngx_unlock_mutexes(pid);
    }
}


// 解除子进程相关的共享内存锁
static void
ngx_unlock_mutexes(ngx_pid_t pid)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;
    ngx_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    // accept锁
    if (ngx_accept_mutex_ptr) {
        (void) ngx_shmtx_force_unlock(&ngx_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    // 共享内存里的锁
    part = (ngx_list_part_t *) &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        sp = (ngx_slab_pool_t *) shm_zone[i].shm.addr;

        if (ngx_shmtx_force_unlock(&sp->mutex, pid)) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


// debug断点时的动作，停止或是直接core
void
ngx_debug_point(void)
{
    ngx_core_conf_t  *ccf;

    // 取核心配置
    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    // stop，使用stop信号停止运行
    // 之后可以用gdb调试
    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    // 直接abort
    // 产生coredump，再用gdb调试
    case NGX_DEBUG_POINTS_ABORT:
        // ngx_config.h:#define ngx_abort       abort
        ngx_abort();
    }

    // 其他则无动作，不会有任何影响
}


// 被ngx_cycle.c里的ngx_signal_process()调用
// 发送reload/stop等信号
ngx_int_t
ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_pid_t pid)
{
    ngx_signal_t  *sig;

    // 字符串比较，找到对应的信号，调用kill发送
    // signals是本文件前面定义的一个数组
    for (sig = signals; sig->signo != 0; sig++) {
        if (ngx_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
