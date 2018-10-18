// annotated by chrono since 2016
//
// * main
// * ngx_process_options
// * ngx_get_options

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>


// 显示帮助信息，1.10增加-T，可以dump整个配置文件
static void ngx_show_version_info(void);

// 检查NGINX环境变量，获取之前监听的socket
static ngx_int_t ngx_add_inherited_sockets(ngx_cycle_t *cycle);

// 1.11.x新增函数
static void ngx_cleanup_environment(void *data);

// nginx自己实现的命令行参数解析
static ngx_int_t ngx_get_options(int argc, char *const *argv);

// 设置cycle->prefix/cycle->conf_prefix等成员
static ngx_int_t ngx_process_options(ngx_cycle_t *cycle);

// 保存命令行参数到全局变量ngx_argc/ngx_argv
static ngx_int_t ngx_save_argv(ngx_cycle_t *cycle, int argc, char *const *argv);

// ngx_core_module的函数指针表，创建配置结构体
static void *ngx_core_module_create_conf(ngx_cycle_t *cycle);
static char *ngx_core_module_init_conf(ngx_cycle_t *cycle, void *conf);

// 解析user等核心配置指令
static char *ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_env(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 设置绑定cpu的掩码
static char *ngx_set_cpu_affinity(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_set_worker_processes(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 1.10新的动态模块特性，调用dlopen
// 加载动态模块的指令
// 不能在http/event里使用，而且要在http/event之前
// 否则会因为modules_used不允许加载动态模块
//
// 打开动态库文件
// 设置内存池销毁时的清理动作，关闭动态库
// 使用"ngx_modules"取动态库里的模块数组
// 使用"ngx_module_names"取动态库里的模块名字数组
// 使用"ngx_module_order"取动态库里的模块顺序数组
// 模块顺序只对http filter模块有意义
// 所以可以没有，不需要检查
// 遍历动态库里的模块数组
// 流程类似ngx_preinit_modules
// 调用ngx_add_module添加模块
static char *ngx_load_module(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 调用dlclose关闭动态库
// #define ngx_dlclose(handle)        dlclose(handle)
#if (NGX_HAVE_DLOPEN)
static void ngx_unload_module(void *data);
#endif


// debug point枚举定义，宏的定义在ngx_cycle.h
// in ngx_process.c ngx_debug_point
static ngx_conf_enum_t  ngx_debug_points[] = {
    { ngx_string("stop"), NGX_DEBUG_POINTS_STOP },
    { ngx_string("abort"), NGX_DEBUG_POINTS_ABORT },
    { ngx_null_string, 0 }
};


// ngx_core_module定义的核心指令，都在main域配置
// 配置结构体是ngx_core_conf_t，定义在ngx_cycle.h
static ngx_command_t  ngx_core_commands[] = {

    // 守护进程, on/off
    { ngx_string("daemon"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_core_conf_t, daemon),
      NULL },

    // 启动master/worker进程机制, on/off
    { ngx_string("master_process"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_core_conf_t, master),
      NULL },

    // nginx更新缓存时间的精度，如果设置了会定时发送sigalarm信号更新时间
    // ngx_timer_resolution = ccf->timer_resolution;默认值是0
    { ngx_string("timer_resolution"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_core_conf_t, timer_resolution),
      NULL },

    // pid文件的存放位置
    { ngx_string("pid"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_core_conf_t, pid),
      NULL },

    // 用于实现共享锁，linux下无意义
    { ngx_string("lock_file"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_core_conf_t, lock_file),
      NULL },

    // 启动worker进程，数量由配置决定，即worker_processes指令
    // ngx_start_worker_processes(cycle, ccf->worker_processes,
    //                           NGX_PROCESS_RESPAWN);
    { ngx_string("worker_processes"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_set_worker_processes,
      0,
      0,
      NULL },

    { ngx_string("debug_points"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,                   //特殊的set_enum函数
      0,
      offsetof(ngx_core_conf_t, debug_points),
      &ngx_debug_points },

    //设置user
    { ngx_string("user"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE12,
      ngx_set_user,
      0,
      0,
      NULL },

    { ngx_string("worker_priority"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_set_priority,
      0,
      0,
      NULL },

    // 设置绑定cpu的掩码
    { ngx_string("worker_cpu_affinity"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
      ngx_set_cpu_affinity,
      0,
      0,
      NULL },

    // RLIMIT_NOFILE,进程可打开的最大文件描述符数量，超出将产生EMFILE错误
    // 在ngx_event_module_init里检查
    { ngx_string("worker_rlimit_nofile"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_core_conf_t, rlimit_nofile),
      NULL },

    // coredump文件最大长度
    { ngx_string("worker_rlimit_core"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      0,
      offsetof(ngx_core_conf_t, rlimit_core),
      NULL },

    { ngx_string("worker_shutdown_timeout"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_core_conf_t, shutdown_timeout),
      NULL },

    // coredump文件的存放路径
    { ngx_string("working_directory"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_core_conf_t, working_directory),
      NULL },

    { ngx_string("env"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_set_env,
      0,
      0,
      NULL },

    // old threads 在1.9.x里已经被删除，不再使用

    // 加载动态模块的指令
    // 不能在http/event里使用，而且要在http/event之前
    // 否则会因为modules_used不允许加载动态模块
    { ngx_string("load_module"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_load_module,
      0,
      0,
      NULL },

      ngx_null_command
};


// ngx_core_module的函数指针表，创建配置结构体
// 两个函数都在本文件内,只是简单地创建并初始化成员
static ngx_core_module_t  ngx_core_module_ctx = {
    ngx_string("core"),
    ngx_core_module_create_conf,        //创建配置结构体
    ngx_core_module_init_conf           //初始化结构体参数
};


// ngx_core_module模块定义，指定指令集和函数指针表
ngx_module_t  ngx_core_module = {
    NGX_MODULE_V1,
    &ngx_core_module_ctx,                  /* module context */
    ngx_core_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 1.10引入动态模块后此变量不再使用
// 模块计数器，声明在ngx_conf_file.h, 在main里统计得到总数
// ngx_uint_t          ngx_max_module;

// 解析命令行的标志变量,ngx_get_options()设置
// 仅在本文件里使用，woker等进程无关
static ngx_uint_t   ngx_show_help;          // 显示帮助信息
static ngx_uint_t   ngx_show_version;       // 显示版本信息
static ngx_uint_t   ngx_show_configure;     // 显示编译配置信息

// 启动时的参数,ngx_get_options()设置
// 仅在本文件里使用，woker等进程无关
// 前三个是u_char是因为要赋值给ngx_str_t
// ngx_signal用char*是因为要做字符串比较，不需要存储
static u_char      *ngx_prefix;             // -p参数，工作路径
static u_char      *ngx_conf_file;          // -c参数，配置文件
static u_char      *ngx_conf_params;        // -g参数
static char        *ngx_signal;             // -s参数，unix信号, stop/quit/reload/reopen/


static char **ngx_os_environ;


// nginx启动的入口函数
// 相关文件ngx_process_cycle.c/ngx_posix_init.c/ngx_process.c
// 设置重要的指针volatile ngx_cycle_t  *ngx_cycle;
//
// 1)解析命令行参数,显示帮助信息
// 2)初始化操作系统调用接口函数ngx_os_io = ngx_linux_io;
// 3)根据命令行参数等建立一个基本的cycle
// 4)初始化模块数组ngx_modules
// 5)核心操作，调用ngx_init_cycle创建进程使用的cycle,解析配置文件,启动监听端口
// 6)启动单进程或多进程
int ngx_cdecl
main(int argc, char *const *argv)
{
    ngx_buf_t        *b;
    ngx_log_t        *log;
    ngx_uint_t        i;
    ngx_cycle_t      *cycle, init_cycle;    //cycle结构体
    ngx_conf_dump_t  *cd;
    ngx_core_conf_t  *ccf;      //获得ngx_core_module的配置结构体

    ngx_debug_init();

    if (ngx_strerror_init() != NGX_OK) {
        return 1;
    }

    // 解析命令行参数, 本文件内查找ngx_get_options
    // 设置ngx_show_version/ngx_show_help等变量
    if (ngx_get_options(argc, argv) != NGX_OK) {
        return 1;
    }

    // 1.9.x改到ngx_show_version_info()
    if (ngx_show_version) {

        // 显示帮助信息，1.10增加-T，可以dump整个配置文件
        ngx_show_version_info();

        // 1.9.x ngx_show_version_info()结束

        if (!ngx_test_config) {     //如果是-t参数，那么接下来要走流程检查配置但不启动
            return 0;
        }
    }

    // 在ngx_os_init函数里设置（os/unix/ngx_posix_init.c）
    // 使用系统调用getrlimit(RLIMIT_NOFILE, &rlmt)
    // 是nginx能够打开的最多描述数量，但似乎并没有使用
    /* TODO */ ngx_max_sockets = -1;

    // ngx_times.c,初始化各个cache时间变量
    // 调用ngx_time_update()，得到当前的时间
    ngx_time_init();

#if (NGX_PCRE)
    ngx_regex_init();       // 正则表达式库初始化
#endif

    // 定义在os/unix/ngx_process_cycle.c : ngx_pid_t     ngx_pid;
    // ngx_process.h : #define ngx_getpid   getpid
    // 获取当前进程也就是master进程的pid
    // 如果是master/worker，会fork出新的子进程，见os/unix/ngx_daemon.c
    ngx_pid = ngx_getpid();

    // 1.13.8新增,父进程pid
    ngx_parent = ngx_getppid();

    // 初始化log，仅在配置阶段使用
    // ngx_prefix是-p后的参数，即nginx的工作目录
    // 默认是NGX_CONF_PREFIX，即/usr/local/nginx
    log = ngx_log_init(ngx_prefix);
    if (log == NULL) {
        return 1;
    }

    /* STUB */
#if (NGX_OPENSSL)
    ngx_ssl_init(log);
#endif

    /*
     * init_cycle->log is required for signal handlers and
     * ngx_process_options()
     */

    // 设置最开始的cycle
    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;

    // 定义在ngx_cycle.c,
    // volatile ngx_cycle_t  *ngx_cycle;
    // nginx生命周期使用的超重要对象
    // ngx_cycle指针指向第一个cycle结构体
    ngx_cycle = &init_cycle;

    // 创建cycle使用的内存池，用于之后所有的内存分配，必须成功
    // 这个内存池很小，只有1k，因为只是临时用
    init_cycle.pool = ngx_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        return 1;
    }

    // 分配内存，拷贝参数，没有使用内存池
    // 拷贝到全局变量ngx_argc/ngx.argv
    if (ngx_save_argv(&init_cycle, argc, argv) != NGX_OK) {
        return 1;
    }

    // 设置cycle->prefix/cycle->conf_prefix等成员
    if (ngx_process_options(&init_cycle) != NGX_OK) {
        return 1;
    }

    // os/unix/ngx_posix_init.c
    // 初始化ngx_os_io结构体，设置基本的收发函数
    // 基本的页大小,ngx_pagesize = getpagesize()
    // 最多描述符数量，ngx_max_sockets
    // 初始化随机数
    // ngx_os_io = ngx_linux_io;重要的操作,设置为linux的接口函数
    if (ngx_os_init(log) != NGX_OK) {
        return 1;
    }

    /*
     * ngx_crc32_table_init() requires ngx_cacheline_size set in ngx_os_init()
     */

    // 初始化用于crc32计算的表，在ngx_crc32.c
    if (ngx_crc32_table_init() != NGX_OK) {
        return 1;
    }

    /*
     * ngx_slab_sizes_init() requires ngx_pagesize set in ngx_os_init()
     */

    // 1.14.0新增
    ngx_slab_sizes_init();

    // 检查NGINX环境变量，获取之前监听的socket
    // 用于update binary
    if (ngx_add_inherited_sockets(&init_cycle) != NGX_OK) {
        return 1;
    }

    // 开始计算所有的静态模块数量
    // ngx_modules是nginx模块数组，存储所有的模块指针，由make生成在objs/ngx_modules.c
    // 这里赋值每个模块的index成员
    // ngx_modules_n保存了最后一个可用的序号
    // ngx_max_module是模块数量的上限
    if (ngx_preinit_modules() != NGX_OK) {
        return 1;
    }

    // ngx_cycle.c
    // 初始化cycle,800多行
    // 由之前最基本的init_cycle产生出真正使用的cycle
    // 解析配置文件，配置所有的模块
    // 创建共享内存，打开文件，监听配置的端口
    cycle = ngx_init_cycle(&init_cycle);
    if (cycle == NULL) {
        if (ngx_test_config) {
            ngx_log_stderr(0, "configuration file %s test failed",
                           init_cycle.conf_file.data);
        }

        return 1;
    }

    // 如果用了-t参数要测试配置，在这里就结束了
    // 定义在ngx_cycle.c
    if (ngx_test_config) {
        //非安静模式，输出测试信息
        if (!ngx_quiet_mode) {
            ngx_log_stderr(0, "configuration file %s test is successful",
                           cycle->conf_file.data);
        }

        // 1.10, dump整个配置文件
        if (ngx_dump_config) {
            cd = cycle->config_dump.elts;

            for (i = 0; i < cycle->config_dump.nelts; i++) {

                ngx_write_stdout("# configuration file ");
                (void) ngx_write_fd(ngx_stdout, cd[i].name.data,
                                    cd[i].name.len);
                ngx_write_stdout(":" NGX_LINEFEED);

                b = cd[i].buffer;

                (void) ngx_write_fd(ngx_stdout, b->pos, b->last - b->pos);
                ngx_write_stdout(NGX_LINEFEED);
            }
        }

        return 0;
    }

    // 如果用了-s参数，那么就要发送reload/stop等信号，然后结束
    if (ngx_signal) {
        // ngx_cycle.c
        // 最后调用os/unix/ngx_process.c里的函数ngx_os_signal_process()
        return ngx_signal_process(cycle, ngx_signal);
    }

    // ngx_posix_init.c
    // 使用NGX_LOG_NOTICE记录操作系统的一些信息,通常不会显示
    ngx_os_status(cycle->log);

    // 定义在ngx_cycle.c,
    // volatile ngx_cycle_t  *ngx_cycle;
    // nginx生命周期使用的超重要对象
    // 指针切换到ngx_init_cycle()创建好的新对象
    ngx_cycle = cycle;

    // ngx_init_cycle()里已经解析了配置文件
    // 检查core模块的配置
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // master on且单进程
    // 如果master_process off那么就不是master进程
    // ngx_process定义在os/unix/ngx_process_cycle.c
    if (ccf->master && ngx_process == NGX_PROCESS_SINGLE) {
        // 设置为master进程状态
        ngx_process = NGX_PROCESS_MASTER;
    }

// unix/linux将进程守护进程化
#if !(NGX_WIN32)

    // os/unix/ngx_process.c
    // 使用signals数组，初始化信号处理handler
    if (ngx_init_signals(cycle->log) != NGX_OK) {
        return 1;
    }

    // 守护进程
    if (!ngx_inherited && ccf->daemon) {
        // os/unix/ngx_daemon.c
        // 经典的daemon操作，使用fork
        if (ngx_daemon(cycle->log) != NGX_OK) {
            return 1;
        }

        ngx_daemonized = 1;
    }

    if (ngx_inherited) {
        ngx_daemonized = 1;
    }

#endif

    // ngx_cycle.c
    // 把ngx_pid字符串化，写入pid文件
    // 在daemon后，此时的pid是真正的master进程pid
    if (ngx_create_pidfile(&ccf->pid, cycle->log) != NGX_OK) {
        return 1;
    }

    if (ngx_log_redirect_stderr(cycle) != NGX_OK) {
        return 1;
    }

    if (log->file->fd != ngx_stderr) {
        if (ngx_close_file(log->file->fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_close_file_n " built-in log failed");
        }
    }

    // 默认不使用标准流记录日志
    // 在ngx_log.c里
    ngx_use_stderr = 0;

    // 启动单进程或者master/worker多进程，内部会调用fork
    // 子进程完全复制父进程的cycle，包括打开的文件、共享内存、监听的端口
    if (ngx_process == NGX_PROCESS_SINGLE) {
        // 如果master_process off那么就不是master进程
        // ngx_process_cycle.c
        ngx_single_process_cycle(cycle);

    } else {
        // ngx_process_cycle.c
        // 启动worker进程，数量由配置决定，即worker_processes指令
        // 核心操作是sigsuspend，暂时挂起进程，不占用CPU，只有收到信号时才被唤醒
        ngx_master_process_cycle(cycle);
    }

    // 只有退出无限循环才会走到这里，进程结束
    return 0;
}


// 显示帮助信息，1.10增加-T，可以dump整个配置文件
static void
ngx_show_version_info(void)
{
    // NGINX_VER_BUILD in nginx.h
    ngx_write_stderr("nginx version: " NGINX_VER_BUILD NGX_LINEFEED);

    if (ngx_show_help) {
        ngx_write_stderr(
            "Usage: nginx [-?hvVtTq] [-s signal] [-c filename] "
                         "[-p prefix] [-g directives]" NGX_LINEFEED
                         NGX_LINEFEED
            "Options:" NGX_LINEFEED
            "  -?,-h         : this help" NGX_LINEFEED
            "  -v            : show version and exit" NGX_LINEFEED
            "  -V            : show version and configure options then exit"
                               NGX_LINEFEED
            "  -t            : test configuration and exit" NGX_LINEFEED
            "  -T            : test configuration, dump it and exit"
                               NGX_LINEFEED
            "  -q            : suppress non-error messages "
                               "during configuration testing" NGX_LINEFEED
            "  -s signal     : send signal to a master process: "
                               "stop, quit, reopen, reload" NGX_LINEFEED
#ifdef NGX_PREFIX
            "  -p prefix     : set prefix path (default: " NGX_PREFIX ")"
                               NGX_LINEFEED
#else
            "  -p prefix     : set prefix path (default: NONE)" NGX_LINEFEED
#endif
            "  -c filename   : set configuration file (default: " NGX_CONF_PATH
                               ")" NGX_LINEFEED
            "  -g directives : set global directives out of configuration "
                               "file" NGX_LINEFEED NGX_LINEFEED
        );
    }

    if (ngx_show_configure) {       //输出编译配置信息

#ifdef NGX_COMPILER
        ngx_write_stderr("built by " NGX_COMPILER NGX_LINEFEED);
#endif

#if (NGX_SSL)
        if (ngx_strcmp(ngx_ssl_version(), OPENSSL_VERSION_TEXT) == 0) {
            ngx_write_stderr("built with " OPENSSL_VERSION_TEXT NGX_LINEFEED);
        } else {
            ngx_write_stderr("built with " OPENSSL_VERSION_TEXT
                             " (running with ");
            ngx_write_stderr((char *) (uintptr_t) ngx_ssl_version());
            ngx_write_stderr(")" NGX_LINEFEED);
        }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        ngx_write_stderr("TLS SNI support enabled" NGX_LINEFEED);
#else
        ngx_write_stderr("TLS SNI support disabled" NGX_LINEFEED);
#endif
#endif

        ngx_write_stderr("configure arguments:" NGX_CONFIGURE NGX_LINEFEED);
    }
}


// 检查NGINX环境变量，获取之前监听的socket
static ngx_int_t
ngx_add_inherited_sockets(ngx_cycle_t *cycle)
{
    u_char           *p, *v, *inherited;
    ngx_int_t         s;
    ngx_listening_t  *ls;

    // 获取环境变量，NGINX_VAR定义在nginx.h，值是"NGINX"
    inherited = (u_char *) getenv(NGINX_VAR);

    // 无变量则直接退出函数
    if (inherited == NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "using inherited sockets from \"%s\"", inherited);

    // 清空cycle的监听端口数组
    if (ngx_array_init(&cycle->listening, cycle->pool, 10,
                       sizeof(ngx_listening_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    // 从环境变量字符串里切分出socket
    // 逐个添加进cycle->listening数组
    for (p = inherited, v = p; *p; p++) {
        // 分隔符是:/;
        if (*p == ':' || *p == ';') {

            // 把字符串转换成整数，即socket描述符
            s = ngx_atoi(v, p - v);
            if (s == NGX_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "invalid socket number \"%s\" in " NGINX_VAR
                              " environment variable, ignoring the rest"
                              " of the variable", v);
                break;
            }

            // 跳过分隔符
            v = p + 1;

            // 添加一个监听端口对象
            ls = ngx_array_push(&cycle->listening);
            if (ls == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(ls, sizeof(ngx_listening_t));

            // 设置为刚获得的socket描述符
            ls->fd = (ngx_socket_t) s;
        }
    }

    // v和p是环境变量字符串的指针，最后必须都到末尾
    // 否则格式有错误，但只记录日志，正常添加socket描述符
    if (v != p) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "invalid socket number \"%s\" in " NGINX_VAR
                      " environment variable, ignoring", v);
    }

    // 设置继承socket描述符的标志位
    ngx_inherited = 1;

    // in ngx_connection.c
    // 根据传递过来的socket描述符，使用系统调用获取之前设置的参数
    // 填入ngx_listeing_t结构体
    return ngx_set_inherited_sockets(cycle);
}


char **
ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last)
{
    char                **p, **env;
    ngx_str_t            *var;
    ngx_uint_t            i, n;
    ngx_core_conf_t      *ccf;
    ngx_pool_cleanup_t   *cln;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (last == NULL && ccf->environment) {
        return ccf->environment;
    }

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (ngx_strcmp(var[i].data, "TZ") == 0
            || ngx_strncmp(var[i].data, "TZ=", 3) == 0)
        {
            goto tz_found;
        }
    }

    var = ngx_array_push(&ccf->env);
    if (var == NULL) {
        return NULL;
    }

    var->len = 2;
    var->data = (u_char *) "TZ";

    var = ccf->env.elts;

tz_found:

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {
            n++;
            continue;
        }

        for (p = ngx_os_environ; *p; p++) {

            if (ngx_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                n++;
                break;
            }
        }
    }

    if (last) {
        env = ngx_alloc((*last + n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        *last = n;

    } else {
        cln = ngx_pool_cleanup_add(cycle->pool, 0);
        if (cln == NULL) {
            return NULL;
        }

        env = ngx_alloc((n + 1) * sizeof(char *), cycle->log);
        if (env == NULL) {
            return NULL;
        }

        cln->handler = ngx_cleanup_environment;
        cln->data = env;
    }

    n = 0;

    for (i = 0; i < ccf->env.nelts; i++) {

        if (var[i].data[var[i].len] == '=') {
            env[n++] = (char *) var[i].data;
            continue;
        }

        for (p = ngx_os_environ; *p; p++) {

            if (ngx_strncmp(*p, var[i].data, var[i].len) == 0
                && (*p)[var[i].len] == '=')
            {
                env[n++] = *p;
                break;
            }
        }
    }

    env[n] = NULL;

    if (last == NULL) {
        ccf->environment = env;
        environ = env;
    }

    return env;
}


static void
ngx_cleanup_environment(void *data)
{
    char  **env = data;

    if (environ == env) {

        /*
         * if the environment is still used, as it happens on exit,
         * the only option is to leak it
         */

        return;
    }

    ngx_free(env);
}


// 执行新的nginx程序，热更新
// 使用环境变量传递已经打开的文件描述符
ngx_pid_t
ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv)
{
    char             **env, *var;
    u_char            *p;
    ngx_uint_t         i, n;
    ngx_pid_t          pid;
    ngx_exec_ctx_t     ctx;
    ngx_core_conf_t   *ccf;
    ngx_listening_t   *ls;

    ngx_memzero(&ctx, sizeof(ngx_exec_ctx_t));

    ctx.path = argv[0];
    ctx.name = "new binary process";
    ctx.argv = argv;

    n = 2;
    env = ngx_set_environment(cycle, &n);
    if (env == NULL) {
        return NGX_INVALID_PID;
    }

    // #define NGINX_VAR          "NGINX"
    // 计算环境变量字符串的长度
    // 所有的监听端口，32位的数字
    // ‘+1’是分隔符‘；’
    // ‘+2’是‘=’和末尾的null
    var = ngx_alloc(sizeof(NGINX_VAR)
                    + cycle->listening.nelts * (NGX_INT32_LEN + 1) + 2,
                    cycle->log);
    if (var == NULL) {
        ngx_free(env);
        return NGX_INVALID_PID;
    }

    // 先拷贝变量名和‘=’，注意sizeof后面不用-1
    p = ngx_cpymem(var, NGINX_VAR "=", sizeof(NGINX_VAR));

    // 逐个打印文件描述符，后面接';'
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        p = ngx_sprintf(p, "%ud;", ls[i].fd);
    }

    // 字符串最后是null
    *p = '\0';

    env[n++] = var;

#if (NGX_SETPROCTITLE_USES_ENV)

    /* allocate the spare 300 bytes for the new binary process title */

    env[n++] = "SPARE=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

#endif

    env[n] = NULL;

#if (NGX_DEBUG)
    {
    char  **e;
    for (e = env; *e; e++) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0, "env: %s", *e);
    }
    }
#endif

    ctx.envp = (char *const *) env;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // 本进程的pid文件改名
    if (ngx_rename_file(ccf->pid.data, ccf->oldpid.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_rename_file_n " %s to %s failed "
                      "before executing new binary process \"%s\"",
                      ccf->pid.data, ccf->oldpid.data, argv[0]);

        ngx_free(env);
        ngx_free(var);

        return NGX_INVALID_PID;
    }

    pid = ngx_execute(cycle, &ctx);

    if (pid == NGX_INVALID_PID) {
        if (ngx_rename_file(ccf->oldpid.data, ccf->pid.data)
            == NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_rename_file_n " %s back to %s failed after "
                          "an attempt to execute new binary process \"%s\"",
                          ccf->oldpid.data, ccf->pid.data, argv[0]);
        }
    }

    ngx_free(env);
    ngx_free(var);

    return pid;
}


// nginx自己实现的命令行参数解析
static ngx_int_t
ngx_get_options(int argc, char *const *argv)
{
    u_char     *p;
    ngx_int_t   i;

    for (i = 1; i < argc; i++) {

        p = (u_char *) argv[i];

        if (*p++ != '-') {
            ngx_log_stderr(0, "invalid option: \"%s\"", argv[i]);
            return NGX_ERROR;
        }

        while (*p) {

            switch (*p++) {

            case '?':
            case 'h':
                ngx_show_version = 1;
                ngx_show_help = 1;
                break;

            case 'v':
                ngx_show_version = 1;
                break;

            case 'V':
                ngx_show_version = 1;
                ngx_show_configure = 1;
                break;

            case 't':
                ngx_test_config = 1;        //测试配置文件
                break;

            case 'T':
                ngx_test_config = 1;
                ngx_dump_config = 1;
                break;

            case 'q':
                ngx_quiet_mode = 1;
                break;

            case 'p':
                if (*p) {                   //-p后紧接着路径
                    ngx_prefix = p;         //设置ngx_prefix变量
                    goto next;
                }

                if (argv[++i]) {            //-p后有空格，使用argv数组
                    ngx_prefix = (u_char *) argv[i];
                    goto next;
                }

                ngx_log_stderr(0, "option \"-p\" requires directory name");
                return NGX_ERROR;

            case 'c':
                if (*p) {
                    ngx_conf_file = p;      //设置ngx_conf_file,配置文件
                    goto next;
                }

                if (argv[++i]) {
                    ngx_conf_file = (u_char *) argv[i];
                    goto next;
                }

                ngx_log_stderr(0, "option \"-c\" requires file name");
                return NGX_ERROR;

            case 'g':
                if (*p) {
                    ngx_conf_params = p;
                    goto next;
                }

                if (argv[++i]) {
                    ngx_conf_params = (u_char *) argv[i];
                    goto next;
                }

                ngx_log_stderr(0, "option \"-g\" requires parameter");
                return NGX_ERROR;

            case 's':
                if (*p) {
                    ngx_signal = (char *) p;        //要发送的信号，设置ngx_signal

                } else if (argv[++i]) {
                    ngx_signal = argv[i];

                } else {
                    ngx_log_stderr(0, "option \"-s\" requires parameter");
                    return NGX_ERROR;
                }

                if (ngx_strcmp(ngx_signal, "stop") == 0
                    || ngx_strcmp(ngx_signal, "quit") == 0
                    || ngx_strcmp(ngx_signal, "reopen") == 0
                    || ngx_strcmp(ngx_signal, "reload") == 0)
                {
                    ngx_process = NGX_PROCESS_SIGNALLER;    //发送信号标志
                    goto next;
                }

                ngx_log_stderr(0, "invalid option: \"-s %s\"", ngx_signal);
                return NGX_ERROR;

            default:
                ngx_log_stderr(0, "invalid option: \"%c\"", *(p - 1));
                return NGX_ERROR;
            }
        }

    next:

        continue;
    }

    return NGX_OK;
}


// 保存命令行参数到全局变量ngx_argc/ngx_argv
static ngx_int_t
ngx_save_argv(ngx_cycle_t *cycle, int argc, char *const *argv)
{
#if (NGX_FREEBSD)

    ngx_os_argv = (char **) argv;
    ngx_argc = argc;
    ngx_argv = (char **) argv;

#else
    size_t     len;
    ngx_int_t  i;

    // 定义在os/unix/ngx_process.c
    ngx_os_argv = (char **) argv;
    ngx_argc = argc;

    // 分配内存，拷贝参数，没有使用内存池
    ngx_argv = ngx_alloc((argc + 1) * sizeof(char *), cycle->log);
    if (ngx_argv == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < argc; i++) {
        len = ngx_strlen(argv[i]) + 1;

        ngx_argv[i] = ngx_alloc(len, cycle->log);
        if (ngx_argv[i] == NULL) {
            return NGX_ERROR;
        }

        (void) ngx_cpystrn((u_char *) ngx_argv[i], (u_char *) argv[i], len);
    }

    ngx_argv[i] = NULL;

#endif

    ngx_os_environ = environ;

    return NGX_OK;
}


// 设置cycle->prefix/cycle->conf_prefix等成员
static ngx_int_t
ngx_process_options(ngx_cycle_t *cycle)
{
    u_char  *p;
    size_t   len;

    if (ngx_prefix) {
        len = ngx_strlen(ngx_prefix);
        p = ngx_prefix;

        if (len && !ngx_path_separator(p[len - 1])) {
            p = ngx_pnalloc(cycle->pool, len + 1);
            if (p == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(p, ngx_prefix, len);
            p[len++] = '/';
        }

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

    } else {

#ifndef NGX_PREFIX

        p = ngx_pnalloc(cycle->pool, NGX_MAX_PATH);
        if (p == NULL) {
            return NGX_ERROR;
        }

        if (ngx_getcwd(p, NGX_MAX_PATH) == 0) {
            ngx_log_stderr(ngx_errno, "[emerg]: " ngx_getcwd_n " failed");
            return NGX_ERROR;
        }

        len = ngx_strlen(p);

        p[len++] = '/';

        cycle->conf_prefix.len = len;
        cycle->conf_prefix.data = p;
        cycle->prefix.len = len;
        cycle->prefix.data = p;

#else

#ifdef NGX_CONF_PREFIX
        ngx_str_set(&cycle->conf_prefix, NGX_CONF_PREFIX);
#else
        ngx_str_set(&cycle->conf_prefix, NGX_PREFIX);
#endif
        ngx_str_set(&cycle->prefix, NGX_PREFIX);

#endif
    }

    if (ngx_conf_file) {
        cycle->conf_file.len = ngx_strlen(ngx_conf_file);
        cycle->conf_file.data = ngx_conf_file;

    } else {
        ngx_str_set(&cycle->conf_file, NGX_CONF_PATH);
    }

    if (ngx_conf_full_name(cycle, &cycle->conf_file, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    for (p = cycle->conf_file.data + cycle->conf_file.len - 1;
         p > cycle->conf_file.data;
         p--)
    {
        if (ngx_path_separator(*p)) {
            cycle->conf_prefix.len = p - cycle->conf_file.data + 1;
            cycle->conf_prefix.data = cycle->conf_file.data;
            break;
        }
    }

    if (ngx_conf_params) {
        cycle->conf_param.len = ngx_strlen(ngx_conf_params);
        cycle->conf_param.data = ngx_conf_params;
    }

    if (ngx_test_config) {
        cycle->log->log_level = NGX_LOG_INFO;
    }

    return NGX_OK;
}


static void *
ngx_core_module_create_conf(ngx_cycle_t *cycle)
{
    ngx_core_conf_t  *ccf;

    // 分配内存，注意是pcalloc，内存全为0
    ccf = ngx_pcalloc(cycle->pool, sizeof(ngx_core_conf_t));
    if (ccf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc()
     *
     *     ccf->pid = NULL;
     *     ccf->oldpid = NULL;
     *     ccf->priority = 0;
     *     ccf->cpu_affinity_auto = 0;
     *     ccf->cpu_affinity_n = 0;
     *     ccf->cpu_affinity = NULL;
     */

    // 需要设置初始值的参数必须置为unset
    // ngx_conf_init_value系列宏只识别unset
    ccf->daemon = NGX_CONF_UNSET;
    ccf->master = NGX_CONF_UNSET;
    ccf->timer_resolution = NGX_CONF_UNSET_MSEC;
    ccf->shutdown_timeout = NGX_CONF_UNSET_MSEC;

    ccf->worker_processes = NGX_CONF_UNSET;
    ccf->debug_points = NGX_CONF_UNSET;

    ccf->rlimit_nofile = NGX_CONF_UNSET;
    ccf->rlimit_core = NGX_CONF_UNSET;

    ccf->user = (ngx_uid_t) NGX_CONF_UNSET_UINT;
    ccf->group = (ngx_gid_t) NGX_CONF_UNSET_UINT;

    if (ngx_array_init(&ccf->env, cycle->pool, 1, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }

    return ccf;
}


static char *
ngx_core_module_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_core_conf_t  *ccf = conf;

    ngx_conf_init_value(ccf->daemon, 1);            //默认启用守护进程
    ngx_conf_init_value(ccf->master, 1);            //默认启用master进程
    ngx_conf_init_msec_value(ccf->timer_resolution, 0);     //时间分辨率为0

    // 1.11.11新增，worker进程关闭的超时时间，默认永远等待
    ngx_conf_init_msec_value(ccf->shutdown_timeout, 0);

    ngx_conf_init_value(ccf->worker_processes, 1);  //默认只有一个worker
    ngx_conf_init_value(ccf->debug_points, 0);      //不使用debug point

#if (NGX_HAVE_CPU_AFFINITY)

    if (!ccf->cpu_affinity_auto
        && ccf->cpu_affinity_n
        && ccf->cpu_affinity_n != 1
        && ccf->cpu_affinity_n != (ngx_uint_t) ccf->worker_processes)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "the number of \"worker_processes\" is not equal to "
                      "the number of \"worker_cpu_affinity\" masks, "
                      "using last mask for remaining worker processes");
    }

#endif


    if (ccf->pid.len == 0) {        //如果不设置pid指令，使用默认的NGX_PID_PATH
        ngx_str_set(&ccf->pid, NGX_PID_PATH);
    }

    if (ngx_conf_full_name(cycle, &ccf->pid, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ccf->oldpid.len = ccf->pid.len + sizeof(NGX_OLDPID_EXT);

    ccf->oldpid.data = ngx_pnalloc(cycle->pool, ccf->oldpid.len);
    if (ccf->oldpid.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(ngx_cpymem(ccf->oldpid.data, ccf->pid.data, ccf->pid.len),
               NGX_OLDPID_EXT, sizeof(NGX_OLDPID_EXT));


#if !(NGX_WIN32)

    if (ccf->user == (uid_t) NGX_CONF_UNSET_UINT && geteuid() == 0) {
        struct group   *grp;
        struct passwd  *pwd;

        ngx_set_errno(0);
        pwd = getpwnam(NGX_USER);
        if (pwd == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "getpwnam(\"" NGX_USER "\") failed");
            return NGX_CONF_ERROR;
        }

        ccf->username = NGX_USER;
        ccf->user = pwd->pw_uid;

        ngx_set_errno(0);
        grp = getgrnam(NGX_GROUP);
        if (grp == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "getgrnam(\"" NGX_GROUP "\") failed");
            return NGX_CONF_ERROR;
        }

        ccf->group = grp->gr_gid;
    }


    if (ccf->lock_file.len == 0) {
        ngx_str_set(&ccf->lock_file, NGX_LOCK_PATH);
    }

    if (ngx_conf_full_name(cycle, &ccf->lock_file, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    {
    ngx_str_t  lock_file;

    lock_file = cycle->old_cycle->lock_file;

    if (lock_file.len) {
        lock_file.len--;

        if (ccf->lock_file.len != lock_file.len
            || ngx_strncmp(ccf->lock_file.data, lock_file.data, lock_file.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "\"lock_file\" could not be changed, ignored");
        }

        cycle->lock_file.len = lock_file.len + 1;
        lock_file.len += sizeof(".accept");

        cycle->lock_file.data = ngx_pstrdup(cycle->pool, &lock_file);
        if (cycle->lock_file.data == NULL) {
            return NGX_CONF_ERROR;
        }

    } else {
        cycle->lock_file.len = ccf->lock_file.len + 1;
        cycle->lock_file.data = ngx_pnalloc(cycle->pool,
                                      ccf->lock_file.len + sizeof(".accept"));
        if (cycle->lock_file.data == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(ngx_cpymem(cycle->lock_file.data, ccf->lock_file.data,
                              ccf->lock_file.len),
                   ".accept", sizeof(".accept"));
    }
    }

#endif

    return NGX_CONF_OK;
}


static char *
ngx_set_user(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_WIN32)

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"user\" is not supported, ignored");

    return NGX_CONF_OK;

#else

    ngx_core_conf_t  *ccf = conf;

    char             *group;
    struct passwd    *pwd;
    struct group     *grp;
    ngx_str_t        *value;

    if (ccf->user != (uid_t) NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (geteuid() != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the \"user\" directive makes sense only "
                           "if the master process runs "
                           "with super-user privileges, ignored");
        return NGX_CONF_OK;
    }

    value = cf->args->elts;

    ccf->username = (char *) value[1].data;

    ngx_set_errno(0);
    pwd = getpwnam((const char *) value[1].data);
    if (pwd == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "getpwnam(\"%s\") failed", value[1].data);
        return NGX_CONF_ERROR;
    }

    ccf->user = pwd->pw_uid;

    group = (char *) ((cf->args->nelts == 2) ? value[1].data : value[2].data);

    ngx_set_errno(0);
    grp = getgrnam(group);
    if (grp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "getgrnam(\"%s\") failed", group);
        return NGX_CONF_ERROR;
    }

    ccf->group = grp->gr_gid;

    return NGX_CONF_OK;

#endif
}


static char *
ngx_set_env(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_core_conf_t  *ccf = conf;

    ngx_str_t   *value, *var;
    ngx_uint_t   i;

    var = ngx_array_push(&ccf->env);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    *var = value[1];

    for (i = 0; i < value[1].len; i++) {

        if (value[1].data[i] == '=') {

            var->len = i;

            return NGX_CONF_OK;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_core_conf_t  *ccf = conf;

    ngx_str_t        *value;
    ngx_uint_t        n, minus;

    if (ccf->priority != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].data[0] == '-') {
        n = 1;
        minus = 1;

    } else if (value[1].data[0] == '+') {
        n = 1;
        minus = 0;

    } else {
        n = 0;
        minus = 0;
    }

    ccf->priority = ngx_atoi(&value[1].data[n], value[1].len - n);
    if (ccf->priority == NGX_ERROR) {
        return "invalid number";
    }

    if (minus) {
        ccf->priority = -ccf->priority;
    }

    return NGX_CONF_OK;
}


// 设置绑定cpu的掩码
static char *
ngx_set_cpu_affinity(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_HAVE_CPU_AFFINITY)
    ngx_core_conf_t  *ccf = conf;

    u_char            ch, *p;
    ngx_str_t        *value;
    ngx_uint_t        i, n;
    ngx_cpuset_t     *mask;

    // 不能重复设置
    if (ccf->cpu_affinity) {
        return "is duplicate";
    }

    // 创建数组，个数是参数数量减1,即去掉指令的数量
    mask = ngx_palloc(cf->pool, (cf->args->nelts - 1) * sizeof(ngx_cpuset_t));
    if (mask == NULL) {
        return NGX_CONF_ERROR;
    }

    // 掩码数量
    ccf->cpu_affinity_n = cf->args->nelts - 1;

    // 把掩码填入ccf核心配置
    ccf->cpu_affinity = mask;

    value = cf->args->elts;

    // 处理auto参数
    // auto后可以再使用一个掩码，限定绑定的cpu
    if (ngx_strcmp(value[1].data, "auto") == 0) {

        // 使用auto后不能有多个mask
        if (cf->args->nelts > 3) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid number of arguments in "
                               "\"worker_cpu_affinity\" directive");
            return NGX_CONF_ERROR;
        }

        // 自动绑定标志位
        ccf->cpu_affinity_auto = 1;

        // 置所有的cpu位
        CPU_ZERO(&mask[0]);
        for (i = 0; i < (ngx_uint_t) ngx_min(ngx_ncpu, CPU_SETSIZE); i++) {
            CPU_SET(i, &mask[0]);
        }

        // 之后从第2个开始
        n = 2;

    } else {
        // 没有auto则都是掩码
        n = 1;
    }

    // 逐个处理掩码
    for ( /* void */ ; n < cf->args->nelts; n++) {

        // 二进制掩码的长度不能超过cpu数量
        if (value[n].len > CPU_SETSIZE) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "\"worker_cpu_affinity\" supports up to %d CPUs only",
                         CPU_SETSIZE);
            return NGX_CONF_ERROR;
        }

        i = 0;
        CPU_ZERO(&mask[n - 1]);

        // 注意是倒着计算，最右边的是CPU0
        for (p = value[n].data + value[n].len - 1;
             p >= value[n].data;
             p--)
        {
            ch = *p;

            // 允许使用空格
            // 例如'00 01'
            if (ch == ' ') {
                continue;
            }

            i++;

            if (ch == '0') {
                continue;
            }

            // 设置掩码
            if (ch == '1') {
                CPU_SET(i - 1, &mask[n - 1]);
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "invalid character \"%c\" in \"worker_cpu_affinity\"",
                          ch);
            return NGX_CONF_ERROR;
        }   // 处理完一个掩码
    }   // 处理完所有掩码

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"worker_cpu_affinity\" is not supported "
                       "on this platform, ignored");
#endif

    return NGX_CONF_OK;
}


ngx_cpuset_t *
ngx_get_cpu_affinity(ngx_uint_t n)
{
#if (NGX_HAVE_CPU_AFFINITY)
    ngx_uint_t        i, j;
    ngx_cpuset_t     *mask;
    ngx_core_conf_t  *ccf;

    static ngx_cpuset_t  result;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    if (ccf->cpu_affinity == NULL) {
        return NULL;
    }

    // 自动绑定cpu
    if (ccf->cpu_affinity_auto) {
        // 取限制掩码
        mask = &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];

        // 找到应该使用的cpu
        for (i = 0, j = n; /* void */ ; i++) {

            if (CPU_ISSET(i % CPU_SETSIZE, mask) && j-- == 0) {
                break;
            }

            if (i == CPU_SETSIZE && j == n) {
                /* empty mask */
                return NULL;
            }

            /* void */
        }

        // 设置掩码
        CPU_ZERO(&result);
        CPU_SET(i % CPU_SETSIZE, &result);

        return &result;
    }

    // 不是自动设置则取第n个
    if (ccf->cpu_affinity_n > n) {
        return &ccf->cpu_affinity[n];
    }

    // 设置的不足，取最后一个绑定
    return &ccf->cpu_affinity[ccf->cpu_affinity_n - 1];

#else

    return NULL;

#endif
}


static char *
ngx_set_worker_processes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t        *value;
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) conf;

    if (ccf->worker_processes != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "auto") == 0) {
        ccf->worker_processes = ngx_ncpu;
        return NGX_CONF_OK;
    }

    ccf->worker_processes = ngx_atoi(value[1].data, value[1].len);

    if (ccf->worker_processes == NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


// 打开动态库文件
// 设置内存池销毁时的清理动作，关闭动态库
// 使用"ngx_modules"取动态库里的模块数组
// 使用"ngx_module_names"取动态库里的模块名字数组
// 使用"ngx_module_order"取动态库里的模块顺序数组
// 模块顺序只对http filter模块有意义
// 所以可以没有，不需要检查
// 遍历动态库里的模块数组
// 流程类似ngx_preinit_modules
// 调用ngx_add_module添加模块
static char *
ngx_load_module(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_HAVE_DLOPEN)
    void                *handle;
    char               **names, **order;
    ngx_str_t           *value, file;
    ngx_uint_t           i;
    ngx_module_t        *module, **modules;
    ngx_pool_cleanup_t  *cln;

    // 标志位，cycle已经完成模块的初始化，不能再添加模块
    if (cf->cycle->modules_used) {
        return "is specified too late";
    }

    // 取配置参数
    value = cf->args->elts;

    // 第一个参数是动态库文件名
    file = value[1];

    // 计算正确的路径，如果不是绝对路径就从prefix开始
    if (ngx_conf_full_name(cf->cycle, &file, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // 当cycle内存池销毁时的清理动作
    cln = ngx_pool_cleanup_add(cf->cycle->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    // 打开动态库文件
    handle = ngx_dlopen(file.data);
    if (handle == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_dlopen_n " \"%s\" failed (%s)",
                           file.data, ngx_dlerror());
        return NGX_CONF_ERROR;
    }

    // 设置内存池销毁时的清理动作，关闭动态库
    cln->handler = ngx_unload_module;
    cln->data = handle;

    // 使用"ngx_modules"取动态库里的模块数组
    modules = ngx_dlsym(handle, "ngx_modules");
    if (modules == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "ngx_modules", ngx_dlerror());
        return NGX_CONF_ERROR;
    }

    // 使用"ngx_module_names"取动态库里的模块名字数组
    names = ngx_dlsym(handle, "ngx_module_names");
    if (names == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_dlsym_n " \"%V\", \"%s\" failed (%s)",
                           &value[1], "ngx_module_names", ngx_dlerror());
        return NGX_CONF_ERROR;
    }

    // 使用"ngx_module_order"取动态库里的模块顺序数组
    // 模块顺序只对http filter模块有意义
    // 所以可以没有，不需要检查
    order = ngx_dlsym(handle, "ngx_module_order");

    // 遍历动态库里的模块数组
    // 流程类似ngx_preinit_modules
    // 调用ngx_add_module添加模块
    for (i = 0; modules[i]; i++) {
        module = modules[i];

        // 在这里为动态模块设置名字
        module->name = names[i];

        // cycle->modules_n是模块计数器 如果超过最大数量则报错
        // 使用模块里的各种信息进行检查，只有正确的才能加载
        // 首先是版本号，必须一致，例如1.10的不能给1.9使用
        // 比较签名字符串，里面是二进制兼容信息
        // 看cycle里的模块数组里是否有重名的 也就是说每个模块的名字都不能相同
        // 模块还没有加载，那么就给一个全局序号，不是ctx_index
        // 把动态模块的指针加入cycle的模块数组
        // 最后完成了一个动态模块的加载，放到了cycle模块数组里的合适位置
        if (ngx_add_module(cf, &file, module, order) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cf->log, 0, "module: %s i:%ui",
                       module->name, module->index);
    }

    return NGX_CONF_OK;

#else

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "\"load_module\" is not supported "
                       "on this platform");
    return NGX_CONF_ERROR;

#endif
}


#if (NGX_HAVE_DLOPEN)

// 调用dlclose关闭动态库
// #define ngx_dlclose(handle)        dlclose(handle)
static void
ngx_unload_module(void *data)
{
    void  *handle = data;

    if (ngx_dlclose(handle) != 0) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      ngx_dlclose_n " failed (%s)", ngx_dlerror());
    }
}

#endif
