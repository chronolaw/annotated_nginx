// annotated by chrono since 2016
//
// * ngx_shm_zone_s
// * ngx_cycle_s
// * ngx_core_conf_t

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


// 设置debug断点时的动作，停止或是直接core
// in ngx_process.c ngx_debug_point
#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

// ngx_shm_zone_t
// nginx共享内存结构体
// 使用共享内存锁保证安全
//
// ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
// void ngx_shmtx_lock(ngx_shmtx_t *mtx);
// void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
//
// sp = (ngx_slab_pool_t *) zn->shm.addr;
// if (ngx_shmtx_create(&sp->mutex, &sp->lock, file) != NGX_OK) {
struct ngx_shm_zone_s {
    // init回调使用的数据
    // 存储与共享内存使用相关的数据，ctx
    // 与ngx_slab_pool_t.data用法类似
    void                     *data;

    // os/unix/ngx_shmem.h
    // typedef struct {
    //     u_char      *addr;
    //     size_t       size;
    //     ngx_str_t    name;
    //     ngx_log_t   *log;
    //     ngx_uint_t   exists;   /* unsigned  exists:1;  */
    // } ngx_shm_t;
    // 真正操作共享内存的对象
    // shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    ngx_shm_t                 shm;

    // 创建成功后回调初始化共享内存
    // typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);
    // data不空表示复用旧数据
    ngx_shm_zone_init_pt      init;

    // 关联的标记，防止同名
    // 通常是创建共享内存的模块指针
    void                     *tag;

    void                     *sync;

    // reload时是否复用
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


// nginx核心数据结构，表示nginx的生命周期，含有许多重要参数
//
// conf_ctx, 存储所有模块的配置结构体，是个二维数组
// free_connections,空闲连接，使用指针串成单向链表
// listening,监听的端口数组
// connections/read_events/write_events,连接池,大小是connection_n
//
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

    // old_cycle的log对象
    ngx_log_t                *log;

    // 使用error_log指令设置的新log对象
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

    // 文件也当做连接来处理，也是读写操作
    // 如果使用epoll，那么这个指针通常是null，即不会使用
    ngx_connection_t        **files;

    // 空闲连接，使用指针串成单向链表
    // 指向第一个空闲连接，即头节点
    ngx_connection_t         *free_connections;

    // 空闲连接的数量
    ngx_uint_t                free_connection_n;

    // 1.10，保存模块数组，可以加载动态模块
    // 可以容纳所有的模块，大小是ngx_max_module + 1
    // ngx_cycle_modules()初始化
    ngx_module_t            **modules;

    // 拷贝模块序号计数器到本cycle
    // ngx_cycle_modules()初始化
    ngx_uint_t                modules_n;

    // 标志位，cycle已经完成模块的初始化，不能再添加模块
    // 在ngx_load_module里检查，不允许加载动态模块
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    // 复用连接对象队列
    ngx_queue_t               reusable_connections_queue;
    ngx_uint_t                reusable_connections_n;

    // 监听的端口数组, in ngx_connection.h
    // 主要成员: fd,backlog,rcvbuf,sndbuf
    ngx_array_t               listening;

    // 打开的目录
    ngx_array_t               paths;

    // dump config用
    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    // 打开的文件，主要是日志
    // 存储ngx_open_file_t
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
    // 即-c选项指定的配置文件目录
    ngx_str_t                 conf_prefix;

    // #define NGX_PREFIX  "/usr/local/nginx/"
    // 即-p选项指定的工作目录
    ngx_str_t                 prefix;

    // 在linux里直接用共享内存实现锁，此成员无用
    ngx_str_t                 lock_file;

    // 当前主机的hostname
    // ngx_init_cycle()里初始化，全小写
    ngx_str_t                 hostname;
};


// ngx_core_conf_t
// ngx_core_module的配置结构体，在nginx.c里设置
typedef struct {
    ngx_flag_t                daemon;       //守护进程是否启用
    ngx_flag_t                master;       //master/worker进程机制是否启用

    //调用time_update的时间分辨率，毫秒，在event模块里使用
    ngx_msec_t                timer_resolution;

    // 1.11.11新增，worker进程关闭的超时时间，默认永远等待
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;     //worker进程的数量
    ngx_int_t                 debug_points;         //是否使用debug point

    // 可打开的最大文件数量，超过则报ENOFILE错误
    ngx_int_t                 rlimit_nofile;

    // coredump文件大小
    off_t                     rlimit_core;

    int                       priority;

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;

    // nginx运行使用的用户名，默认是nobody
    // objs/ngx_auto_config.h:#define NGX_USER  "nobody"
    char                     *username;

    ngx_uid_t                 user;
    ngx_gid_t                 group;

    // core dump的目录
    ngx_str_t                 working_directory;

    // 用于实现共享锁，linux下无意义
    ngx_str_t                 lock_file;

    // 旧的线程实现，1.9.x已经删除，不应该使用

    // master进程的pid文件名
    ngx_str_t                 pid;

    // new binary时老nginx的pid文件名
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


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
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);

// 设置关闭worker进程的超时时间
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


// nginx生命周期使用的超重要对象
extern volatile ngx_cycle_t  *ngx_cycle;

extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;

// -t参数，检查配置文件, in ngx_cycle.c
extern ngx_uint_t             ngx_test_config;

// 1.10, dump整个配置文件, in ngx_cycle.c
extern ngx_uint_t             ngx_dump_config;

// 安静模式，不输出测试信息, in ngx_cycle.c
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
