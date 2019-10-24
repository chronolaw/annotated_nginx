// annotated by chrono since 2016
//
// * ngx_event_s
// * ngx_event_actions_t
// * ngx_event_conf_t
// * ngx_event_module_t
// * ngx_event_accept
// * ngx_process_events_and_timers

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_H_INCLUDED_
#define _NGX_EVENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_INVALID_INDEX  0xd0d0d0d0


#if (NGX_HAVE_IOCP)

typedef struct {
    WSAOVERLAPPED    ovlp;
    ngx_event_t     *event;
    int              error;
} ngx_event_ovlp_t;

#endif


// nginx事件模块的核心结构体
// 表示一个nginx事件（读/写/超时）
// data表示事件相关的对象，通常是ngx_connection_t，用c = ev->data;
// 重要的成员是handler，即事件发生时调用的函数
struct ngx_event_s {
    // 事件相关的对象，通常是ngx_connection_t
    // 在多线程通知里是ngx_event_handler_pt，即通知回调函数
    void            *data;

    // 写事件，也就是说tcp连接是写状态，可以发送数据
    // 如果是0，意味着这个事件是读事件
    // ngx_connection.c:ngx_get_connection里设置
    unsigned         write:1;

    // 监听状态标志位，只有listening相关的事件才置此标志位
    unsigned         accept:1;

    /* used to detect the stale events in kqueue and epoll */
    // 检测事件是否失效
    // 存储在epoll数据结构体里的指针低位
    // 在ngx_get_connection里获取空闲连接时，这个标志位会取反
    // 这样如果连接失效，那么instance就会不同
    // 判断逻辑在ngx_epoll_module.c:ngx_epoll_process_events
    unsigned         instance:1;

    /*
     * the event was passed or would be passed to a kernel;
     * in aio mode - operation was posted.
     */
    // 事件是否是活跃的，也就是说已经添加进了epoll关注
    unsigned         active:1;

    // epoll无意义
    unsigned         disabled:1;

    /* the ready event; in aio mode 0 means that no operation can be posted */
    // 事件已经就绪，也就是说有数据可读或者可以发送数据
    // 在读写操作完成后会置ready=0
    unsigned         ready:1;

    // epoll无意义
    unsigned         oneshot:1;

    /* aio operation is complete */
    // 异步操作的完成标志，用于aio和多线程
    unsigned         complete:1;

    // 当前的字节流已经结束即eof，不会再有数据可读
    // 如果recv() == 0 ，客户端关闭连接，那么置此标记
    unsigned         eof:1;

    // 发生了错误
    unsigned         error:1;

    // 事件是否已经超时
    // 由ngx_event_expire_timers遍历定时器红黑树，找出所有过期的事件设置此标志位
    unsigned         timedout:1;

    // 事件是否在定时器里
    // ngx_add_timer加入定时器时设置
    // 处理完定时器事件后清除标记
    unsigned         timer_set:1;

    // 需要延迟处理，用于限速，nginx会暂不写数据
    // 参考ngx_http_write_filter_module.c
    unsigned         delayed:1;

    // 延迟接收请求，即只有客户端真正发来数据时内核才会触发accept
    // 可以提高运行效率
    unsigned         deferred_accept:1;

    /* the pending eof reported by kqueue, epoll or in aio chain operation */
    unsigned         pending_eof:1;

    // 事件是否已经加入延后处理队列中，可以加快事件的处理速度
    // 操作函数宏ngx_post_event/ngx_delete_posted_event
    // ngx_posted_accept_events/ngx_posted_events
    unsigned         posted:1;

    unsigned         closed:1;

    /* to test on worker exit */
    unsigned         channel:1;
    unsigned         resolver:1;

    // 在进程退出时定时器是否可以忽略
    unsigned         cancelable:1;

#if (NGX_HAVE_KQUEUE)
    unsigned         kq_vnode:1;

    /* the pending errno reported by kqueue */
    int              kq_errno;
#endif

    /*
     * kqueue only:
     *   accept:     number of sockets that wait to be accepted
     *   read:       bytes to read when event is ready
     *               or lowat when event is set with NGX_LOWAT_EVENT flag
     *   write:      available space in buffer when event is ready
     *               or lowat when event is set with NGX_LOWAT_EVENT flag
     *
     * iocp: TODO
     *
     * otherwise:
     *   accept:     1 if accept many, 0 otherwise
     *   read:       bytes to read when event is ready, -1 if not known
     */

    // 是否尽可能多地接受请求建立连接，即multi_accept
    // 1.11.x后增加新用途，在接收数据时标记是否可用
    // 早期（< 1.17.4）这里使用了bit field，只能存储0/1，节约内存
    int              available;

    // 重要！！
    // 事件发生时调用的函数
    // ngx_core.h:typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
    // tcp/http接受连接时的回调是ngx_event_accept
    // udp接受连接时的回调是ngx_event_recvmsg
    ngx_event_handler_pt  handler;


#if (NGX_HAVE_IOCP)
    ngx_event_ovlp_t ovlp;
#endif

    // 在epoll通知机制里用作简单的计数器ngx_epoll_notify_handler
    ngx_uint_t       index;

    // 日志对象
    ngx_log_t       *log;

    // 红黑树节点成员，用于把事件加入定时器
    // 判断事件超时用
    ngx_rbtree_node_t   timer;

    /* the posted queue */
    // 队列成员，加入延后处理的队列
    // ngx_posted_accept_events/ngx_posted_events
    ngx_queue_t      queue;

#if 0

    /* the threads support */

    /*
     * the event thread context, we store it here
     * if $(CC) does not understand __thread declaration
     * and pthread_getspecific() is too costly
     */

    void            *thr_ctx;

#if (NGX_EVENT_T_PADDING)

    /* event should not cross cache line in SMP */

    uint32_t         padding[NGX_EVENT_T_PADDING];
#endif
#endif
};


#if (NGX_HAVE_FILE_AIO)

struct ngx_event_aio_s {
    void                      *data;
    ngx_event_handler_pt       handler;
    ngx_file_t                *file;

    ngx_fd_t                   fd;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                  (*preload_handler)(ngx_buf_t *file);
#endif

#if (NGX_HAVE_EVENTFD)
    int64_t                    res;
#endif

#if !(NGX_HAVE_EVENTFD) || (NGX_TEST_BUILD_EPOLL)
    ngx_err_t                  err;
    size_t                     nbytes;
#endif

    ngx_aiocb_t                aiocb;
    ngx_event_t                event;
};

#endif

// 可以使用typedef来简化ngx_event_actions_t的定义
#if 0
typedef ngx_int_t  (*events_ctl_pt)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);
typedef ngx_int_t  (*events_add_all_pt)(ngx_connection_t *c);
typedef ngx_int_t  (*events_del_all_pt)(ngx_connection_t *c, ngx_uint_t flags);
typedef ngx_int_t  (*events_notify_pt)(ngx_event_handler_pt handler);
typedef ngx_int_t  (*events_process_pt)(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags);
typedef ngx_int_t  (*events_init_pt)(ngx_cycle_t *cycle, ngx_msec_t timer);
typedef void       (*events_done_pt)(ngx_cycle_t *cycle);

typedef struct {
    events_ctl_pt       add;
    events_ctl_pt       del;
    events_ctl_pt       enable;
    events_ctl_pt       disable;
    events_add_all_pt   add_conn;
    events_del_all_pt   del_conn;
    events_notify_pt    notify;
    events_process_pt   process_events;
    events_init_pt      init;
    events_done_pt      done;
} ngx_event_actions_t;
#endif

// 添加读事件的便捷接口，适合epoll/kqueue/select等各种事件模型
// 内部还是调用ngx_add_event
// ngx_int_t ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags);
//
// 添加写事件的便捷接口，适合epoll/kqueue/select等各种事件模型
// 内部还是调用ngx_add_event,多了个send_lowat操作
// linux不支持send_lowat指令，send_lowat总是0
// ngx_int_t ngx_handle_write_event(ngx_event_t *wev, size_t lowat);

// ngx_event_actions_t
// 全局的事件模块访问接口，是一个函数表
// 由epoll/kqueue/select等模块实现
// epoll的实现在modules/ngx_epoll_module.c
typedef struct {
    // 添加事件,事件发生时epoll调用可以获取
    // epoll添加事件
    // 检查事件关联的连接对象，决定是新添加还是修改
    // 避免误删除了读写事件的关注
    ngx_int_t  (*add)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);

    // 删除事件,epoll不再关注该事件
    // epoll删除事件
    // 检查事件关联的连接对象，决定是完全删除还是修改
    // 避免误删除了读写事件的关注
    ngx_int_t  (*del)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);

    // 同add
    ngx_int_t  (*enable)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);

    // 同del
    ngx_int_t  (*disable)(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags);

    // 添加一个连接，也就是读写事件都添加
    // epoll关注连接的读写事件
    // 添加事件成功，读写事件都是活跃的，即已经使用
    ngx_int_t  (*add_conn)(ngx_connection_t *c);

    // 删除一个连接，该连接的读写事件都不再关注
    // epoll删除连接的读写事件
    // 删除事件成功，读写事件都不活跃
    ngx_int_t  (*del_conn)(ngx_connection_t *c, ngx_uint_t flags);

    // 目前仅多线程使用，通知
    // 调用系统函数eventfd，创建一个可以用于通知的描述符，用于实现notify
    // 模仿此用法也可以实现自己的通知机制
    ngx_int_t  (*notify)(ngx_event_handler_pt handler);

    // 事件模型的核心功能，处理发生的事件
    //
    // epoll模块核心功能，调用epoll_wait处理发生的事件
    // 使用event_list和nevents获取内核返回的事件
    // timer是无事件发生时最多等待的时间，即超时时间
    // 函数可以分为两部分，一是用epoll获得事件，二是处理事件，加入延后队列
    // 在ngx_process_events_and_timers里被调用
    ngx_int_t  (*process_events)(ngx_cycle_t *cycle, ngx_msec_t timer,
                                 ngx_uint_t flags);

    // 初始化事件模块
    // 调用epoll_create初始化epoll机制
    // 参数size=cycle->connection_n / 2，但并无实际意义
    // 设置全局变量，操作系统提供的底层数据收发接口
    // 初始化全局的事件模块访问接口，指向epoll的函数
    // 默认使用et模式，边缘触发，高速
    ngx_int_t  (*init)(ngx_cycle_t *cycle, ngx_msec_t timer);

    // 事件模块结束时的收尾工作
    // epoll模块结束工作，关闭epoll句柄和通知句柄，释放内存
    void       (*done)(ngx_cycle_t *cycle);
} ngx_event_actions_t;


// 全局的事件模块访问接口，是一个函数表
// 定义了若干宏简化对它的操作
// 常用的有ngx_add_event/ngx_del_event
// 在epoll模块的ngx_epoll_init里设置，指向epoll的函数
// ngx_event_actions = ngx_epoll_module_ctx.actions;
extern ngx_event_actions_t   ngx_event_actions;

#if (NGX_HAVE_EPOLLRDHUP)
extern ngx_uint_t            ngx_use_epoll_rdhup;
#endif


/*
 * The event filter requires to read/write the whole data:
 * select, poll, /dev/poll, kqueue, epoll.
 */
// lt模式
#define NGX_USE_LEVEL_EVENT      0x00000001

/*
 * The event filter is deleted after a notification without an additional
 * syscall: kqueue, epoll.
 */
#define NGX_USE_ONESHOT_EVENT    0x00000002

/*
 * The event filter notifies only the changes and an initial level:
 * kqueue, epoll.
 */
// clear event也就是et模式
#define NGX_USE_CLEAR_EVENT      0x00000004

/*
 * The event filter has kqueue features: the eof flag, errno,
 * available data, etc.
 */
#define NGX_USE_KQUEUE_EVENT     0x00000008

/*
 * The event filter supports low water mark: kqueue's NOTE_LOWAT.
 * kqueue in FreeBSD 4.1-4.2 has no NOTE_LOWAT so we need a separate flag.
 */
#define NGX_USE_LOWAT_EVENT      0x00000010

/*
 * The event filter requires to do i/o operation until EAGAIN: epoll.
 */
// 即ET模式
#define NGX_USE_GREEDY_EVENT     0x00000020

/*
 * The event filter is epoll.
 */
// 在linux上我们通常使用epoll
#define NGX_USE_EPOLL_EVENT      0x00000040

/*
 * Obsolete.
 */
// rtsig在nginx 1.9.x里已经被删除
#define NGX_USE_RTSIG_EVENT      0x00000080

/*
 * Obsolete.
 */
// aio在nginx 1.9.x里已经被删除
#define NGX_USE_AIO_EVENT        0x00000100

/*
 * Need to add socket or handle only once: i/o completion port.
 */
#define NGX_USE_IOCP_EVENT       0x00000200

/*
 * The event filter has no opaque data and requires file descriptors table:
 * poll, /dev/poll.
 */
#define NGX_USE_FD_EVENT         0x00000400

/*
 * The event module handles periodic or absolute timer event by itself:
 * kqueue in FreeBSD 4.4, NetBSD 2.0, and MacOSX 10.4, Solaris 10's event ports.
 */
#define NGX_USE_TIMER_EVENT      0x00000800

/*
 * All event filters on file descriptor are deleted after a notification:
 * Solaris 10's event ports.
 */
#define NGX_USE_EVENTPORT_EVENT  0x00001000

/*
 * The event filter support vnode notifications: kqueue.
 */
#define NGX_USE_VNODE_EVENT      0x00002000


/*
 * The event filter is deleted just before the closing file.
 * Has no meaning for select and poll.
 * kqueue, epoll, eventport:         allows to avoid explicit delete,
 *                                   because filter automatically is deleted
 *                                   on file close,
 *
 * /dev/poll:                        we need to flush POLLREMOVE event
 *                                   before closing file.
 */
#define NGX_CLOSE_EVENT    1

/*
 * disable temporarily event filter, this may avoid locks
 * in kernel malloc()/free(): kqueue.
 */
#define NGX_DISABLE_EVENT  2

/*
 * event must be passed to kernel right now, do not wait until batch processing.
 */
#define NGX_FLUSH_EVENT    4


/* these flags have a meaning only for kqueue */
#define NGX_LOWAT_EVENT    0
#define NGX_VNODE_EVENT    0


#if (NGX_HAVE_EPOLL) && !(NGX_HAVE_EPOLLRDHUP)
#define EPOLLRDHUP         0
#endif


// 重定义事件宏，屏蔽系统差异

// kqueue in freebsd/osx
#if (NGX_HAVE_KQUEUE)

#define NGX_READ_EVENT     EVFILT_READ
#define NGX_WRITE_EVENT    EVFILT_WRITE

#undef  NGX_VNODE_EVENT
#define NGX_VNODE_EVENT    EVFILT_VNODE

/*
 * NGX_CLOSE_EVENT, NGX_LOWAT_EVENT, and NGX_FLUSH_EVENT are the module flags
 * and they must not go into a kernel so we need to choose the value
 * that must not interfere with any existent and future kqueue flags.
 * kqueue has such values - EV_FLAG1, EV_EOF, and EV_ERROR:
 * they are reserved and cleared on a kernel entrance.
 */
#undef  NGX_CLOSE_EVENT
#define NGX_CLOSE_EVENT    EV_EOF

#undef  NGX_LOWAT_EVENT
#define NGX_LOWAT_EVENT    EV_FLAG1

#undef  NGX_FLUSH_EVENT
#define NGX_FLUSH_EVENT    EV_ERROR

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  EV_ONESHOT
#define NGX_CLEAR_EVENT    EV_CLEAR

#undef  NGX_DISABLE_EVENT
#define NGX_DISABLE_EVENT  EV_DISABLE


#elif (NGX_HAVE_DEVPOLL && !(NGX_TEST_BUILD_DEVPOLL)) \
      || (NGX_HAVE_EVENTPORT && !(NGX_TEST_BUILD_EVENTPORT))

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


// linux使用epoll
#elif (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

// 读事件，即可读或者有accept连接
// EPOLLRDHUP表示客户端关闭连接（断连），也当做读事件处理
// 这时recv返回0
#define NGX_READ_EVENT     (EPOLLIN|EPOLLRDHUP)

// 写事件，可写
#define NGX_WRITE_EVENT    EPOLLOUT

// 水平触发,仅用于accept接受连接
#define NGX_LEVEL_EVENT    0

// 边缘触发，高速模式
#define NGX_CLEAR_EVENT    EPOLLET

#define NGX_ONESHOT_EVENT  0x70000000
#if 0
#define NGX_ONESHOT_EVENT  EPOLLONESHOT
#endif

#if (NGX_HAVE_EPOLLEXCLUSIVE)
#define NGX_EXCLUSIVE_EVENT  EPOLLEXCLUSIVE
#endif

// poll
#elif (NGX_HAVE_POLL)

#define NGX_READ_EVENT     POLLIN
#define NGX_WRITE_EVENT    POLLOUT

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1


// select
#else /* select */

#define NGX_READ_EVENT     0
#define NGX_WRITE_EVENT    1

#define NGX_LEVEL_EVENT    0
#define NGX_ONESHOT_EVENT  1

#endif /* NGX_HAVE_KQUEUE */


#if (NGX_HAVE_IOCP)
#define NGX_IOCP_ACCEPT      0
#define NGX_IOCP_IO          1
#define NGX_IOCP_CONNECT     2
#endif


#if (NGX_TEST_BUILD_EPOLL)
#define NGX_EXCLUSIVE_EVENT  0
#endif


#ifndef NGX_CLEAR_EVENT
#define NGX_CLEAR_EVENT    0    /* dummy declaration */
#endif


// 全局的事件模块访问接口，是一个函数表
// 定义了若干宏简化对它的操作
// 常用的有ngx_add_event/ngx_del_event
#define ngx_process_events   ngx_event_actions.process_events
#define ngx_done_events      ngx_event_actions.done

// 向epoll添加删除事件
#define ngx_add_event        ngx_event_actions.add
#define ngx_del_event        ngx_event_actions.del

// 向epoll添加删除连接，即同时添加读写事件
#define ngx_add_conn         ngx_event_actions.add_conn
#define ngx_del_conn         ngx_event_actions.del_conn

// 事件通知
#define ngx_notify           ngx_event_actions.notify

// 向定时器红黑树里添加事件，设置超时，ngx_event_timer.h
#define ngx_add_timer        ngx_event_add_timer

// 从定时器红黑树里删除事件, ngx_event_timer.h
#define ngx_del_timer        ngx_event_del_timer


// os/unix/ngx_os.h
// 操作系统提供的底层数据收发接口
// ngx_posix_init.c里初始化为linux的底层接口
// 在epoll模块的ngx_epoll_init里设置
//
// typedef struct {
//     ngx_recv_pt        recv;
//     ngx_recv_chain_pt  recv_chain;
//     ngx_recv_pt        udp_recv;
//     ngx_send_pt        send;
//     ngx_send_chain_pt  send_chain;
//     ngx_uint_t         flags;
// } ngx_os_io_t;
//
// in ngx_connection.c
extern ngx_os_io_t  ngx_io;

// 宏定义简化调用
#define ngx_recv             ngx_io.recv
#define ngx_recv_chain       ngx_io.recv_chain
#define ngx_udp_recv         ngx_io.udp_recv
#define ngx_send             ngx_io.send
#define ngx_send_chain       ngx_io.send_chain
#define ngx_udp_send         ngx_io.udp_send
#define ngx_udp_send_chain   ngx_io.udp_send_chain


// event模块的type标记
#define NGX_EVENT_MODULE      0x544E5645  /* "EVNT" */
#define NGX_EVENT_CONF        0x02000000


// ngx_event_conf_t
// event_core模块的配置结构体
typedef struct {
    // nginx每个进程可使用的连接数量，即cycle里的连接池大小
    ngx_uint_t    connections;

    // 使用的是哪个event模块，值是具体事件模块的ctx_index
    ngx_uint_t    use;

    // 是否尽可能多接受客户端请求，会影响进程间负载均衡
    ngx_flag_t    multi_accept;

    // 是否使用负载均衡锁，在共享内存里的一个原子变量
    ngx_flag_t    accept_mutex;

    // 负载均衡锁的等待时间，进程如果未获得锁会等一下再尝试
    ngx_msec_t    accept_mutex_delay;

    // 事件模块的名字，如epoll/select/kqueue
    // 使用name在event模块里查找，决定使用的事件机制
    u_char       *name;

    // 针对某些连接打印调试日志
#if (NGX_DEBUG)
    ngx_array_t   debug_connection;
#endif
} ngx_event_conf_t;


// ngx_event_module_t
// 事件模块的函数指针表
// 核心是actions，即事件处理函数
typedef struct {
    // 事件模块的名字，如epoll/select/kqueue
    ngx_str_t              *name;

    // 事件模块的配置相关函数比较简单
    void                 *(*create_conf)(ngx_cycle_t *cycle);
    char                 *(*init_conf)(ngx_cycle_t *cycle, void *conf);

    // 事件模块访问接口，是一个函数表
    ngx_event_actions_t     actions;
} ngx_event_module_t;


// 连接计数器，使用共享内存，所有worker公用
extern ngx_atomic_t          *ngx_connection_counter;

// 用共享内存实现的原子变量，负载均衡锁
// 使用1.9.x的reuseport会自动禁用负载均衡，效率更高
extern ngx_atomic_t          *ngx_accept_mutex_ptr;
extern ngx_shmtx_t            ngx_accept_mutex;
extern ngx_uint_t             ngx_use_accept_mutex;
extern ngx_uint_t             ngx_accept_events;
extern ngx_uint_t             ngx_accept_mutex_held;
extern ngx_msec_t             ngx_accept_mutex_delay;
extern ngx_int_t              ngx_accept_disabled;


// stat模块的统计用变量，也用共享内存实现
#if (NGX_STAT_STUB)

extern ngx_atomic_t  *ngx_stat_accepted;
extern ngx_atomic_t  *ngx_stat_handled;
extern ngx_atomic_t  *ngx_stat_requests;
extern ngx_atomic_t  *ngx_stat_active;
extern ngx_atomic_t  *ngx_stat_reading;
extern ngx_atomic_t  *ngx_stat_writing;
extern ngx_atomic_t  *ngx_stat_waiting;

#endif


// NGX_UPDATE_TIME要求epoll主动更新时间
#define NGX_UPDATE_TIME         1

// 要求事件延后处理，加入post队列，避免处理事件过多地占用负载均衡锁
#define NGX_POST_EVENTS         2


// 在epoll的ngx_epoll_process_events里检查，更新时间的标志
extern sig_atomic_t           ngx_event_timer_alarm;

// 事件模型的基本标志位
// 在ngx_epoll_init里设置为et模式，边缘触发
// NGX_USE_CLEAR_EVENT|NGX_USE_GREEDY_EVENT|NGX_USE_EPOLL_EVENT
extern ngx_uint_t             ngx_event_flags;

extern ngx_module_t           ngx_events_module;
extern ngx_module_t           ngx_event_core_module;


// 函数宏，从cycle的conf_ctx里获得event模块的指针，然后再取数组序号
// 1.15.6之前有隐患，宏末尾多了分号，如果用在函数里就会编译失败
// 应该是个小bug，其他的xxx_get_conf没有分号
// 1.15.6修复
#define ngx_event_get_conf(conf_ctx, module)                                  \
             (*(ngx_get_conf(conf_ctx, ngx_events_module))) [module.ctx_index]



// ngx_event_process_init里设置接受连接的回调函数为ngx_event_accept，可以接受连接
// 监听端口上收到连接请求时的回调函数，即事件handler
// 从cycle的连接池里获取连接
// 关键操作 ls->handler(c);调用其他模块的业务handler
// 例如ngx_http_init_connection,ngx_stream_init_connection
void ngx_event_accept(ngx_event_t *ev);

#if !(NGX_WIN32)
// 1.10新增函数，接受udp连接的handler
void ngx_event_recvmsg(ngx_event_t *ev);
void ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
#endif

// 1.15.7改为非static
// 清理函数，会删除红黑树节点
void ngx_delete_udp_connection(void *data);

// 尝试获取负载均衡锁，监听端口
// 如未获取则不监听端口
// 内部调用ngx_enable_accept_events/ngx_disable_accept_events
ngx_int_t ngx_trylock_accept_mutex(ngx_cycle_t *cycle);

// 遍历监听端口列表，加入epoll连接事件，开始接受请求
ngx_int_t ngx_enable_accept_events(ngx_cycle_t *cycle);

u_char *ngx_accept_log_error(ngx_log_t *log, u_char *buf, size_t len);

#if (NGX_DEBUG)
void ngx_debug_accepted_connection(ngx_event_conf_t *ecf, ngx_connection_t *c);
#endif


// 在ngx_single_process_cycle/ngx_worker_process_cycle里调用
// 处理socket读写事件和定时器事件
// 获取负载均衡锁，监听端口接受连接
// 调用epoll模块的ngx_epoll_process_events获取发生的事件
// 然后处理超时事件和在延后队列里的所有事件
void ngx_process_events_and_timers(ngx_cycle_t *cycle);

// 添加读事件的便捷接口，适合epoll/kqueue/select等各种事件模型
// 内部还是调用ngx_add_event
ngx_int_t ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags);

// 添加写事件的便捷接口，适合epoll/kqueue/select等各种事件模型
// 内部还是调用ngx_add_event,多了个send_lowat操作
// linux不支持send_lowat指令，send_lowat总是0
ngx_int_t ngx_handle_write_event(ngx_event_t *wev, size_t lowat);


#if (NGX_WIN32)
void ngx_event_acceptex(ngx_event_t *ev);
ngx_int_t ngx_event_post_acceptex(ngx_listening_t *ls, ngx_uint_t n);
u_char *ngx_acceptex_log_error(ngx_log_t *log, u_char *buf, size_t len);
#endif


// 设置发送数据时epoll的响应阈值
// 当系统空闲缓冲超过lowat时触发epoll可写事件
// linux不支持send_lowat指令，send_lowat总是0
ngx_int_t ngx_send_lowat(ngx_connection_t *c, size_t lowat);


/* used in ngx_log_debugX() */
#define ngx_event_ident(p)  ((ngx_connection_t *) (p))->fd


#include <ngx_event_timer.h>
#include <ngx_event_posted.h>

#if (NGX_WIN32)
#include <ngx_iocp_module.h>
#endif


#endif /* _NGX_EVENT_H_INCLUDED_ */
