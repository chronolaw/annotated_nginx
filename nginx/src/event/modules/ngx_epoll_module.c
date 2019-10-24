// annotated by chrono since 2016
//
// * ngx_epoll_init
// * ngx_epoll_process_events
// * ngx_epoll_notify
// * ngx_epoll_add_event
// * ngx_epoll_del_event
// * ngx_epoll_add_connection
// * ngx_epoll_del_connection

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 下面这段用于测试epoll功能
// 代码与linux的基本相同，可以参考
#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */

#define EPOLLIN        0x001        //有读事件发生，即可读
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004        //有写事件发生，即可写
#define EPOLLERR       0x008
#define EPOLLHUP       0x010
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400

// EPOLLRDHUP表示客户端关闭连接（断连），也当做读事件处理
// 这时recv返回0
#define EPOLLRDHUP     0x2000

#define EPOLLEXCLUSIVE 0x10000000
#define EPOLLONESHOT   0x40000000
#define EPOLLET        0x80000000   //ET模式，即边缘触发

#define EPOLL_CTL_ADD  1            //添加事件
#define EPOLL_CTL_DEL  2            //删除事件
#define EPOLL_CTL_MOD  3            //修改事件

// epoll系统调用使用的结构体
// nginx只使用ptr，存储连接对象的指针
// 指针最低位用做标志位，存储instance
typedef union epoll_data {
    // union使用ptr成员，关联到连接对象
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};


// 初始化epoll，返回一个句柄，size无意义
int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


// 添加或删除事件，op=EPOLL_CTL_ADD/EPOLL_CTL_DEL/EPOLL_CTL_MOD
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


// 等待注册的事件发生
// 内核把发生的事件拷贝到events数组里，返回值是数量
int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_EVENTFD)
#define SYS_eventfd       323
#endif

// aio暂不研究
#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


#endif
#endif /* NGX_TEST_BUILD_EPOLL */


// epoll模块的配置结构体
typedef struct {
    // epoll系统调用，获取事件的数组大小
    // 对应指令epoll_events
    ngx_uint_t  events;

    // aio暂不研究
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t;


// 调用epoll_create初始化epoll机制, timer无意义
// 参数size=cycle->connection_n / 2，但并无实际意义
// 设置全局变量，操作系统提供的底层数据收发接口
// 初始化全局的事件模块访问接口，指向epoll的函数
// 默认使用et模式，边缘触发，高速
static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);

#if (NGX_HAVE_EVENTFD)
// 调用系统函数eventfd，创建一个可以用于通知的描述符，用于实现notify
static ngx_int_t ngx_epoll_notify_init(ngx_log_t *log);

// 当发生通知事件时的回调函数，再回调真正的功能函数ev->data
static void ngx_epoll_notify_handler(ngx_event_t *ev);
#endif

#if (NGX_HAVE_EPOLLRDHUP)
static void ngx_epoll_test_rdhup(ngx_cycle_t *cycle);
#endif

// epoll模块结束工作，关闭epoll句柄和通知句柄，释放内存
static void ngx_epoll_done(ngx_cycle_t *cycle);

// epoll添加事件
// 检查事件关联的连接对象，决定是新添加还是修改
// 避免误删除了读写事件的关注
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);

// epoll删除事件
// 检查事件关联的连接对象，决定是完全删除还是修改
// 避免误删除了读写事件的关注
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);

// epoll关注连接的读写事件
// 添加事件成功，读写事件都是活跃的，即已经使用
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);

// epoll删除连接的读写事件
// 删除事件成功，读写事件都不活跃
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);

// 使用epoll模拟了事件通知机制
// 向文件里写一个数字，令文件可读，从而触发epoll事件
// 参数handler是真正的业务回调函数
#if (NGX_HAVE_EVENTFD)
static ngx_int_t ngx_epoll_notify(ngx_event_handler_pt handler);
#endif

// epoll模块核心功能，调用epoll_wait处理发生的事件
// 使用event_list和nevents获取内核返回的事件
// timer是无事件发生时最多等待的时间，即超时时间
// 函数可以分为两部分，一是用epoll获得事件，二是处理事件，加入延后队列
// 在ngx_process_events_and_timers里被调用
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

// aio暂不研究
#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

// 创建配置结构体
static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);

// 初始化配置结构体
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

// 以下是epoll使用的变量

// epoll系统调用使用的句柄，由epoll_create()创建
static int                  ep = -1;

// epoll系统调用使用的数组，存储内核返回的事件
// 大小由nevents确定
// 相当于std::vector<epoll_event> event_list;
static struct epoll_event  *event_list;

// event_list数组的大小
static ngx_uint_t           nevents;

// notify使用的变量
#if (NGX_HAVE_EVENTFD)
// 用于多线程通知用的描述符，并不关联实际的socket或者文件
static int                  notify_fd = -1;

// 通知用的事件对象
static ngx_event_t          notify_event;

// 通知用的连接对象，并不关联实际的连接
static ngx_connection_t     notify_conn;
#endif

// aio暂不研究
// 方式与notify类似，也使用一个静态的event和conn
#if (NGX_HAVE_FILE_AIO)

int                         ngx_eventfd = -1;
aio_context_t               ngx_aio_ctx = 0;

static ngx_event_t          ngx_eventfd_event;
static ngx_connection_t     ngx_eventfd_conn;

#endif

#if (NGX_HAVE_EPOLLRDHUP)
ngx_uint_t                  ngx_use_epoll_rdhup;
#endif

// epoll模块的名字
// 用在ngx_epoll_module_ctx里
static ngx_str_t      epoll_name = ngx_string("epoll");

// epoll模块支持的指令，两个
static ngx_command_t  ngx_epoll_commands[] = {

    // event_list数组大小，存储内核返回的事件
    { ngx_string("epoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },

    // aio暂不研究
    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },

      ngx_null_command
};


// epoll模块的函数表
static ngx_event_module_t  ngx_epoll_module_ctx = {
    // epoll模块的名字"epoll"
    &epoll_name,

    // 创建配置结构体
    ngx_epoll_create_conf,               /* create configuration */

    // 初始化配置结构体
    ngx_epoll_init_conf,                 /* init configuration */

    // epoll的事件模块访问接口，是一个函数表
    {
        // epoll添加事件
        // 检查事件关联的连接对象，决定是新添加还是修改
        // 避免误删除了读写事件的关注
        ngx_epoll_add_event,             /* add an event */

        // epoll删除事件
        // 检查事件关联的连接对象，决定是完全删除还是修改
        // 避免误删除了读写事件的关注
        ngx_epoll_del_event,             /* delete an event */

        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */

        // epoll关注连接的读写事件
        // 添加事件成功，读写事件都是活跃的，即已经使用
        ngx_epoll_add_connection,        /* add an connection */

        // epoll删除连接的读写事件
        // 删除事件成功，读写事件都不活跃
        ngx_epoll_del_connection,        /* delete an connection */

#if (NGX_HAVE_EVENTFD)
        // 使用epoll模拟了事件通知机制
        // 向文件里写一个数字，令文件可读，从而触发epoll事件
        // 参数handler是真正的业务回调函数
        ngx_epoll_notify,                /* trigger a notify */
#else
        NULL,                            /* trigger a notify */
#endif
        // epoll模块核心功能，调用epoll_wait处理发生的事件
        // 使用event_list和nevents获取内核返回的事件
        // timer是无事件发生时最多等待的时间，即超时时间
        // 函数可以分为两部分，一是用epoll获得事件，二是处理事件，加入延后队列
        // 函数里不处理定时器，因为定时器不属于epoll事件
        ngx_epoll_process_events,        /* process the events */

        // 调用epoll_create初始化epoll机制, timer无意义
        // 参数size=cycle->connection_n / 2，但并无实际意义
        // 设置全局变量，操作系统提供的底层数据收发接口
        // 初始化全局的事件模块访问接口，指向epoll的函数
        // 默认使用et模式，边缘触发，高速
        ngx_epoll_init,                  /* init the events */

        // epoll模块结束工作，关闭epoll句柄和通知句柄，释放内存
        ngx_epoll_done,                  /* done the events */
    }
};

// epoll模块定义
ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


// aio暂不研究
#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */

static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


static void
ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    ngx_eventfd = eventfd(0, 0);
#else
    ngx_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

    ngx_eventfd_event.data = &ngx_eventfd_conn;
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
    ngx_eventfd_event.log = cycle->log;
    ngx_eventfd_event.active = 1;
    ngx_eventfd_conn.fd = ngx_eventfd;
    ngx_eventfd_conn.read = &ngx_eventfd_event;
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &ngx_eventfd_conn;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
}

#endif


// 调用epoll_create初始化epoll机制, timer无意义
// 参数size=cycle->connection_n / 2，但并无实际意义
// 设置全局变量，操作系统提供的底层数据收发接口
// 初始化全局的事件模块访问接口，指向epoll的函数
// 默认使用et模式，边缘触发，高速
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;

    // 获取epoll模块的配置
    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    // ep == -1表示还没有创建epoll句柄，需要初始化
    if (ep == -1) {
        // 创建epoll句柄
        // 参数size=cycle->connection_n / 2，但并无实际意义
        ep = epoll_create(cycle->connection_n / 2);

        // epoll初始化失败
        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }

#if (NGX_HAVE_EVENTFD)
        // 初始化多线程通知用的描述符和事件/连接
        if (ngx_epoll_notify_init(cycle->log) != NGX_OK) {

            // 如果初始化失败，那么notify指针置空
            ngx_epoll_module_ctx.actions.notify = NULL;
        }
#endif

// aio暂不研究
#if (NGX_HAVE_FILE_AIO)
        ngx_epoll_aio_init(cycle, epcf);
#endif

#if (NGX_HAVE_EPOLLRDHUP)
        ngx_epoll_test_rdhup(cycle);
#endif
    }

    // 检查当前事件数组的大小，最开始nevents是0
    if (nevents < epcf->events) {

        // 如果是reload，那么就先释放，再重新分配内存
        if (event_list) {
            ngx_free(event_list);
        }

        // 相当于vector.resize(cf.events)
        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    // 设置正确的数组长度
    nevents = epcf->events;

    // 设置全局变量，操作系统提供的底层数据收发接口
    // ngx_posix_init.c里初始化为linux的底层接口
    ngx_io = ngx_os_io;

    // 初始化全局的事件模块访问接口，指向epoll的函数
    ngx_event_actions = ngx_epoll_module_ctx.actions;

#if (NGX_HAVE_CLEAR_EVENT)
    // 默认使用et模式，边缘触发，高速
    ngx_event_flags = NGX_USE_CLEAR_EVENT
#else
    ngx_event_flags = NGX_USE_LEVEL_EVENT
#endif
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

// 调用系统函数eventfd，创建一个可以用于通知的描述符，用于实现notify
static ngx_int_t
ngx_epoll_notify_init(ngx_log_t *log)
{
    struct epoll_event  ee;

#if (NGX_HAVE_SYS_EVENTFD_H)
    // 调用系统函数eventfd，创建一个可以用于通知的描述符，用于实现notify
    // 当通知时写入一个数字，触发可读事件
    notify_fd = eventfd(0, 0);
#else
    notify_fd = syscall(SYS_eventfd, 0);
#endif

    if (notify_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "eventfd() failed");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
                   "notify eventfd: %d", notify_fd);

    // 设置通知用的事件对象回调函数
    notify_event.handler = ngx_epoll_notify_handler;
    notify_event.log = log;
    notify_event.active = 1;

    // 设置通知用的连接对象关联的描述符，不用于收发数据
    notify_conn.fd = notify_fd;

    //只有读事件，写事件无意义
    notify_conn.read = &notify_event;
    notify_conn.log = log;

    // 设置epoll事件属性，可读，边缘触发
    ee.events = EPOLLIN|EPOLLET;

    // union使用ptr成员，关联到连接对象
    ee.data.ptr = &notify_conn;

    // 调用epoll_ctl/EPOLL_CTL_ADD，添加epoll事件
    if (epoll_ctl(ep, EPOLL_CTL_ADD, notify_fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

        if (close(notify_fd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                            "eventfd close() failed");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


// 当发生通知事件时的回调函数，再回调真正的功能函数ev->data
static void
ngx_epoll_notify_handler(ngx_event_t *ev)
{
    ssize_t               n;
    uint64_t              count;
    ngx_err_t             err;
    ngx_event_handler_pt  handler;

    // 检查event对象里的index，如果小于0xffffffff则不做任何处理
    // 这样可以节约系统资源，避免多余的操作
    // 注意有个++操作
    if (++ev->index == NGX_MAX_UINT32_VALUE) {
        ev->index = 0;

        // 从描述符里读8个字节
        n = read(notify_fd, &count, sizeof(uint64_t));

        err = ngx_errno;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "read() eventfd %d: %z count:%uL", notify_fd, n, count);

        // 简单地检查一下写入的数字是否正确，只比较长度，不关心内容
        if ((size_t) n != sizeof(uint64_t)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, err,
                          "read() eventfd %d failed", notify_fd);
        }
    }

    // 获取event对象的data成员，转换为函数指针
    // ngx_core.h:typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
    handler = ev->data;

    // 回调真正的功能函数
    handler(ev);
}

#endif


#if (NGX_HAVE_EPOLLRDHUP)

static void
ngx_epoll_test_rdhup(ngx_cycle_t *cycle)
{
    int                 s[2], events;
    struct epoll_event  ee;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "socketpair() failed");
        return;
    }

    ee.events = EPOLLET|EPOLLIN|EPOLLRDHUP;

    if (epoll_ctl(ep, EPOLL_CTL_ADD, s[0], &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll_ctl() failed");
        goto failed;
    }

    if (close(s[1]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
        s[1] = -1;
        goto failed;
    }

    s[1] = -1;

    events = epoll_wait(ep, &ee, 1, 5000);

    if (events == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll_wait() failed");
        goto failed;
    }

    if (events) {
        ngx_use_epoll_rdhup = ee.events & EPOLLRDHUP;

    } else {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, NGX_ETIMEDOUT,
                      "epoll_wait() timed out");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "testing the EPOLLRDHUP flag: %s",
                   ngx_use_epoll_rdhup ? "success" : "fail");

failed:

    if (s[1] != -1 && close(s[1]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
    }

    if (close(s[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() failed");
    }
}

#endif


// epoll模块结束工作，关闭epoll句柄和通知句柄，释放内存
static void
ngx_epoll_done(ngx_cycle_t *cycle)
{
    // 关闭epoll句柄
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NGX_HAVE_EVENTFD)

    // 关闭通知句柄
    if (close(notify_fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    notify_fd = -1;

#endif

// aio暂不研究
#if (NGX_HAVE_FILE_AIO)

    if (ngx_eventfd != -1) {

        if (io_destroy(ngx_aio_ctx) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "io_destroy() failed");
        }

        if (close(ngx_eventfd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "eventfd close() failed");
        }

        ngx_eventfd = -1;
    }

    ngx_aio_ctx = 0;

#endif

    // 释放内存,vector.clear()
    ngx_free(event_list);

    // 置为空指针和0，安全
    event_list = NULL;
    nevents = 0;
}


// epoll添加事件
// 检查事件关联的连接对象，决定是新添加还是修改
// 避免误删除了读写事件的关注
static ngx_int_t
ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    // 获取事件关联的连接对象
    c = ev->data;

    // 计算epoll的标志位
    events = (uint32_t) event;

    // prev是对应事件的标志
    // 添加读事件则查看写事件
    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

        // 读事件的epoll标志
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    // 添加写事件则查看读事件
    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;

        // 写事件的epoll标志
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

    // 如果另外的读写事件是活跃的那么就意味着已经加过了
    // active的设置就在下面的代码里
    // epoll的操作就是修改EPOLL_CTL_MOD
    // 需要加上对应事件的读写标志，即prev
    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

#if (NGX_HAVE_EPOLLEXCLUSIVE && NGX_HAVE_EPOLLRDHUP)
    if (flags & NGX_EXCLUSIVE_EVENT) {
        events &= ~EPOLLRDHUP;
    }
#endif

    // 加上flags标志，里面有ET
    ee.events = events | (uint32_t) flags;

    // union的指针成员，关联到连接对象
    // 因为目前的32位/64位的计算机指针地址低位都是0（字节对齐）
    // 所以用最低位来存储instance标志，即一个bool值
    // 在真正取出连接对象时需要把低位的信息去掉
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    // 到这里，已经确定了是新添加还是修改epoll事件
    // 执行系统调用，添加epoll关注事件
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    // 添加事件成功，此事件就是活跃的，即已经使用
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
}


// epoll删除事件
// 检查事件关联的连接对象，决定是完全删除还是修改
// 避免误删除了读写事件的关注
static ngx_int_t
ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    // 是否是要求事件关闭
    if (flags & NGX_CLOSE_EVENT) {
        // 设置active成员
        ev->active = 0;
        return NGX_OK;
    }

    // 获取事件关联的连接对象
    c = ev->data;

    // prev是对应事件的标志
    // 添加读事件则查看写事件
    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    // 添加写事件则查看读事件
    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }


    // 如果另外的读写事件是活跃的那么就意味着已经加过了
    // active的设置就在下面的代码里
    // epoll的操作就是修改EPOLL_CTL_MOD
    // 需要加上对应事件的读写标志，即prev
    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;

        // union的指针成员，关联到连接对象
        // 因为目前的32位/64位的计算机指针地址低位都是0（字节对齐）
        // 所以用最低位来存储instance标志，即一个bool值
        // 在真正取出连接对象时需要把低位的信息去掉
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        // 对应的读写事件没有，那么就可以删除整个事件
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    // 到这里，已经确定了是删除还是修改epoll事件
    // 执行系统调用，删除epoll关注事件
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    // 删除事件成功，此事件不活跃，即已停止关注
    ev->active = 0;

    return NGX_OK;
}


// epoll关注连接的读写事件
// 添加事件成功，读写事件都是活跃的，即已经使用
static ngx_int_t
ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    // 不区分读写，添加全部标志位，使用et模式
    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;

    // union的指针成员，关联到连接对象
    // 因为目前的32位/64位的计算机指针地址低位都是0（字节对齐）
    // 所以用最低位来存储instance标志，即一个bool值
    // 在真正取出连接对象时需要把低位的信息去掉
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    // 执行系统调用，直接添加epoll关注事件
    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    // 添加事件成功，读写事件都是活跃的，即已经使用
    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
}


// epoll删除连接的读写事件
// 删除事件成功，读写事件都不活跃
static ngx_int_t
ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        // 删除事件成功，读写事件都不活跃
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    // 直接删除所有的事件
    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    // 执行系统调用，直接删除epoll关注事件
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    // 删除事件成功，读写事件都不活跃
    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
}


#if (NGX_HAVE_EVENTFD)

// 使用epoll模拟了事件通知机制
// 向文件里写一个数字，令文件可读，从而触发epoll事件
// 参数handler是真正的业务回调函数
static ngx_int_t
ngx_epoll_notify(ngx_event_handler_pt handler)
{
    // 永远写入数字1，但类型是uint64_t，8个字节
    static uint64_t inc = 1;

    // 设置真正的业务回调函数
    notify_event.data = handler;

    // 向文件里写一个数字，令文件可读，从而触发epoll事件
    if ((size_t) write(notify_fd, &inc, sizeof(uint64_t)) != sizeof(uint64_t)) {
        ngx_log_error(NGX_LOG_ALERT, notify_event.log, ngx_errno,
                      "write() to eventfd %d failed", notify_fd);
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif


// epoll模块核心功能，调用epoll_wait处理发生的事件
// 使用event_list和nevents获取内核返回的事件
// timer是无事件发生时最多等待的时间，即超时时间
// 如果ngx_event_find_timer返回timer==0，那么epoll不会等待，立即返回
// 函数可以分为两部分，一是用epoll获得事件，二是处理事件，加入延后队列
// 函数里不处理定时器，因为定时器不属于epoll事件
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

    // 如果使用负载均衡且抢到了accept锁，那么flags里有NGX_POST_EVENTS标志
    // 如果没有设置更新缓存时间的精度，那么flags里有NGX_UPDATE_TIME

    // 调用epoll_wait处理发生的事件
    // 使用event_list和nevents获取内核返回的事件
    // 返回值events是实际获得的事件数量
    // epoll_wait等待最多timer时间后返回
    // 如果epoll有事件发生，那么等待时间timer无意义，epoll_wait立即返回
    // 如果ngx_event_find_timer返回timer==0，那么epoll不会等待，立即返回
    events = epoll_wait(ep, event_list, (int) nevents, timer);

    // 检查是否发生了错误
    // 如果调用epoll_wait获得了0个或多个事件，就没有错误
    err = (events == -1) ? ngx_errno : 0;

    // 如果要求更新时间，或者收到了更新时间的信号
    // 通常event模块调用时总会传递NGX_UPDATE_TIME，这时就会更新缓存的时间
    // sigalarm信号的处理函数设置ngx_event_timer_alarm变量
    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        // in ngx_times.c，系统调用，更新缓存事件
        ngx_time_update();
    }

    // 错误处理
    if (err) {

        // 错误是由信号中断引起的
        if (err == NGX_EINTR) {

            // 如果是更新时间的信号，那么就不是错误
            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

    // 0个事件，说明nginx没有收到任何请求或者数据收发
    if (events == 0) {
        // #define NGX_TIMER_INFINITE  (ngx_msec_t) -1
        // 不是无限等待，在很短的时间里无事件发生，是正常现象
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        // 无限等待，却没有任何事件， 出错了
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

    // 调用epoll_wait获得了多个事件，存储在event_list里，共events个
    // 遍历event_list数组，逐个处理事件
    for (i = 0; i < events; i++) {

        // 从epoll结构体的union.ptr获得连接对象指针
        c = event_list[i].data.ptr;

        // 因为目前的32位/64位的计算机指针地址低位都是0（字节对齐）
        // 所以用最低位来存储instance标志，即一个bool值
        // 在真正取出连接对象时需要把低位的信息去掉
        instance = (uintptr_t) c & 1;

        // 此时才是真正的连接对象指针
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        // 优先查看连接里的读事件
        rev = c->read;

        // fd == -1描述符无效
        // instance不对，连接有错误
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        // 获取epoll的事件标志
        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        // EPOLLERR|EPOLLHUP是发生了错误
        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);

            /*
             * if the error events were returned, add EPOLLIN and EPOLLOUT
             * to handle the events at least in one active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        // 发生了错误，但没有EPOLLIN|EPOLLOUT的读写事件
        //if ((revents & (EPOLLERR|EPOLLHUP))
        //     && (revents & (EPOLLIN|EPOLLOUT)) == 0)
        //{
        //    /*
        //     * if the error events were returned without EPOLLIN or EPOLLOUT,
        //     * then add these flags to handle the events at least in one
        //     * active handler
        //     */

        //    // 加上一个读写事件，保证后续有handler可以处理
        //    // 实际上会由读事件来处理
        //    revents |= EPOLLIN|EPOLLOUT;
        //}

        // 有读事件，且读事件是可用的
        if ((revents & EPOLLIN) && rev->active) {

#if (NGX_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            // 读事件可用
            rev->ready = 1;

            // nginx 1.17.5新增,用在ngx_recv时检查
            rev->available = -1;

            // 检查此事件是否要延后处理
            // 如果使用负载均衡且抢到accept锁，那么flags里有NGX_POST_EVENTS标志
            // 1.9.x使用reuseport，那么就不延后处理
            if (flags & NGX_POST_EVENTS) {
                // 是否是接受请求的事件，两个延后处理队列
                queue = rev->accept ? &ngx_posted_accept_events
                                    : &ngx_posted_events;

                // 暂不处理，而是加入延后处理队列
                // 加快事件的处理速度，避免其他进程的等待
                // in ngx_event_posted.h,函数宏
                ngx_post_event(rev, queue);

            } else {
                // 不accept的进程不需要入队，直接处理
                // 不延后，立即调用读事件的handler回调函数处理事件
                // 1.9.x reuseport直接处理，省去了入队列出队列的成本，更快
                rev->handler(rev);
            }
        }

        // 读事件处理完后再查看连接里的写事件
        wev = c->write;

        // 有写事件，且写事件是可用的
        if ((revents & EPOLLOUT) && wev->active) {

            // fd == -1描述符无效
            // instance不对，连接有错误
            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            // 写事件可用
            wev->ready = 1;

            // 1.10新增，使用complete标记多线程异步操作已经完成
#if (NGX_THREADS)
            wev->complete = 1;
#endif

            // 检查此事件是否要延后处理
            // 1.9.x使用reuseport，那么就不延后处理
            if (flags & NGX_POST_EVENTS) {
                // 暂不处理，而是加入延后处理队列
                // 加快事件的处理速度，避免其他进程的等待
                // 写事件只有一个队列
                // in ngx_event_posted.h,函数宏
                ngx_post_event(wev, &ngx_posted_events);

            } else {
                // 不accept的进程不需要入队，直接处理
                // 不延后，立即调用写事件的handler回调函数处理事件
                // 1.9.x reuseport直接处理，省去了入队列出队列的成本，更快
                wev->handler(wev);
            }
        }
    }       //for循环结束，处理完epoll_wait获得的内核事件

    return NGX_OK;
}


// aio暂不研究
#if (NGX_HAVE_FILE_AIO)

static void
ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(ngx_eventfd, &ready, 8);

    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %d", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %XL %XL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (ngx_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

                ngx_post_event(e, &ngx_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif


// 创建配置结构体
static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    // 两个值都是数字，所以要置为-1
    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;

    return epcf;
}


// 初始化配置结构体
static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    // 如果不使用epoll_events指令, epcf->events默认是512
    ngx_conf_init_uint_value(epcf->events, 512);

    ngx_conf_init_uint_value(epcf->aio_requests, 32);

    return NGX_CONF_OK;
}
