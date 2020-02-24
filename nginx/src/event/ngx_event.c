// annotated by chrono since 2016
//
// * ngx_process_events_and_timers
// * ngx_event_module_init
// * ngx_event_process_init
// * ngx_handle_read_event
// * ngx_handle_write_event

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 默认的epoll数组长度
// 最多同时处理512个连接，太少
// 通常可以配置到32000或者更多
#define DEFAULT_CONNECTIONS  512


// 各内置事件模块
// rtsig在1.9.x里已经删除

extern ngx_module_t ngx_kqueue_module;
extern ngx_module_t ngx_eventport_module;
extern ngx_module_t ngx_devpoll_module;

// 通常我们在Linux上只使用epoll
extern ngx_module_t ngx_epoll_module;

extern ngx_module_t ngx_select_module;


// 1.15.2之前只检查是否创建了配置结构体，无其他操作
// 因为event模块只有一个events指令
// 1.15.2之后增加新的代码
static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);

// 在ngx_init_cycle里调用，fork子进程之前
// 创建共享内存，存放负载均衡锁和统计用的原子变量
static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);

// 重要！
// fork之后，worker进程初始化时调用，即每个worker里都会执行
// 初始化两个延后处理的事件队列,初始化定时器红黑树
// 发送定时信号，更新时间用
// 初始化cycle里的连接和事件数组
// 设置接受连接的回调函数为ngx_event_accept，可以接受连接
static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);

// 解析events配置块
// 设置事件模块的ctx_index
static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 解析worker_connections指令
// 取得指令字符串,转换为数字
// 再设置到cycle里，即连接池数组的大小
// 决定了nginx同时能够处理的最大连接数量
static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 解析use指令
// 决定使用哪个事件模型，linux上通常是epoll
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 创建event_core模块的配置结构体，成员初始化为unset
static void *ngx_event_core_create_conf(ngx_cycle_t *cycle);

// 所有模块配置解析完毕后，对配置进行初始化
// 如果有的指令没有写，就要给正确的默认值
// 模块默认使用epoll
// 默认不接受多个请求，也就是一次只accept一个连接
// 1.11.3之前默认使用负载均衡锁，之后默认关闭
static char *ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf);


// nginx更新缓存时间的精度，如果设置了会定时发送sigalarm信号更新时间
// ngx_timer_resolution = ccf->timer_resolution;默认值是0
static ngx_uint_t     ngx_timer_resolution;

// 在epoll的ngx_epoll_process_events里检查，更新时间的标志
sig_atomic_t          ngx_event_timer_alarm;

// 事件模块计数器
static ngx_uint_t     ngx_event_max_module;

// 事件模型的基本标志位
// 在ngx_epoll_init里设置为et模式，边缘触发
// NGX_USE_CLEAR_EVENT|NGX_USE_GREEDY_EVENT|NGX_USE_EPOLL_EVENT
// 在ngx_recv.c:ngx_unix_recv里使用，尽量多读数据
ngx_uint_t            ngx_event_flags;

// 全局的事件模块访问接口，是一个函数表
// 定义了若干宏简化对它的操作
// 常用的有ngx_add_event/ngx_del_event
ngx_event_actions_t   ngx_event_actions;


// 连接计数器，使用共享内存，所有worker公用
static ngx_atomic_t   connection_counter = 1;

// ngx_connection_counter初始指向静态变量connection_counter
// 如果是单进程，那么就使用这个静态变量
// 如果是多进程，那么就改指向共享内存里的地址
ngx_atomic_t         *ngx_connection_counter = &connection_counter;

// 1.9.x如果使用了reuseport，那么就会禁用负载均衡锁
// 由linux系统内核来实现负载均衡，选择恰当的进程接受连接
// 由于锁会影响性能，所以1.11.3开始nginx默认不使用锁

// 负载均衡锁指针，初始为空指针
ngx_atomic_t         *ngx_accept_mutex_ptr;

// 负载均衡锁
ngx_shmtx_t           ngx_accept_mutex;

// 负载均衡锁标志量
ngx_uint_t            ngx_use_accept_mutex;

// ngx_accept_events在epoll里不使用，暂不关注
ngx_uint_t            ngx_accept_events;

// 是否已经持有负载均衡锁
// in ngx_event_accept.c:ngx_trylock_accept_mutex
ngx_uint_t            ngx_accept_mutex_held;

// 等待多少时间再次尝试获取负载均衡锁
// ngx_accept_mutex_delay = ecf->accept_mutex_delay;
ngx_msec_t            ngx_accept_mutex_delay;

// ngx_accept_disabled是总连接数的1/8-空闲连接数
// 也就是说空闲连接数小于总数的1/8,那么就暂时停止接受连接
// in ngx_event_accept.c:ngx_event_accept
ngx_int_t             ngx_accept_disabled;


// 统计用的共享内存变量指针
#if (NGX_STAT_STUB)

static ngx_atomic_t   ngx_stat_accepted0;
ngx_atomic_t         *ngx_stat_accepted = &ngx_stat_accepted0;
static ngx_atomic_t   ngx_stat_handled0;
ngx_atomic_t         *ngx_stat_handled = &ngx_stat_handled0;
static ngx_atomic_t   ngx_stat_requests0;
ngx_atomic_t         *ngx_stat_requests = &ngx_stat_requests0;
static ngx_atomic_t   ngx_stat_active0;
ngx_atomic_t         *ngx_stat_active = &ngx_stat_active0;
static ngx_atomic_t   ngx_stat_reading0;
ngx_atomic_t         *ngx_stat_reading = &ngx_stat_reading0;
static ngx_atomic_t   ngx_stat_writing0;
ngx_atomic_t         *ngx_stat_writing = &ngx_stat_writing0;
static ngx_atomic_t   ngx_stat_waiting0;
ngx_atomic_t         *ngx_stat_waiting = &ngx_stat_waiting0;

#endif



// events模块仅支持一个指令，即events块
static ngx_command_t  ngx_events_commands[] = {

    { ngx_string("events"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_events_module_ctx = {
    ngx_string("events"),
    NULL,

    // 1.15.2之前只检查是否创建了配置结构体，无其他操作
    // 因为event模块只有一个events指令
    // 1.15.2之后增加新的代码
    ngx_event_init_conf
};


// ngx_events_module只是组织各具体的事件模块，本身无功能
ngx_module_t  ngx_events_module = {
    NGX_MODULE_V1,
    &ngx_events_module_ctx,                /* module context */
    ngx_events_commands,                   /* module directives */
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


// event_core模块的名字："event_core"
static ngx_str_t  event_core_name = ngx_string("event_core");


static ngx_command_t  ngx_event_core_commands[] = {

    // nginx每个worker进程里的连接池数量，决定了nginx的服务能力
    { ngx_string("worker_connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    // 功能同worker_connections，但已经被废弃，不要使用
    // { ngx_string("connections"),...}

    // 决定使用哪个事件模型，linux上通常是epoll
    { ngx_string("use"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_use,
      0,
      0,
      NULL },

    // 默认不接受多个请求，也就是一次只accept一个连接
    { ngx_string("multi_accept"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, multi_accept),
      NULL },

    // 是否使用负载均衡锁
    // accept_mutex off也是可以的，这样连接快但可能负载不均衡
    // 1.10后支持reuseport，可以不使用此指令
    // 1.11.3后负载均衡锁默认是关闭的
    { ngx_string("accept_mutex"),
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex),
      NULL },

    // 默认负载均衡锁的等待时间是500毫秒
    // 不持有锁的其他进程最多等待500毫秒再尝试抢锁
    { ngx_string("accept_mutex_delay"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex_delay),
      NULL },

    // 是否要针对某些连接打印调试日志
    { ngx_string("debug_connection"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_debug_connection,
      0,
      0,
      NULL },

      ngx_null_command
};


// event_core模块是event模块，不是core模块
// 但它不实现具体的事件模型，所以actions函数表全是空指针
static ngx_event_module_t  ngx_event_core_module_ctx = {
    // event_core模块的名字："event_core"
    &event_core_name,

    // 创建event_core模块的配置结构体，成员初始化为unset
    ngx_event_core_create_conf,            /* create configuration */

    // 所有模块配置解析完毕后，对配置进行初始化
    // 如果有的指令没有写，就要给正确的默认值
    // 模块默认使用epoll
    // 默认不接受多个请求，也就是一次只accept一个连接
    // 1.11.3之前默认使用负载均衡锁，之后默认关闭
    ngx_event_core_init_conf,              /* init configuration */

    // 不实现具体的事件模型，所以actions函数表全是空指针
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


ngx_module_t  ngx_event_core_module = {
    NGX_MODULE_V1,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */

    // 在ngx_init_cycle里调用，fork子进程之前
    // 创建共享内存，存放负载均衡锁和统计用的原子变量
    ngx_event_module_init,                 /* init module */

    // 初始化cycle里的连接和事件数组
    // fork之后，worker进程初始化时调用，即每个worker里都会执行
    // 初始化两个延后处理的事件队列,初始化定时器红黑树
    // 发送定时信号，更新时间用
    // 初始化cycle里的连接和事件数组
    // 设置接受连接的回调函数为ngx_event_accept，可以接受连接
    ngx_event_process_init,                /* init process */

    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 重要！！
// 在ngx_process_cycle.c:ngx_single_process_cycle/ngx_worker_process_cycle里调用
// 处理socket读写事件和定时器事件
// 获取负载均衡锁，监听端口接受连接
// 调用epoll模块的ngx_epoll_process_events获取发生的事件
// 然后处理超时事件和在延后队列里的所有事件
void
ngx_process_events_and_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t  flags;
    ngx_msec_t  timer, delta;

    // ccf->timer_resolution
    // nginx更新缓存时间的精度，如果设置了会定时发送sigalarm信号更新时间
    // ngx_timer_resolution = ccf->timer_resolution;默认值是0
    if (ngx_timer_resolution) {
        // 要求epoll无限等待事件的发生，直至被sigalarm信号中断
        timer = NGX_TIMER_INFINITE;
        flags = 0;

    } else {
        // 没有设置时间精度，默认设置
        // 在定时器红黑树里找到最小的时间，二叉树查找很快
        // timer >0 红黑树里即将超时的事件的时间
        // timer <0 表示红黑树为空，即无超时事件
        // timer==0意味着在红黑树里已经有事件超时了，必须立即处理
        // timer==0，epoll就不会等待，收集完事件立即返回
        timer = ngx_event_find_timer();

        // NGX_UPDATE_TIME要求epoll等待这个时间，然后主动更新时间
        flags = NGX_UPDATE_TIME;

        // nginx 1.9.x不再使用old threads代码
#if (NGX_WIN32)

        /* handle signals from master in case of network inactivity */

        if (timer == NGX_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }

    // 现在已经设置了合适的timer和flag

    // 负载均衡锁标志量， accept_mutex on
    // 1.9.x，如果使用了reuseport，那么ngx_use_accept_mutex==0
    //
    // 1.11.3开始，默认不使用负载均衡锁，提高性能，下面的代码直接跳过
    if (ngx_use_accept_mutex) {
        // ngx_accept_disabled = ngx_cycle->connection_n / 8
        //                      - ngx_cycle->free_connection_n;
        // ngx_accept_disabled是总连接数的1/8-空闲连接数
        // 也就是说空闲连接数小于总数的1/8,那么就暂时停止接受连接
        if (ngx_accept_disabled > 0) {

            // 但也不能永远不接受连接，毕竟还是有空闲连接的，所以每次要减一
            ngx_accept_disabled--;

        } else {
            // 尝试获取负载均衡锁，开始监听端口
            // 如未获取则不监听端口
            // 内部调用ngx_enable_accept_events/ngx_disable_accept_events
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                // 如果监听失败，那么直接结束函数，不处理epoll事件
                return;
            }

            // ngx_trylock_accept_mutex执行成功
            // 使用变量ngx_accept_mutex_held检查是否成功获取了锁

            // 确实已经获得了锁，接下来的epoll的事件需要加入延后队列处理
            // 这样可以尽快释放锁给其他进程，提高运行效率
            if (ngx_accept_mutex_held) {

                // 加上NGX_POST_EVENTS标志
                // epoll获得的所有事件都会加入到ngx_posted_events
                // 待释放锁后再逐个处理，尽量避免过长时间持有锁
                flags |= NGX_POST_EVENTS;

            } else {
                // 未获取到锁
                // 要求epoll无限等待，或者等待时间超过配置的ngx_accept_mutex_delay
                // 也就是说nginx的epoll不会等待超过ngx_accept_mutex_delay的500毫秒
                // 如果epoll有事件发生，那么此等待时间无意义，epoll_wait立即返回
                if (timer == NGX_TIMER_INFINITE
                    || timer > ngx_accept_mutex_delay)
                {
                    // epoll的超时时间最大就是ngx_accept_mutex_delay
                    // ngx_accept_mutex_delay = ecf->accept_mutex_delay;
                    // 如果时间精度设置的太粗，那么就使用这个时间,500毫秒
                    timer = ngx_accept_mutex_delay;
                }
            }
        }
    }   //ngx_use_accept_mutex

    // 如果不使用负载均衡，或者没有抢到锁
    // 那么就不会使用延后处理队列，即没有NGX_POST_EVENTS标志

    // 1.11.3开始，默认不使用负载均衡锁，提高性能
    // 省去了锁操作和队列操作

    // 不管是否获得了负载均衡锁，都要处理事件和定时器
    // 如果获得了负载均衡锁,事件就会多出一个accept事件
    // 否则只有普通的读写事件和定时器事件

    // 1.17.5新增,处理ngx_posted_next_events
    if (!ngx_queue_empty(&ngx_posted_next_events)) {
        ngx_event_move_posted_next(cycle);
        timer = 0;
    }

    // 获取当前的时间，毫秒数
    delta = ngx_current_msec;

    // #define ngx_process_events   ngx_event_actions.process_events
    // 实际上就是ngx_epoll_process_events
    //
    // epoll模块核心功能，调用epoll_wait处理发生的事件
    // 使用event_list和nevents获取内核返回的事件
    // timer是无事件发生时最多等待的时间，即超时时间
    // 如果ngx_event_find_timer返回timer==0，那么epoll不会等待，立即返回
    // 函数可以分为两部分，一是用epoll获得事件，二是处理事件，加入延后队列
    //
    // 如果不使用负载均衡（accept_mutex off）
    // 那么所有IO事件均在此函数里处理，即搜集事件并调用handler
    (void) ngx_process_events(cycle, timer, flags);

    // 在ngx_process_events里缓存的时间肯定已经更新
    // 计算得到epoll一次调用消耗的毫秒数
    delta = ngx_current_msec - delta;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "timer delta: %M", delta);

    // 先处理连接事件，通常只有一个accept的连接
    // in ngx_event_posted.c
    // 实际上调用的就是ngx_event_accept
    // 在http模块里是http.c:ngx_http_init_connection
    //
    // 如果不使用负载均衡（accept_mutex off）或者reuseport
    // 那么此处就是空操作，因为队列为空
    ngx_event_process_posted(cycle, &ngx_posted_accept_events);

    // 释放锁，其他进程可以获取，再监听端口
    // 这里只处理accept事件，工作量小，可以尽快释放锁，供其他进程使用
    if (ngx_accept_mutex_held) {
        // 释放负载均衡锁
        // 其他进程最多等待ngx_accept_mutex_delay毫秒后
        // 再走ngx_trylock_accept_mutex决定端口的监听权
        ngx_shmtx_unlock(&ngx_accept_mutex);
    }

    // 如果消耗了一点时间，那么看看是否定时器里有过期的
    if (delta) {
        // 遍历定时器红黑树，找出所有过期的事件，调用handler处理超时
        // 其中可能有的socket读写超时，那么就结束请求，断开连接
        ngx_event_expire_timers();
    }

    // 接下来处理延后队列里的事件，即调用事件的handler(ev)，收发数据
    // in ngx_event_posted.c
    // 这里因为要处理大量的事件，而且是简单的顺序调用，所以可能会阻塞
    // nginx大部分的工作量都在这里
    // 注意与accept的函数是相同的，但队列不同，即里面的事件不同
    //
    // 如果不使用负载均衡（accept_mutex off）或者reuseport
    // 那么此处就是空操作，因为队列为空
    ngx_event_process_posted(cycle, &ngx_posted_events);
}


// 添加读事件的便捷接口，适合epoll/kqueue/select等各种事件模型
// 内部还是调用ngx_add_event
ngx_int_t
ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
{
    // 使用et模式，epoll/kqueue
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
            if (ngx_del_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT | flags)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->oneshot && !rev->ready) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* iocp */

    return NGX_OK;
}


// 添加写事件的便捷接口，适合epoll/kqueue/select等各种事件模型
// 内部还是调用ngx_add_event,多了个send_lowat操作
// linux不支持send_lowat指令，send_lowat总是0
ngx_int_t
ngx_handle_write_event(ngx_event_t *wev, size_t lowat)
{
    ngx_connection_t  *c;

    if (lowat) {
        c = wev->data;

        // 设置发送数据时epoll的响应阈值
        // 当系统空闲缓冲超过lowat时触发epoll可写事件
        // linux不支持send_lowat指令，send_lowat总是0
        if (ngx_send_lowat(c, lowat) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT,
                              NGX_CLEAR_EVENT | (lowat ? NGX_LOWAT_EVENT : 0))
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* iocp */

    return NGX_OK;
}


// 1.15.2之前只检查是否创建了配置结构体，无其他操作
// 因为event模块只有一个events指令
// 1.15.2之后增加新的代码
static char *
ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
    // 1.15.2新增部分检查代码
#if (NGX_HAVE_REUSEPORT)
    ngx_uint_t        i;
    ngx_listening_t  *ls;
#endif

    // 要求必须有events{}配置块
    // 1.15.2之前只有这一段
    if (ngx_get_conf(cycle->conf_ctx, ngx_events_module) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return NGX_CONF_ERROR;
    }

    // 检查连接数，需要大于监听端口数量
    if (cycle->connection_n < cycle->listening.nelts + 1) {

        /*
         * there should be at least one connection for each listening
         * socket, plus an additional connection for channel
         */

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "%ui worker_connections are not enough "
                      "for %ui listening sockets",
                      cycle->connection_n, cycle->listening.nelts);

        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_REUSEPORT)

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

        if (!ls[i].reuseport || ls[i].worker != 0) {
            continue;
        }

        // reuseport专用的函数，1.8.x没有
        // 拷贝了worker数量个的监听结构体, in ngx_connection.c
        // 从ngx_stream_optimize_servers等函数处转移过来
        if (ngx_clone_listening(cycle, &ls[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /* cloning may change cycle->listening.elts */

        ls = cycle->listening.elts;
    }

#endif

    return NGX_CONF_OK;
}


// 在ngx_init_cycle里调用，fork子进程之前
// 创建共享内存，存放负载均衡锁和统计用的原子变量
static ngx_int_t
ngx_event_module_init(ngx_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    ngx_shm_t            shm;
    ngx_time_t          *tp;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;

    // events模块的配置结构体
    // 实际上是一个存储void*指针的数组
    cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);

    // event_core模块的配置结构体
    // 从数组cf里按序号查找
    ecf = (*cf)[ngx_event_core_module.ctx_index];

    // 上面的两行代码相当于:
    // ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module)

    if (!ngx_test_config && ngx_process <= NGX_PROCESS_MASTER) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    // core模块的配置结构体
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // 获取核心配置的时间精度，用在epoll里更新缓存时间
    ngx_timer_resolution = ccf->timer_resolution;

    // unix专用代码, 可打开的最多文件描述符
#if !(NGX_WIN32)
    {
    ngx_int_t      limit;
    struct rlimit  rlmt;

    // 系统调用getrlimit，Linux内核对进程的限制
    // RLIMIT_NOFILE,进程可打开的最大文件描述符数量，超出将产生EMFILE错误
    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {

        // 系统调用失败则记录alert级别日志
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {
        // 成功获取内核参数
        //
        // rlmt.rlim_cur是系统的软限制
        // event里配置的连接数不能超过系统内核限制
        // 或者是配置的rlimit_nofile限制
        if (ecf->connections > (ngx_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == NGX_CONF_UNSET
                || ecf->connections > (ngx_uint_t) ccf->rlimit_nofile))
        {
            // 如果超过了报警告级别日志
            // limit就是上限
            limit = (ccf->rlimit_nofile == NGX_CONF_UNSET) ?
                         (ngx_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections exceed "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(NGX_WIN32) */


    // 如果非master/worker进程，即只启动一个进程，那么就没必要使用负载均衡锁
    if (ccf->master == 0) {
        return NGX_OK;
    }

    // 已经有了负载均衡锁，已经初始化过了，就没必要再做操作
    if (ngx_accept_mutex_ptr) {
        return NGX_OK;
    }


    /* cl should be equal to or greater than cache line size */

    // cl是一个基本长度，可以容纳原子变量
    // 对齐到cache line，操作更快
    cl = 128;

    // 最基本的三个：负载均衡锁，连接计数器,
    size = cl            /* ngx_accept_mutex */
           + cl          /* ngx_connection_counter */
           + cl;         /* ngx_temp_number */

    // 其他统计用的原子变量
#if (NGX_STAT_STUB)

    size += cl           /* ngx_stat_accepted */
           + cl          /* ngx_stat_handled */
           + cl          /* ngx_stat_requests */
           + cl          /* ngx_stat_active */
           + cl          /* ngx_stat_reading */
           + cl          /* ngx_stat_writing */
           + cl;         /* ngx_stat_waiting */

#endif

    // 创建共享内存，存放负载均衡锁和统计用的原子变量
    // 因为内存很小，而且仅用做统计，比较简单
    // 所以不用slab管理
    shm.size = size;
    ngx_str_set(&shm.name, "nginx_shared_zone");
    shm.log = cycle->log;

    // 分配一块共享内存
    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    // shared是共享内存的地址指针
    shared = shm.addr;

    // 第一个就是负载均衡锁
    ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;

    // spin是-1则不使用信号量
    // 只会自旋，不会导致进程睡眠等待
    // 这样避免抢accept锁时的性能降低
    ngx_accept_mutex.spin = (ngx_uint_t) -1;

    // 初始化互斥锁
    // spin是-1则不使用信号量
    // 只会自旋，不会导致进程睡眠等待
    if (ngx_shmtx_create(&ngx_accept_mutex, (ngx_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    // 连接计数器
    ngx_connection_counter = (ngx_atomic_t *) (shared + 1 * cl);

    // 计数器置1
    (void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %uA",
                   ngx_connection_counter, *ngx_connection_counter);

    // 临时文件用
    ngx_temp_number = (ngx_atomic_t *) (shared + 2 * cl);

    tp = ngx_timeofday();

    // 随机数
    // 每个进程不同
    ngx_random_number = (tp->msec << 16) + ngx_pid;

#if (NGX_STAT_STUB)

    ngx_stat_accepted = (ngx_atomic_t *) (shared + 3 * cl);
    ngx_stat_handled = (ngx_atomic_t *) (shared + 4 * cl);
    ngx_stat_requests = (ngx_atomic_t *) (shared + 5 * cl);
    ngx_stat_active = (ngx_atomic_t *) (shared + 6 * cl);
    ngx_stat_reading = (ngx_atomic_t *) (shared + 7 * cl);
    ngx_stat_writing = (ngx_atomic_t *) (shared + 8 * cl);
    ngx_stat_waiting = (ngx_atomic_t *) (shared + 9 * cl);

#endif

    return NGX_OK;
}


#if !(NGX_WIN32)

// sigalarm信号的处理函数，只设置ngx_event_timer_alarm变量
// 在epoll的ngx_epoll_process_events里检查，更新时间的标志
// 信号处理函数应该尽量简单，避免阻塞进程
static void
ngx_timer_signal_handler(int signo)
{
    ngx_event_timer_alarm = 1;

#if 1
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
#endif
}

#endif


// fork之后，worker进程初始化时调用，即每个worker里都会执行
// 初始化两个延后处理的事件队列,初始化定时器红黑树
// 发送定时信号，更新时间用
// 初始化cycle里的连接和事件数组
// 设置接受连接的回调函数为ngx_event_accept，可以接受连接
static ngx_int_t
ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           m, i;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *ls;
    ngx_connection_t    *c, *next, *old;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;

    // core模块的配置结构体
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    // event_core模块的配置结构体
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    // 使用master/worker多进程，使用负载均衡
    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {

        // 设置全局变量
        // 使用负载均衡，刚开始未持有锁，设置抢锁的等待时间
        ngx_use_accept_mutex = 1;
        ngx_accept_mutex_held = 0;
        ngx_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        // 单进程、未明确指定负载均衡，就不使用负载均衡
        ngx_use_accept_mutex = 0;
    }

#if (NGX_WIN32)

    /*
     * disable accept mutex on win32 as it may cause deadlock if
     * grabbed by a process which can't accept connections
     */

    ngx_use_accept_mutex = 0;

#endif

    // 初始化两个延后处理的事件队列
    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);

    // 初始化定时器红黑树
    if (ngx_event_timer_init(cycle->log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    // 遍历事件模块，但只执行实际使用的事件模块对应初始化函数
    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        // 找到use指令使用的事件模型，或者是默认事件模型
        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        // 找到事件模块

        module = cycle->modules[m]->ctx;

        // 调用事件模块的事件初始化函数
        //
        // 调用epoll_create初始化epoll机制
        // 参数size=cycle->connection_n / 2，但并无实际意义
        // 设置全局变量，操作系统提供的底层数据收发接口
        // 初始化全局的事件模块访问接口，指向epoll的函数
        // 默认使用et模式，边缘触发，高速
        if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) {
            /* fatal */
            exit(2);
        }

        // 找到一个事件模块即退出循环
        // 也就是说只能使用一种事件模型
        break;
    }

// unix代码, 发送定时信号，更新时间用
#if !(NGX_WIN32)

    // NGX_USE_TIMER_EVENT标志量只有eventport/kqueue,epoll无此标志位
    // ngx_timer_resolution = ccf->timer_resolution;默认值是0
    // 所以只有使用了timer_resolution指令才会发信号
    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        struct sigaction  sa;
        struct itimerval  itv;

        // 设置信号掩码，sigalarm
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = ngx_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(SIGALRM) failed");
            return NGX_ERROR;
        }

        // 设置信号发送的时间间隔，也就是nginx的时间精度
        // 收到信号会设置设置ngx_event_timer_alarm变量
        // 在epoll的ngx_epoll_process_events里检查，更新时间的标志
        itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
        itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = ngx_timer_resolution / 1000;
        itv.it_value.tv_usec = (ngx_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setitimer() failed");
        }
    }

    // poll, /dev/poll进入这个分支处理
    if (ngx_event_flags & NGX_USE_FD_EVENT) {
        struct rlimit  rlmt;

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return NGX_ERROR;
        }

        cycle->files_n = (ngx_uint_t) rlmt.rlim_cur;

        cycle->files = ngx_calloc(sizeof(ngx_connection_t *) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return NGX_ERROR;
        }
    }

#else

    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "the \"timer_resolution\" directive is not supported "
                      "with the configured event method, ignored");
        ngx_timer_resolution = 0;
    }

#endif

    // 创建连接池数组，大小是cycle->connection_n
    // 直接使用malloc分配内存，没有使用内存池
    cycle->connections =
        ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return NGX_ERROR;
    }

    c = cycle->connections;

    // 创建读事件池数组，大小是cycle->connection_n
    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NGX_ERROR;
    }

    // 读事件对象初始化
    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
    }

    // 创建写事件池数组，大小是cycle->connection_n
    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return NGX_ERROR;
    }

    // 写事件对象初始化
    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
    }

    // i是数组的末尾
    i = cycle->connection_n;
    next = NULL;

    // 把连接对象与读写事件关联起来
    // 注意i是数组的末尾，从最后遍历
    do {
        i--;

        // 使用data成员，把连接对象串成链表
        c[i].data = next;

        // 读写事件
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];

        // 连接的描述符是-1，表示无效
        c[i].fd = (ngx_socket_t) -1;

        // next指针指向数组的前一个元素
        next = &c[i];
    } while (i);

    // 连接对象已经串成链表，现在设置空闲链表指针
    // 此时next指向连接对象数组的第一个元素
    cycle->free_connections = next;

    // 连接没有使用，全是空闲连接
    cycle->free_connection_n = cycle->connection_n;

    /* for each listening socket */

    // 为每个监听端口分配一个连接对象
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

#if (NGX_HAVE_REUSEPORT)
        // 注意这里
        // 只有worker id是本worker的listen才会enable
        // 也就是说虽然克隆了多个listening，但只有一个会enable
        // 即reuseport的端口只会在某个worker进程监听
        if (ls[i].reuseport && ls[i].worker != ngx_worker) {
            continue;
        }
#endif

        // 获取一个空闲连接
        c = ngx_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return NGX_ERROR;
        }

        c->type = ls[i].type;
        c->log = &ls[i].log;

        // 连接的listening对象
        // 两者相互连接
        c->listening = &ls[i];
        ls[i].connection = c;

        // 监听端口只关心读事件
        rev = c->read;

        rev->log = c->log;

        // 设置accept标志，接受连接
        rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (ngx_del_event(old->read, NGX_READ_EVENT, NGX_CLOSE_EVENT)
                    == NGX_ERROR)
                {
                    return NGX_ERROR;
                }

                old->fd = (ngx_socket_t) -1;
            }
        }

#if (NGX_WIN32)

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            ngx_iocp_conf_t  *iocpcf;

            rev->handler = ngx_event_acceptex;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ls[i].log.handler = ngx_acceptex_log_error;

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

        } else {
            rev->handler = ngx_event_accept;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

#else

        // 重要！！
        // 设置接受连接的回调函数为ngx_event_accept
        // 监听端口上收到连接请求时的回调函数，即事件handler
        // 从cycle的连接池里获取连接
        // 关键操作 ls->handler(c);调用其他模块的业务handler
        // 1.10使用ngx_event_recvmsg接收udp
        rev->handler = (c->type == SOCK_STREAM) ? ngx_event_accept
                                                : ngx_event_recvmsg;

#if (NGX_HAVE_REUSEPORT)

        // reuseport无视负载均衡，直接开始监听
        if (ls[i].reuseport) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            continue;
        }

#endif

        // 如果使用负载均衡，不向epoll添加事件，只有抢到锁才添加
        if (ngx_use_accept_mutex) {
            continue;
        }

#if (NGX_HAVE_EPOLLEXCLUSIVE)

        if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
            && ccf->worker_processes > 1)
        {
            // nginx 1.9.x不再使用rtsig

            // 单进程、未明确指定负载均衡，不使用负载均衡
            // 直接加入epoll事件，开始监听，可以接受请求
            // 如果支持EPOLLEXCLUSIVE，使用特殊的标志位
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_EXCLUSIVE_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            // 跳过下面的普通add event
            continue;
        }

#endif

        // 单进程、未明确指定负载均衡，不使用负载均衡
        // 直接加入epoll事件，开始监听，可以接受请求
        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

#endif

    } // 为每个监听端口分配一个连接对象循环结束

    return NGX_OK;
}


// 设置发送数据时epoll的响应阈值
// 当系统空闲缓冲超过lowat时触发epoll可写事件
// linux不支持send_lowat指令，send_lowat总是0，即随时可写
// ngx_handle_write_event()里调用
ngx_int_t
ngx_send_lowat(ngx_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (NGX_HAVE_LOWAT_EVENT)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return NGX_OK;
    }

#endif

    // 如果阈值是0,或者已经设置过了，就直接返回
    if (lowat == 0 || c->sndlowat) {
        return NGX_OK;
    }

    sndlowat = (int) lowat;

    // 设置socket参数
    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1)
    {
        ngx_connection_error(c, ngx_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return NGX_ERROR;
    }

    // 标志位
    c->sndlowat = 1;

    return NGX_OK;
}


// 解析events配置块
// 设置事件模块的ctx_index
static char *
ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    ngx_uint_t            i;
    ngx_conf_t            pcf;
    ngx_event_module_t   *m;

    // 不允许出现两个events配置块
    // conf实际上是个二维数组，所以是void**
    if (*(void **) conf) {
        return "is duplicate";
    }

    /* count the number of the event modules and set up their indices */

    // 得到所有的事件模块数量
    // 设置事件模块的ctx_index
    ngx_event_max_module = ngx_count_modules(cf->cycle, NGX_EVENT_MODULE);

    // ctx是void***，也就是void** *，即指向二维数组的指针
    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    // 分配存储事件模块配置的数组
    *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    // 在cycle里存储这个指针
    *(void **) conf = ctx;

    // 对每一个事件模块调用create_conf创建配置结构体
    // 事件模块的层次很简单，没有多级，所以二维数组就够了
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        // 调用create_conf创建配置结构体
        if (m->create_conf) {
            (*ctx)[cf->cycle->modules[i]->ctx_index] =
                                                     m->create_conf(cf->cycle);
            if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    // 暂存当前的解析上下文
    pcf = *cf;

    // 设置事件模块的新解析上下文
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;

    // 递归解析事件相关模块
    rv = ngx_conf_parse(cf, NULL);

    // 恢复之前保存的解析上下文
    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    // 解析完毕，需要初始化配置，即给默认值
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle,
                              (*ctx)[cf->cycle->modules[i]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


// 取得指令字符串,转换为数字
// 再设置到cycle里，即连接池数组的大小
static char *
ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_str_t  *value;

    if (ecf->connections != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    // 取得指令字符串
    value = cf->args->elts;

    // 转换为数字
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    // 再设置到cycle里，即连接池数组的大小
    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}


// 决定使用哪个事件模型，linux上通常是epoll
static char *
ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             m;
    ngx_str_t            *value;
    ngx_event_conf_t     *old_ecf;
    ngx_event_module_t   *module;

    if (ecf->use != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    // 取得指令字符串
    value = cf->args->elts;

    // 看old_cycle里的event_core配置
    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }


    // 在模块数组里遍历，找事件模块
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        // 取事件模块的函数表，里面有名字
        module = cf->cycle->modules[m]->ctx;
        if (module->name->len == value[1].len) {
            // 长度和名字都一样，即use这个事件模块
            if (ngx_strcmp(module->name->data, value[1].data) == 0) {

                // 设置event_core配置结构体里的use成员为此模块的ctx_index
                ecf->use = cf->cycle->modules[m]->ctx_index;

                // 设置event_core配置结构体里的name成员为此模块的name
                ecf->name = module->name->data;

                // 如果是单进程模式，不允许reload切换事件模型
                if (ngx_process == NGX_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


// 是否要针对某些连接打印调试日志
// 只能在debug模式里开启
// configure --with-debug
static char *
ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // 条件编译宏，只能在debug模式里开启
#if (NGX_DEBUG)
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    // 参数转化为ip地址形式
    rc = ngx_ptocidr(&value[1], &c);

    // 格式正确则加入数组
    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }


    // rc == NGX_ERROR

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    // 格式正确则加入数组
    cidr = ngx_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "nginx using --with-debug option to enable it");

#endif

    return NGX_CONF_OK;
}


// 创建event_core模块的配置结构体，成员初始化为unset
static void *
ngx_event_core_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = NGX_CONF_UNSET_UINT;
    ecf->use = NGX_CONF_UNSET_UINT;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->accept_mutex = NGX_CONF_UNSET;
    ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
    ecf->name = (void *) NGX_CONF_UNSET;

#if (NGX_DEBUG)

    if (ngx_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(ngx_cidr_t)) == NGX_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


// 所有模块配置解析完毕后，对配置进行初始化
// 如果有的指令没有写，就要给正确的默认值
// 模块默认使用epoll
// 默认不接受多个请求，也就是一次只accept一个连接
// 1.11.3之前默认使用负载均衡锁，之后默认关闭
static char *
ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
    int                  fd;
#endif

    // rtsig在nginx 1.9.x已经删除

    ngx_int_t            i;
    ngx_module_t        *module;
    ngx_event_module_t  *event_module;

    module = NULL;

// 测试epoll是否可用
#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    // epoll调用可用，那么模块默认使用epoll
    if (fd != -1) {
        (void) close(fd);
        // epoll调用可用，那么模块默认使用epoll
        module = &ngx_epoll_module;

    } else if (ngx_errno != NGX_ENOSYS) {
        // epoll调用可用，那么模块默认使用epoll
        module = &ngx_epoll_module;
    }

#endif

    // rtsig在nginx 1.9.x已经删除

#if (NGX_HAVE_DEVPOLL) && !(NGX_TEST_BUILD_DEVPOLL)

    module = &ngx_devpoll_module;

#endif

#if (NGX_HAVE_KQUEUE)

    module = &ngx_kqueue_module;

#endif

    // 如果epoll不可用，那么默认使用select
#if (NGX_HAVE_SELECT)

    if (module == NULL) {
        module = &ngx_select_module;
    }

#endif

    // 还没有决定默认的事件模型
    if (module == NULL) {
        // 遍历所有的事件模块
        for (i = 0; cycle->modules[i]; i++) {

            if (cycle->modules[i]->type != NGX_EVENT_MODULE) {
                continue;
            }

            event_module = cycle->modules[i]->ctx;

            // 跳过event_core模块
            if (ngx_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            // 使用数组里的第一个事件模块
            module = cycle->modules[i];
            break;
        }
    }

    // 最后还没有决定默认的事件模型，出错
    if (module == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
        return NGX_CONF_ERROR;
    }

    // nginx每个进程可使用的连接数量，即cycle里的连接池大小
    ngx_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);

    // 如果没有使用worker_connections指令，在这里设置
    cycle->connection_n = ecf->connections;

    // 决定使用的事件模型,之前的module只作为默认值，如果已经使用了use则无效
    ngx_conf_init_uint_value(ecf->use, module->ctx_index);

    // 初始化使用的事件模块的名字
    event_module = module->ctx;
    ngx_conf_init_ptr_value(ecf->name, event_module->name->data);

    // 默认不接受多个请求，也就是一次只accept一个连接
    ngx_conf_init_value(ecf->multi_accept, 0);

    // 1.11.3之前默认使用负载均衡锁，之后默认关闭
    ngx_conf_init_value(ecf->accept_mutex, 0);

    // 默认负载均衡锁的等待时间是500毫秒
    ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);

    return NGX_CONF_OK;
}
