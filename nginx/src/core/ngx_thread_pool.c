// annotated by chrono since 2016
//
// * ngx_thread_pool_s
// * ngx_thread_pool_done
// * ngx_thread_task_post
// * ngx_thread_pool_cycle
// * ngx_thread_pool_handler
// * ngx_thread_pool_init

/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_thread_pool.h>


// 线程池模块的配置，里面是个数组，元素为ngx_thread_pool_t
// 由ngx_thread_pool_add在解析指令的ngx_thread_pool里添加
typedef struct {
    ngx_array_t               pools;
} ngx_thread_pool_conf_t;


// 线程池使用的任务队列
// 与ngx_queue不同，不是侵入式节点，而是首尾指针
typedef struct {
    ngx_thread_task_t        *first;
    ngx_thread_task_t       **last;
} ngx_thread_pool_queue_t;

// 初始化线程池任务队列，first/last都是空
// 与ngx_queue_init不同
#define ngx_thread_pool_queue_init(q)                                         \
    (q)->first = NULL;                                                        \
    (q)->last = &(q)->first


// 描述一个线程池，与thread_pool指令对应
// 此结构体的实际定义在c文件里，外部不可见，深度定制则不方便
// 存储在ngx_thread_pool_conf_t里的数组里
// 核心成员是queue，存储待处理任务
struct ngx_thread_pool_s {
    // 互斥量
    // 锁定互斥量，防止多线程操作的竞态
    // 锁定操作waiting/queue/ngx_thread_pool_task_id
    ngx_thread_mutex_t        mtx;

    // 线程池里的待处理任务队列
    // ngx_thread_task_post把任务放入线程池
    // ngx_thread_pool_cycle消费任务
    ngx_thread_pool_queue_t   queue;

    // 等待的任务数
    ngx_int_t                 waiting;

    // 条件变量,用于等待任务队列queue
    ngx_thread_cond_t         cond;

    // 日志对象，多线程操作也是安全的
    ngx_log_t                *log;

    // 线程池的名字
    ngx_str_t                 name;

    // 线程的数量，默认为32个线程
    ngx_uint_t                threads;

    // 任务等待队列，默认是65535
    ngx_int_t                 max_queue;

    // 定义线程池的配置文件
    u_char                   *file;

    // 定义线程池指令的行号
    ngx_uint_t                line;
};


// 使用ngx_thread_pool_t结构体初始化线程池
// 在init_worker时被调用
// 创建互斥量、条件变量，根据配置的线程数量，创建线程
// 线程的执行函数是ngx_thread_pool_cycle，参数是线程池结构体
static ngx_int_t ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log,
    ngx_pool_t *pool);

// 销毁线程池
// 使用一个要求线程结束的task，发给池里所有的线程
// 最后销毁条件变量和互斥量
static void ngx_thread_pool_destroy(ngx_thread_pool_t *tp);

// 要求线程结束的任务，调用pthread_exit
static void ngx_thread_pool_exit_handler(void *data, ngx_log_t *log);

// 线程池里每个线程执行的函数，无限循环
// 参数是线程池结构体
// 从待处理任务队列里获取任务，然后执行task->handler(task->ctx)
// 处理完的任务加入完成队列
static void *ngx_thread_pool_cycle(void *data);

// 分发处理线程完成的任务，在主线程里执行
// 调用event->handler，即异步事件完成后的回调函数
static void ngx_thread_pool_handler(ngx_event_t *ev);

// 解析thread_pool指令，设置线程数和队列数（默认65535）
static char *ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 创建线程池模块的配置，里面是个数组，元素为ngx_thread_pool_t
static void *ngx_thread_pool_create_conf(ngx_cycle_t *cycle);

// 检查配置的线程池，必须设置线程数量
static char *ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf);

// ngx_single_process_cycle/ngx_worker_process_cycle里调用
// 进程开始时初始化，创建线程池
static ngx_int_t ngx_thread_pool_init_worker(ngx_cycle_t *cycle);

// 进程结束时被调用，清理线程池
// 调用ngx_thread_pool_destroy逐个销毁线程池
static void ngx_thread_pool_exit_worker(ngx_cycle_t *cycle);


// 线程池模块属于core模块，只有一个指令，配置有名的线程池
// 解析thread_pool指令，设置线程数和队列数（默认65535）
static ngx_command_t  ngx_thread_pool_commands[] = {

    { ngx_string("thread_pool"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE23,
      ngx_thread_pool,
      0,
      0,
      NULL },

      ngx_null_command
};


// 线程池模块属于core模块，只有一个指令，配置有名的线程池
static ngx_core_module_t  ngx_thread_pool_module_ctx = {
    ngx_string("thread_pool"),

    // 创建线程池模块的配置，里面是个数组，元素为ngx_thread_pool_t
    ngx_thread_pool_create_conf,

    // 检查配置的线程池，必须设置线程数量
    ngx_thread_pool_init_conf
};


ngx_module_t  ngx_thread_pool_module = {
    NGX_MODULE_V1,
    &ngx_thread_pool_module_ctx,           /* module context */
    ngx_thread_pool_commands,              /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */

    // ngx_single_process_cycle/ngx_worker_process_cycle里调用
    // 进程开始时初始化，创建线程池
    ngx_thread_pool_init_worker,           /* init process */

    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */

    // 进程结束时被调用，清理线程池
    // 调用ngx_thread_pool_destroy逐个销毁线程池
    ngx_thread_pool_exit_worker,           /* exit process */

    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 默认线程池，有32个线程
static ngx_str_t  ngx_thread_pool_default = ngx_string("default");

// 全局计数器,生成task的id
static ngx_uint_t               ngx_thread_pool_task_id;

// 自旋锁保护完成队列ngx_thread_pool_done
static ngx_atomic_t             ngx_thread_pool_done_lock;

// 处理完毕（handler(ctx)）的任务都放到这里
// 使用ngx_thread_pool_done_lock保护
static ngx_thread_pool_queue_t  ngx_thread_pool_done;


// 使用ngx_thread_pool_t结构体初始化线程池
// 在init_worker时被调用
// 创建互斥量、条件变量，根据配置的线程数量，创建线程
// 线程的执行函数是ngx_thread_pool_cycle，参数是线程池结构体
static ngx_int_t
ngx_thread_pool_init(ngx_thread_pool_t *tp, ngx_log_t *log, ngx_pool_t *pool)
{
    int             err;
    pthread_t       tid;
    ngx_uint_t      n;
    pthread_attr_t  attr;

    // 要求必须有事件通知函数ngx_notify
    // 否则多线程无法工作
    // 调用系统函数eventfd，创建一个可以用于通知的描述符
    if (ngx_notify == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0,
               "the configured event method cannot be used with thread pools");
        return NGX_ERROR;
    }

    // 初始化线程池任务队列，first/last都是空
    ngx_thread_pool_queue_init(&tp->queue);

    // 系统调用创建互斥量
    if (ngx_thread_mutex_create(&tp->mtx, log) != NGX_OK) {
        return NGX_ERROR;
    }

    // 系统调用创建条件变量
    if (ngx_thread_cond_create(&tp->cond, log) != NGX_OK) {
        (void) ngx_thread_mutex_destroy(&tp->mtx, log);
        return NGX_ERROR;
    }

    // 线程池使用的log由外部传入
    tp->log = log;

    // 系统调用，初始化一个线程对象的属性
    err = pthread_attr_init(&attr);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_init() failed");
        return NGX_ERROR;
    }

    // 线程detach
    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_setdetachstate() failed");
        return NGX_ERROR;
    }

#if 0
    err = pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, log, err,
                      "pthread_attr_setstacksize() failed");
        return NGX_ERROR;
    }
#endif

    // 根据配置的线程数量，创建线程
    for (n = 0; n < tp->threads; n++) {

        // 线程的执行函数是ngx_thread_pool_cycle，参数是线程池结构体
        // 线程创建后立即detach
        err = pthread_create(&tid, &attr, ngx_thread_pool_cycle, tp);
        if (err) {
            ngx_log_error(NGX_LOG_ALERT, log, err,
                          "pthread_create() failed");
            return NGX_ERROR;
        }
    }

    // 销毁线程属性对象
    (void) pthread_attr_destroy(&attr);

    return NGX_OK;
}


// 销毁线程池
// 使用一个要求线程结束的task，发给池里所有的线程
// 最后销毁条件变量和互斥量
static void
ngx_thread_pool_destroy(ngx_thread_pool_t *tp)
{
    ngx_uint_t           n;
    ngx_thread_task_t    task;

    // lock是一个简单的标志量，作为任务的ctx传递
    volatile ngx_uint_t  lock;

    // 创建要求线程结束的task
    ngx_memzero(&task, sizeof(ngx_thread_task_t));

    // 要求线程结束的任务，调用pthread_exit
    task.handler = ngx_thread_pool_exit_handler;

    // lock是一个简单的标志量，作为任务的ctx传递
    task.ctx = (void *) &lock;

    // 发送tp->threads个task，逐个结束所有的线程
    for (n = 0; n < tp->threads; n++) {
        lock = 1;

        // 把任务加入到线程池的队列
        if (ngx_thread_task_post(tp, &task) != NGX_OK) {
            return;
        }

        // 等待task被某个线程处理，从而结束一个线程
        while (lock) {
            // ngx_process.h:#define ngx_sched_yield()  sched_yield()
            // 避免占用cpu，让出主线程执行权，其他线程有机会执行
            ngx_sched_yield();
        }

        // event.active表示任务是否已经放入任务队列
        // 如果event.active==1则ngx_thread_task_post失败
        task.event.active = 0;
    }

    // 销毁条件变量
    (void) ngx_thread_cond_destroy(&tp->cond, tp->log);

    // 销毁互斥量
    (void) ngx_thread_mutex_destroy(&tp->mtx, tp->log);
}


// 要求线程结束的任务，调用pthread_exit
// 把任务需要处理的data置为0，表示线程结束
static void
ngx_thread_pool_exit_handler(void *data, ngx_log_t *log)
{
    ngx_uint_t *lock = data;

    *lock = 0;

    pthread_exit(0);
}


// 创建一个线程任务结构体
// 参数size是用户数据ctx的大小，位于task之后
// 因为C的内存布局是平坦的，所以使用这种hack的方法来扩展task结构体
ngx_thread_task_t *
ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{
    ngx_thread_task_t  *task;

    // 注意，多分配了size个字节，即用户要求的ctx大小
    task = ngx_pcalloc(pool, sizeof(ngx_thread_task_t) + size);
    if (task == NULL) {
        return NULL;
    }

    // 设置task的ctx指针，即在task地址之后的位置
    task->ctx = task + 1;

    return task;
}


// 把任务放入线程池，由线程执行
// 锁定互斥量，防止多线程操作的竞态
// 如果等待处理的任务数大于设置的最大队列数,那么添加任务失败
// 操作完waiting、queue、ngx_thread_pool_task_id后解锁
ngx_int_t
ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
{
    // event.active表示任务是否已经放入任务队列
    // 如果event.active==1则ngx_thread_task_post失败
    if (task->event.active) {
        ngx_log_error(NGX_LOG_ALERT, tp->log, 0,
                      "task #%ui already active", task->id);
        return NGX_ERROR;
    }

    // 锁定互斥量，防止多线程操作的竞态
    if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
        return NGX_ERROR;
    }

    // 如果等待处理的任务数大于设置的最大队列数
    // 那么添加任务失败
    if (tp->waiting >= tp->max_queue) {
        (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);

        ngx_log_error(NGX_LOG_ERR, tp->log, 0,
                      "thread pool \"%V\" queue overflow: %i tasks waiting",
                      &tp->name, tp->waiting);
        return NGX_ERROR;
    }

    // event.active表示任务是否已经放入任务队列
    // 如果event.active==1则ngx_thread_task_post失败
    task->event.active = 1;

    // task id 增加
    // 全局计数器,生成task的id
    task->id = ngx_thread_pool_task_id++;
    task->next = NULL;

    // 条件变量，发送信号
    // 在ngx_thread_pool_cycle里解除对队列的等待
    if (ngx_thread_cond_signal(&tp->cond, tp->log) != NGX_OK) {
        (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
        return NGX_ERROR;
    }

    // 把任务加入待处理队列
    *tp->queue.last = task;
    tp->queue.last = &task->next;

    // 等待处理的任务数增加
    tp->waiting++;

    // 操作完waiting、queue、ngx_thread_pool_task_id后解锁
    (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                   "task #%ui added to thread pool \"%V\"",
                   task->id, &tp->name);

    return NGX_OK;
}


// 线程池里每个线程执行的函数，无限循环
// 参数是线程池结构体
// 从待处理任务队列里获取任务，然后执行task->handler(task->ctx)
// 处理完的任务加入完成队列
static void *
ngx_thread_pool_cycle(void *data)
{
    // 参数是线程池结构体
    ngx_thread_pool_t *tp = data;

    int                 err;
    sigset_t            set;
    ngx_thread_task_t  *task;

#if 0
    ngx_time_update();
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, tp->log, 0,
                   "thread in pool \"%V\" started", &tp->name);

    // 线程的运行屏蔽几个信号
    sigfillset(&set);

    sigdelset(&set, SIGILL);
    sigdelset(&set, SIGFPE);
    sigdelset(&set, SIGSEGV);
    sigdelset(&set, SIGBUS);

    // 只在主线程中处理信号
    err = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, tp->log, err, "pthread_sigmask() failed");
        return NULL;
    }

    // 无限循环
    // 从待处理任务队列里获取任务，然后执行task->handler(task->ctx)
    for ( ;; ) {
        // 锁定互斥量，防止多线程操作的竞态
        if (ngx_thread_mutex_lock(&tp->mtx, tp->log) != NGX_OK) {
            return NULL;
        }

        /* the number may become negative */
        // 即将处理一个任务，计数器减1
        tp->waiting--;

        // 如果任务队列是空，那么使用条件变量等待
        while (tp->queue.first == NULL) {
            if (ngx_thread_cond_wait(&tp->cond, &tp->mtx, tp->log)
                != NGX_OK)
            {
                (void) ngx_thread_mutex_unlock(&tp->mtx, tp->log);
                return NULL;
            }
        }

        // 此时队列里有待处理的task

        // 取出一个task
        task = tp->queue.first;
        tp->queue.first = task->next;

        // 如果此时队列已经空，调整指针
        if (tp->queue.first == NULL) {
            tp->queue.last = &tp->queue.first;
        }

        // 操作完waiting、queue后解锁，其他线程可以获取task处理
        if (ngx_thread_mutex_unlock(&tp->mtx, tp->log) != NGX_OK) {
            return NULL;
        }

#if 0
        ngx_time_update();
#endif

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                       "run task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        // 调用任务的handler，传递ctx，执行用户定义的操作，通常是阻塞的
        task->handler(task->ctx, tp->log);

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, tp->log, 0,
                       "complete task #%ui in thread pool \"%V\"",
                       task->id, &tp->name);

        task->next = NULL;

        // 自旋锁保护完成队列
        ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);

        // 处理完的任务加入完成队列
        *ngx_thread_pool_done.last = task;
        ngx_thread_pool_done.last = &task->next;

        // 1.10新增
        // 确保内存操作按照正确的顺序工作的非阻塞的同步
        // 迫使处理器来完成位于barrier前面的任何加载和存储操作
        // 才允许它执行位于barrier之后的加载和存储操作
        ngx_memory_barrier();

        // 自旋锁解锁
        ngx_unlock(&ngx_thread_pool_done_lock);

        // 重要，使用event模块的通知函数
        // 让主线程（nginx）的epoll触发事件，调用ngx_thread_pool_handler
        // 分发处理线程完成的任务
        //
        // 调用系统函数eventfd，创建一个可以用于通知的描述符，用于实现notify
        (void) ngx_notify(ngx_thread_pool_handler);
    }   //无限循环，回到开头再取下一个task
}


// 分发处理线程完成的任务，在主线程里执行
// 调用event->handler，即异步事件完成后的回调函数
static void
ngx_thread_pool_handler(ngx_event_t *ev)
{
    ngx_event_t        *event;
    ngx_thread_task_t  *task;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "thread pool handler");

    // 自旋锁保护完成队列
    ngx_spinlock(&ngx_thread_pool_done_lock, 1, 2048);

    // 取出队列里的task，task->next里有很多已经完成的任务
    task = ngx_thread_pool_done.first;

    // 把队列直接置空
    // 即ngx_thread_pool_queue_init
    ngx_thread_pool_done.first = NULL;
    ngx_thread_pool_done.last = &ngx_thread_pool_done.first;

    // 1.10新增
    // 确保内存操作按照正确的顺序工作的非阻塞的同步
    // 迫使处理器来完成位于barrier前面的任何加载和存储操作
    // 才允许它执行位于barrier之后的加载和存储操作
    ngx_memory_barrier();

    // 自旋锁解锁
    ngx_unlock(&ngx_thread_pool_done_lock);

    // 遍历所有已经完成的任务
    while (task) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "run completion handler for task #%ui", task->id);

        // 取task里的事件对象
        event = &task->event;

        // task指针移动到下一个节点
        task = task->next;

        // 线程异步事件已经完成
        event->complete = 1;

        // 事件已经处理完
        event->active = 0;

        // 调用handler，即异步事件完成后的回调函数
        event->handler(event);
    }
}


// 创建线程池模块的配置，里面是个数组，元素为ngx_thread_pool_t
static void *
ngx_thread_pool_create_conf(ngx_cycle_t *cycle)
{
    ngx_thread_pool_conf_t  *tcf;

    tcf = ngx_pcalloc(cycle->pool, sizeof(ngx_thread_pool_conf_t));
    if (tcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&tcf->pools, cycle->pool, 4,
                       sizeof(ngx_thread_pool_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return tcf;
}


// 检查配置的线程池，必须设置线程数量
static char *
ngx_thread_pool_init_conf(ngx_cycle_t *cycle, void *conf)
{
    // 线程池模块的配置结构体
    ngx_thread_pool_conf_t *tcf = conf;

    ngx_uint_t           i;
    ngx_thread_pool_t  **tpp;

    // 直接访问数组，元素是ngx_thread_pool_t
    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {

        // 要求必须设置线程数量
        if (tpp[i]->threads) {
            continue;
        }

        // 默认线程池，有32个线程
        if (tpp[i]->name.len == ngx_thread_pool_default.len
            && ngx_strncmp(tpp[i]->name.data, ngx_thread_pool_default.data,
                           ngx_thread_pool_default.len)
               == 0)
        {
            tpp[i]->threads = 32;
            tpp[i]->max_queue = 65536;
            continue;
        }

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "unknown thread pool \"%V\" in %s:%ui",
                      &tpp[i]->name, tpp[i]->file, tpp[i]->line);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


// 解析thread_pool指令，设置线程数和队列数（默认65535）
static char *
ngx_thread_pool(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t          *value;
    ngx_uint_t          i;
    ngx_thread_pool_t  *tp;

    value = cf->args->elts;

    // 根据配置创建线程池结构体对象,添加进线程池模块配置结构体里的数组
    tp = ngx_thread_pool_add(cf, &value[1]);

    if (tp == NULL) {
        return NGX_CONF_ERROR;
    }

    if (tp->threads) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate thread pool \"%V\"", &tp->name);
        return NGX_CONF_ERROR;
    }

    tp->max_queue = 65536;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "threads=", 8) == 0) {

            tp->threads = ngx_atoi(value[i].data + 8, value[i].len - 8);

            if (tp->threads == (ngx_uint_t) NGX_ERROR || tp->threads == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid threads value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_queue=", 10) == 0) {

            tp->max_queue = ngx_atoi(value[i].data + 10, value[i].len - 10);

            if (tp->max_queue == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_queue value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }
    }

    if (tp->threads == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"threads\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


// 根据配置创建线程池结构体对象,添加进线程池模块配置结构体里的数组
ngx_thread_pool_t *
ngx_thread_pool_add(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_thread_pool_t       *tp, **tpp;
    ngx_thread_pool_conf_t  *tcf;

    // 如果不指定线程池名字，默认使用default
    if (name == NULL) {
        name = &ngx_thread_pool_default;
    }

    // 检查是否已经定义了线程池
    tp = ngx_thread_pool_get(cf->cycle, name);

    if (tp) {
        return tp;
    }

    // 创建线程池结构体对象
    tp = ngx_pcalloc(cf->pool, sizeof(ngx_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

    // 线程池名字
    tp->name = *name;

    // 定义线程池的配置文件
    tp->file = cf->conf_file->file.name.data;

    // 定义线程池指令的行号
    tp->line = cf->conf_file->line;

    // 获得线程池模块的配置结构体，里面只有一个数组
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    // 把线程池结构体添加进数组
    tpp = ngx_array_push(&tcf->pools);
    if (tpp == NULL) {
        return NULL;
    }

    *tpp = tp;

    return tp;
}


// 根据名字获取线程池
// 遍历线程池数组，找到名字对应的结构体
ngx_thread_pool_t *
ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    // 获得线程池模块的配置结构体
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    tpp = tcf->pools.elts;

    // 遍历线程池数组，找到名字对应的结构体
    for (i = 0; i < tcf->pools.nelts; i++) {

        if (tpp[i]->name.len == name->len
            && ngx_strncmp(tpp[i]->name.data, name->data, name->len) == 0)
        {
            return tpp[i];
        }
    }

    return NULL;
}


// ngx_single_process_cycle/ngx_worker_process_cycle里调用
// 进程开始时初始化，创建线程池
static ngx_int_t
ngx_thread_pool_init_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    if (tcf == NULL) {
        return NGX_OK;
    }

    // 初始化线程池任务队列，first/last都是空
    ngx_thread_pool_queue_init(&ngx_thread_pool_done);

    tpp = tcf->pools.elts;

    for (i = 0; i < tcf->pools.nelts; i++) {
        // 使用ngx_thread_pool_t结构体初始化线程池
        // 在init_worker时被调用
        // 创建互斥量、条件变量，根据配置的线程数量，创建线程
        // 线程的执行函数是ngx_thread_pool_cycle，参数是线程池结构体
        if (ngx_thread_pool_init(tpp[i], cycle->log, cycle->pool) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


// 进程结束时被调用，清理线程池
// 调用ngx_thread_pool_destroy逐个销毁线程池
static void
ngx_thread_pool_exit_worker(ngx_cycle_t *cycle)
{
    ngx_uint_t                i;
    ngx_thread_pool_t       **tpp;
    ngx_thread_pool_conf_t   *tcf;

    // 只有worker和single进程才会有线程池
    // master/cache不处理请求，不使用线程池
    if (ngx_process != NGX_PROCESS_WORKER
        && ngx_process != NGX_PROCESS_SINGLE)
    {
        return;
    }

    // 获得线程池模块的配置结构体
    tcf = (ngx_thread_pool_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                  ngx_thread_pool_module);

    // 没有配置则无需任何操作
    if (tcf == NULL) {
        return;
    }

    tpp = tcf->pools.elts;

    // 调用ngx_thread_pool_destroy逐个销毁线程池
    for (i = 0; i < tcf->pools.nelts; i++) {
        // 使用一个要求线程结束的task，发给池里所有的线程
        // 最后销毁条件变量和互斥量
        ngx_thread_pool_destroy(tpp[i]);
    }
}
