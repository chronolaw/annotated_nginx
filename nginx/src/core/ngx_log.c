// annotated by chrono since 2016
//
// * ngx_log_error_core
// * ngx_log_open_default
// * ngx_error_log
// * ngx_log_set_log
// * ngx_log_set_levels

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


// 解析最外层的error_log指令
// 设置新的log对象
static char *ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 设置日志的级别
static char *ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log);

// 日志对象按级别低到高
// 即NGX_LOG_DEBUG=>NGX_LOG_STDERR
// 按level降序
static void ngx_log_insert(ngx_log_t *log, ngx_log_t *new_log);


#if (NGX_DEBUG)

static void ngx_log_memory_writer(ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len);
static void ngx_log_memory_cleanup(void *data);


// 写内存日志用的管理对象
typedef struct {
    // 内存空间的开始结束位置
    u_char        *start;
    u_char        *end;

    // 当前位置
    u_char        *pos;

    // 原子操作，写入的数量
    ngx_atomic_t   written;
} ngx_log_memory_buf_t;

#endif


// error_log指令只能出现在最外部，不能在event{}http{}里
// http/stream等定义了自己的error_log指令
static ngx_command_t  ngx_errlog_commands[] = {

    { ngx_string("error_log"),
      NGX_MAIN_CONF|NGX_CONF_1MORE,
      ngx_error_log,
      0,
      0,
      NULL },

      ngx_null_command
};


// 没有配置结构体需要创建
static ngx_core_module_t  ngx_errlog_module_ctx = {
    ngx_string("errlog"),
    NULL,
    NULL
};


ngx_module_t  ngx_errlog_module = {
    NGX_MODULE_V1,
    &ngx_errlog_module_ctx,                /* module context */
    ngx_errlog_commands,                   /* module directives */
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


// 基本的log对象
// 仅在配置阶段使用
static ngx_log_t        ngx_log;

// 使用的文件对象
// 仅在配置阶段使用
static ngx_open_file_t  ngx_log_file;

// 日志输出到标准错误流
// #define ngx_stderr               STDERR_FILENO
// 默认不使用标准流记录日志
// 在nginx.c里置0
ngx_uint_t              ngx_use_stderr = 1;


// 错误级别与字符串的对应数组
// ngx_log_set_levels
static ngx_str_t err_levels[] = {
    ngx_null_string,
    ngx_string("emerg"),
    ngx_string("alert"),
    ngx_string("crit"),
    ngx_string("error"),
    ngx_string("warn"),
    ngx_string("notice"),
    ngx_string("info"),
    ngx_string("debug")
};

// 调试用的级别，只打印某些特殊子系统的日志
// 在nginx网站没有很好地文档化
// ngx_log_set_levels
static const char *debug_levels[] = {
    "debug_core", "debug_alloc", "debug_mutex", "debug_event",
    "debug_http", "debug_mail", "debug_stream"
};


// 通常我们使用c99的可变参数宏

// 错误消息的最大长度，2k字节
// 先拷贝当前的时间,格式是"1970/09/28 12:00:00"
// 打印错误等级的字符串描述信息，使用关联数组err_levels
// 打印pid和tid
// 打印函数里的字符串可变参数
// 对整个日志链表执行写入操作
#if (NGX_HAVE_VARIADIC_MACROS)

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)

#else

// 此函数原型通常可以忽略，原因见上
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, va_list args)

#endif
{
#if (NGX_HAVE_VARIADIC_MACROS)
    va_list      args;
#endif
    u_char      *p, *last, *msg;
    ssize_t      n;
    ngx_uint_t   wrote_stderr, debug_connection;
    u_char       errstr[NGX_MAX_ERROR_STR];

    // 错误消息的最大长度，2k字节
    last = errstr + NGX_MAX_ERROR_STR;

    // 先拷贝当前的时间
    // 格式是"1970/09/28 12:00:00"
    p = ngx_cpymem(errstr, ngx_cached_err_log_time.data,
                   ngx_cached_err_log_time.len);

    // 打印错误等级的字符串描述信息，使用关联数组err_levels
    p = ngx_slprintf(p, last, " [%V] ", &err_levels[level]);

    // 打印pid和tid
    // #define ngx_log_pid  ngx_pid
    // #define ngx_log_tid           ngx_thread_tid()
    // in os/unix

    /* pid#tid */
    p = ngx_slprintf(p, last, "%P#" NGX_TID_T_FMT ": ",
                    ngx_log_pid, ngx_log_tid);

    // 如果有连接计数则打印
    if (log->connection) {
        p = ngx_slprintf(p, last, "*%uA ", log->connection);
    }

    // 前面输出的是基本的信息：当前时间+[错误级别]+pid#tid:
    msg = p;

    // 打印可变参数
#if (NGX_HAVE_VARIADIC_MACROS)

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

#else

    p = ngx_vslprintf(p, last, fmt, args);

#endif

    // 如果有系统错误码，那么记录(err)
    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    // 记录错误日志时可以执行的回调函数
    // 参数是消息缓冲区里剩余的空间
    // 只有高于debug才会执行
    if (level != NGX_LOG_DEBUG && log->handler) {
        p = log->handler(log, p, last - p);
    }

    // #define NGX_LINEFEED_SIZE        1
    // 日志过长（超过2k）则截断
    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    // #define ngx_linefeed(p)          *p++ = LF;
    // 加上一个换行符
    ngx_linefeed(p);

    // 默认不输出到标准流
    wrote_stderr = 0;

    // 是否要针对某些连接打印调试日志
    // 指令debug_connection
    debug_connection = (log->log_level & NGX_LOG_DEBUG_CONNECTION) != 0;

    // 对整个日志链表执行写入操作
    while (log) {

        // log消息级别低，不需要记录日志，直接退出循环
        // 因为链表是level降序的，避免了遍历整个链表，提高效率
        // 如果是针对某些连接打印调试日志那么无视日志级别
        if (log->log_level < level && !debug_connection) {
            break;
        }

        // log对象有专用的写函数指针，例如syslog
        // 那么就不写文件，调用函数写日志
        // 可以定制writer函数，实现特殊的写日志行为，如rotate
        if (log->writer) {
            log->writer(log, level, errstr, p - errstr);
            goto next;
        }

        // 避免磁盘满时反复写入
        if (ngx_time() == log->disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            goto next;
        }

        // 没有专用的写函数指针，写入磁盘文件

        // 写错误日志消息到关联的文件
        // 实际上就是系统调用write，见ngx_files.h
        n = ngx_write_fd(log->file->fd, errstr, p - errstr);

        // 写入失败，且错误是磁盘满
        // 记录时间，避免磁盘满时反复写入
        if (n == -1 && ngx_errno == NGX_ENOSPC) {
            log->disk_full_time = ngx_time();
        }

        // 检查文件描述符，是标准流
        // 则置标志位
        if (log->file->fd == ngx_stderr) {
            wrote_stderr = 1;
        }

    next:

        // 使用下一个日志对象记录日志
        log = log->next;
    }

    // 默认不使用标准流记录日志
    // 在nginx.c里置0
    if (!ngx_use_stderr
        || level > NGX_LOG_WARN
        || wrote_stderr)
    {
        return;
    }

    // 前面输出的是基本的信息：当前时间+[错误级别]+pid#tid:
    // 调整字符串指针
    msg -= (7 + err_levels[level].len + 3);

    // 重新打印日志级别
    (void) ngx_sprintf(msg, "nginx: [%V] ", &err_levels[level]);

    // 输出到标准流
    (void) ngx_write_console(ngx_stderr, msg, p - msg);
}


// 没有可变参数宏不研究，其实比较简单
#if !(NGX_HAVE_VARIADIC_MACROS)

void ngx_cdecl
ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    va_list  args;

    if (log->log_level >= level) {
        va_start(args, fmt);
        ngx_log_error_core(level, log, err, fmt, args);
        va_end(args);
    }
}


void ngx_cdecl
ngx_log_debug_core(ngx_log_t *log, ngx_err_t err, const char *fmt, ...)
{
    va_list  args;

    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, args);
    va_end(args);
}

#endif


// 直接以alert级别记录日志
void ngx_cdecl
ngx_log_abort(ngx_err_t err, const char *fmt, ...)
{
    u_char   *p;
    va_list   args;
    u_char    errstr[NGX_MAX_CONF_ERRSTR];

    va_start(args, fmt);
    p = ngx_vsnprintf(errstr, sizeof(errstr) - 1, fmt, args);
    va_end(args);

    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                  "%*s", p - errstr, errstr);
}


// 在标准错误流输出信息，里面有nginx前缀
void ngx_cdecl
ngx_log_stderr(ngx_err_t err, const char *fmt, ...)
{
    u_char   *p, *last;
    va_list   args;
    u_char    errstr[NGX_MAX_ERROR_STR];

    last = errstr + NGX_MAX_ERROR_STR;

    p = ngx_cpymem(errstr, "nginx: ", 7);

    va_start(args, fmt);
    p = ngx_vslprintf(p, last, fmt, args);
    va_end(args);

    if (err) {
        p = ngx_log_errno(p, last, err);
    }

    if (p > last - NGX_LINEFEED_SIZE) {
        p = last - NGX_LINEFEED_SIZE;
    }

    ngx_linefeed(p);

    (void) ngx_write_console(ngx_stderr, errstr, p - errstr);
}


// 如果有系统错误码，那么记录(err)
u_char *
ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err)
{
    if (buf > last - 50) {

        /* leave a space for an error code */

        buf = last - 50;
        *buf++ = '.';
        *buf++ = '.';
        *buf++ = '.';
    }

#if (NGX_WIN32)
    buf = ngx_slprintf(buf, last, ((unsigned) err < 0x80000000)
                                       ? " (%d: " : " (%Xd: ", err);
#else
    buf = ngx_slprintf(buf, last, " (%d: ", err);
#endif

    buf = ngx_strerror(err, buf, last - buf);

    if (buf < last) {
        *buf++ = ')';
    }

    return buf;
}


// 初始化日志
// 默认是NGX_CONF_PREFIX，即/usr/local/nginx
// 如果没有文件名就输出到stderr
// 打开有前缀的日志文件
ngx_log_t *
ngx_log_init(u_char *prefix)
{
    u_char  *p, *name;
    size_t   nlen, plen;

    // 初始化为notice级别，即只有warn,error等才能记录日志
    ngx_log.file = &ngx_log_file;
    ngx_log.log_level = NGX_LOG_NOTICE;

    // 由configure自动生成
    // #define NGX_ERROR_LOG_PATH  "logs/error.log"
    name = (u_char *) NGX_ERROR_LOG_PATH;

    /*
     * we use ngx_strlen() here since BCC warns about
     * condition is always false and unreachable code
     */

    nlen = ngx_strlen(name);

    // 如果没有文件名就输出到stderr
    if (nlen == 0) {
        ngx_log_file.fd = ngx_stderr;
        return &ngx_log;
    }

    p = NULL;

#if (NGX_WIN32)
    if (name[1] != ':') {
#else
    if (name[0] != '/') {
#endif

        // 取路径前缀的长度
        // 默认是NGX_CONF_PREFIX，即/usr/local/nginx
        if (prefix) {
            plen = ngx_strlen(prefix);

        } else {
#ifdef NGX_PREFIX
            prefix = (u_char *) NGX_PREFIX;
            plen = ngx_strlen(prefix);
#else
            plen = 0;
#endif
        }

        // 分配一块新内存，容纳前缀和文件名
        // 多两个字节是给'/'
        if (plen) {
            name = malloc(plen + nlen + 2);
            if (name == NULL) {
                return NULL;
            }

            p = ngx_cpymem(name, prefix, plen);

            if (!ngx_path_separator(*(p - 1))) {
                *p++ = '/';
            }

            ngx_cpystrn(p, (u_char *) NGX_ERROR_LOG_PATH, nlen + 1);

            p = name;
        }
    }

    // 打开有前缀的日志文件
    // 因为使用了APPEND，所以多进程写文件是安全的
    ngx_log_file.fd = ngx_open_file(name, NGX_FILE_APPEND,
                                    NGX_FILE_CREATE_OR_OPEN,
                                    NGX_FILE_DEFAULT_ACCESS);

    if (ngx_log_file.fd == NGX_INVALID_FILE) {
        ngx_log_stderr(ngx_errno,
                       "[alert] could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#if (NGX_WIN32)
        ngx_event_log(ngx_errno,
                       "could not open error log file: "
                       ngx_open_file_n " \"%s\" failed", name);
#endif

        ngx_log_file.fd = ngx_stderr;
    }

    if (p) {
        ngx_free(p);
    }

    return &ngx_log;
}


// 打开默认的日志文件
// 初始化new_log
ngx_int_t
ngx_log_open_default(ngx_cycle_t *cycle)
{
    ngx_log_t         *log;

    // #define NGX_ERROR_LOG_PATH  "logs/error.log"
    static ngx_str_t   error_log = ngx_string(NGX_ERROR_LOG_PATH);

    // 在日志链表里找到一个使用文件的日志对象
    // 有就说明已经用指令设置了日志
    if (ngx_log_get_file_log(&cycle->new_log) != NULL) {
        return NGX_OK;
    }

    // 未明确使用error_log是没有，new_log是空的

    // 需要初始化new_log
    if (cycle->new_log.log_level != 0) {
        /* there are some error logs, but no files */

        log = ngx_pcalloc(cycle->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NGX_ERROR;
        }

    } else {
        /* no error logs at all */
        log = &cycle->new_log;
    }

    // 使用error级别
    log->log_level = NGX_LOG_ERR;

    // 打开文件，注意没有前缀
    // 默认使用conf_prefix/prefix
    log->file = ngx_conf_open_file(cycle, &error_log);
    if (log->file == NULL) {
        return NGX_ERROR;
    }

    // 日志对象按级别低到高
    // 即NGX_LOG_DEBUG=>NGX_LOG_STDERR
    // 按level降序
    if (log != &cycle->new_log) {
        ngx_log_insert(&cycle->new_log, log);
    }

    return NGX_OK;
}


ngx_int_t
ngx_log_redirect_stderr(ngx_cycle_t *cycle)
{
    ngx_fd_t  fd;

    if (cycle->log_use_stderr) {
        return NGX_OK;
    }

    /* file log always exists when we are called */
    fd = ngx_log_get_file_log(cycle->log)->file->fd;

    if (fd != ngx_stderr) {
        if (ngx_set_stderr(fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          ngx_set_stderr_n " failed");

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


// 在日志链表里找到一个使用文件的日志对象
ngx_log_t *
ngx_log_get_file_log(ngx_log_t *head)
{
    ngx_log_t  *log;

    for (log = head; log; log = log->next) {
        if (log->file != NULL) {
            return log;
        }
    }

    return NULL;
}


// 设置日志的级别
static char *
ngx_log_set_levels(ngx_conf_t *cf, ngx_log_t *log)
{
    ngx_uint_t   i, n, d, found;
    ngx_str_t   *value;

    // 需要有有多于一个的参数
    if (cf->args->nelts == 2) {
        log->log_level = NGX_LOG_ERR;
        return NGX_CONF_OK;
    }

    value = cf->args->elts;

    // 逐个检查file之后的level参数
    // 允许有多个debug level级别
    for (i = 2; i < cf->args->nelts; i++) {
        found = 0;

        // 检查第i个参数

        // 先看大的level级别
        // info/notice/warn/error等
        for (n = 1; n <= NGX_LOG_DEBUG; n++) {
            // 比较级别的字符串数组
            if (ngx_strcmp(value[i].data, err_levels[n].data) == 0) {

                // 大级别只能设定一次，不能重复
                if (log->log_level != 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "duplicate log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                log->log_level = n;

                // 设置标志位，参数正确
                found = 1;
                break;
            }
        }

        // 检查是否是debug level
        // debug_core/debug_alloc等
        for (n = 0, d = NGX_LOG_DEBUG_FIRST; d <= NGX_LOG_DEBUG_LAST; d <<= 1) {
            // 比较debug子系统的字符串数组
            if (ngx_strcmp(value[i].data, debug_levels[n++]) == 0) {

                // 不能是大level，即低位被设置
                if (log->log_level & ~NGX_LOG_DEBUG_ALL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid log level \"%V\"",
                                       &value[i]);
                    return NGX_CONF_ERROR;
                }

                // 允许使用多个debug level，所以用逻辑位
                log->log_level |= d;

                // 设置标志位，参数正确
                found = 1;
                break;
            }
        }


        // 两个字符串数字里都没有找到，参数错误
        if (!found) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid log level \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }

        // 继续检查下一个参数
    }

    // 如果只是设置了debug级别，那么就打印所有的子系统
    // LOG_DEBUG=DEBUG_ALL=0x7ffffff0
    // 所以在调用log_debug时位操作总成功
    if (log->log_level == NGX_LOG_DEBUG) {
        log->log_level = NGX_LOG_DEBUG_ALL;
    }

    return NGX_CONF_OK;
}


// 解析最外层的error_log指令
// 设置新的log对象
static char *
ngx_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_log_t  *dummy;

    dummy = &cf->cycle->new_log;

    // 解析指令，设置日志的级别，插入日志对象链表
    return ngx_log_set_log(cf, &dummy);
}


// 解析指令，设置日志的级别，插入日志对象链表
char *
ngx_log_set_log(ngx_conf_t *cf, ngx_log_t **head)
{
    ngx_log_t          *new_log;
    ngx_str_t          *value, name;
    ngx_syslog_peer_t  *peer;

    // 检查指针，指向正确的log对象
    if (*head != NULL && (*head)->log_level == 0) {
        new_log = *head;

    } else {

        new_log = ngx_pcalloc(cf->pool, sizeof(ngx_log_t));
        if (new_log == NULL) {
            return NGX_CONF_ERROR;
        }

        if (*head == NULL) {
            *head = new_log;
        }
    }

    value = cf->args->elts;

    // 标准输出
    if (ngx_strcmp(value[1].data, "stderr") == 0) {
        ngx_str_null(&name);
        cf->cycle->log_use_stderr = 1;

        new_log->file = ngx_conf_open_file(cf->cycle, &name);
        if (new_log->file == NULL) {
            return NGX_CONF_ERROR;
        }

    // 内存，用来调试
    } else if (ngx_strncmp(value[1].data, "memory:", 7) == 0) {

#if (NGX_DEBUG)
        size_t                 size, needed;
        ngx_pool_cleanup_t    *cln;
        ngx_log_memory_buf_t  *buf;

        value[1].len -= 7;
        value[1].data += 7;

        // 计算需要的内存大小
        needed = sizeof("MEMLOG  :" NGX_LINEFEED)
                 + cf->conf_file->file.name.len
                 + NGX_SIZE_T_LEN
                 + NGX_INT_T_LEN
                 + NGX_MAX_ERROR_STR;

        size = ngx_parse_size(&value[1]);

        if (size == (size_t) NGX_ERROR || size < needed) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid buffer size \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        // 内存管理对象
        buf = ngx_pcalloc(cf->pool, sizeof(ngx_log_memory_buf_t));
        if (buf == NULL) {
            return NGX_CONF_ERROR;
        }

        // 分配内存
        buf->start = ngx_pnalloc(cf->pool, size);
        if (buf->start == NULL) {
            return NGX_CONF_ERROR;
        }

        buf->end = buf->start + size;

        // 打印开头的字符串
        buf->pos = ngx_slprintf(buf->start, buf->end, "MEMLOG %uz %V:%ui%N",
                                size, &cf->conf_file->file.name,
                                cf->conf_file->line);

        // 后续全是空格，不是0
        ngx_memset(buf->pos, ' ', buf->end - buf->pos);

        // 清理函数
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->data = new_log;
        cln->handler = ngx_log_memory_cleanup;

        // 专门的内存写入函数
        new_log->writer = ngx_log_memory_writer;
        new_log->wdata = buf;

#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "nginx was built without debug support");
        return NGX_CONF_ERROR;
#endif

    // syslog服务
    } else if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }

        new_log->writer = ngx_syslog_writer;
        new_log->wdata = peer;

    // 写入到文件
    } else {
        // 加入到cycle->open_files链表里
        // 没有打开文件，之后在init_cycle里统一打开
        new_log->file = ngx_conf_open_file(cf->cycle, &value[1]);
        if (new_log->file == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    // 设置日志的级别
    if (ngx_log_set_levels(cf, new_log) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    // 插入日志对象链表
    if (*head != new_log) {
        ngx_log_insert(*head, new_log);
    }

    return NGX_CONF_OK;
}


// 日志对象按级别低到高
// 即NGX_LOG_DEBUG=>NGX_LOG_STDERR
// 按level降序
static void
ngx_log_insert(ngx_log_t *log, ngx_log_t *new_log)
{
    ngx_log_t  tmp;

    // 要插入的日志对象级别低
    // 即levle大
    if (new_log->log_level > log->log_level) {

        /*
         * list head address is permanent, insert new log after
         * head and swap its contents with head
         */

        // 交换两个日志对象
        tmp = *log;
        *log = *new_log;
        *new_log = tmp;

        // 现在头是新的日志对象
        log->next = new_log;
        return;
    }

    // 要插入的日志对象级别高
    // 即levle小
    while (log->next) {
        // 在链表里找到级别比它低的
        // 即leval大
        // 插入链表
        if (new_log->log_level > log->next->log_level) {
            new_log->next = log->next;
            log->next = new_log;
            return;
        }

        log = log->next;
    }

    log->next = new_log;
}


#if (NGX_DEBUG)

static void
ngx_log_memory_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf,
    size_t len)
{
    u_char                *p;
    size_t                 avail, written;
    ngx_log_memory_buf_t  *mem;

    mem = log->wdata;

    if (mem == NULL) {
        return;
    }

    // 原子增加写入数量
    written = ngx_atomic_fetch_add(&mem->written, len);

    // 写入的末尾位置
    p = mem->pos + written % (mem->end - mem->pos);

    avail = mem->end - p;

    if (avail >= len) {
        ngx_memcpy(p, buf, len);

    } else {
        ngx_memcpy(p, buf, avail);
        ngx_memcpy(mem->pos, buf + avail, len - avail);
    }
}


static void
ngx_log_memory_cleanup(void *data)
{
    ngx_log_t *log = data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, log, 0, "destroy memory log buffer");

    log->wdata = NULL;
}

#endif
