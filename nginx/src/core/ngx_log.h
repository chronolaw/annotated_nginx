// annotated by chrono since 2016
//
// * ngx_log_s

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LOG_H_INCLUDED_
#define _NGX_LOG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 错误日志的级别，0最高，8最低
// 使用的是低7位
#define NGX_LOG_STDERR            0
#define NGX_LOG_EMERG             1
#define NGX_LOG_ALERT             2
#define NGX_LOG_CRIT              3
#define NGX_LOG_ERR               4
#define NGX_LOG_WARN              5
#define NGX_LOG_NOTICE            6
#define NGX_LOG_INFO              7
#define NGX_LOG_DEBUG             8

// 调试用的日志宏
// 不表示级别，因为已经是debug
// 表示所属的子系统
// if ((log)->log_level & level)
#define NGX_LOG_DEBUG_CORE        0x010
#define NGX_LOG_DEBUG_ALLOC       0x020
#define NGX_LOG_DEBUG_MUTEX       0x040
#define NGX_LOG_DEBUG_EVENT       0x080
#define NGX_LOG_DEBUG_HTTP        0x100
#define NGX_LOG_DEBUG_MAIL        0x200
#define NGX_LOG_DEBUG_STREAM      0x400

/*
 * do not forget to update debug_levels[] in src/core/ngx_log.c
 * after the adding a new debug level
 */

// 调试级别的上下限
#define NGX_LOG_DEBUG_FIRST       NGX_LOG_DEBUG_CORE
#define NGX_LOG_DEBUG_LAST        NGX_LOG_DEBUG_STREAM

// 特殊调试级别，打印某个连接，最高位
#define NGX_LOG_DEBUG_CONNECTION  0x80000000

// 调试所有的子系统，注意没有最高位
// 最高位给调试某个连接使用
// 低三位留给了err/warn/info等日志级别
#define NGX_LOG_DEBUG_ALL         0x7ffffff0


// 记录错误日志时可以执行的回调函数
// 参数是消息缓冲区里剩余的空间
typedef u_char *(*ngx_log_handler_pt) (ngx_log_t *log, u_char *buf, size_t len);

// 专用的写函数指针
// 可以写到syslog或者其他地方
typedef void (*ngx_log_writer_pt) (ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len);


// 错误日志结构体
// 多个日志对象串成一个按level降序的链表
// 即日志级别由低到高，提高记录日志的效率
// 一个日志链表可以理解为其他日志模型里的category
// cycle->log, cscf->error_log, clcf->error_log
// 因为使用了APPEND，所以多进程写文件是安全的
struct ngx_log_s {
    // 日志对象的级别，会过滤掉低级别的日志信息
    // 即if ((log)->log_level >= level)
    ngx_uint_t           log_level;

    // 日志文件对象
    // 里面有日志的文件名
    ngx_open_file_t     *file;

    // 日志关联的连接计数
    // c->log->connection = c->number;
    ngx_atomic_uint_t    connection;

    // 记录写日志磁盘满错误发生的时间
    // 避免反复写磁盘导致的阻塞
    // 时间间隔为1秒
    time_t               disk_full_time;

    // 记录错误日志时可以执行的回调函数
    // 参数是消息缓冲区里剩余的空间
    // 定制额外的信息
    // 只有高于debug才会执行
    // 例如ngx_http_log_error
    ngx_log_handler_pt   handler;

    // handler执行时需要的数据
    // 例如ngx_http_log_ctx_t，里面有请求、连接等
    void                *data;

    // 专用的写函数指针
    // 可以写到syslog或者其他地方
    // 实现特殊的记录日志动作
    ngx_log_writer_pt    writer;

    // writer相关的数据，需要用户自己管理
    void                *wdata;

    /*
     * we declare "action" as "char *" because the actions are usually
     * the static strings and in the "u_char *" case we have to override
     * their types all the time
     */

    // 通常由handler使用，定制特殊的日志消息
    // 例如 while ...
    char                *action;

    // 下一个日志对象
    // 多个日志对象串成一个按level降序的链表
    // 即日志级别由低到高，提高记录日志的效率
    ngx_log_t           *next;
};


// 错误消息的最大长度，2k字节
#define NGX_MAX_ERROR_STR   2048


/*********************************/

// 通常我们使用c99的可变参数宏
#if (NGX_HAVE_C99_VARIADIC_MACROS)

#define NGX_HAVE_VARIADIC_MACROS  1

// 最常用的日志宏
// level, log, err, fmt, ...
#define ngx_log_error(level, log, ...)                                        \
    if ((log)->log_level >= level) ngx_log_error_core(level, log, __VA_ARGS__)

// 先拷贝当前的时间,格式是"1970/09/28 12:00:00"
// 打印错误等级的字符串描述信息，使用关联数组err_levels
// 打印pid和tid
// 打印函数里的字符串可变参数
// 对整个日志链表执行写入操作
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);

// 只有在configure时使用--with-debug才会启用
// 调试日志宏,级别固定为debug
// 注意使用&操作检查位
// 记录日志的条件使用逻辑与操作，检查子系统
// LOG_DEBUG=DEBUG_ALL=0x7ffffff0
// 所以在调用log_debug时位操作总成功
//
// 调试用的级别，只打印某些特殊子系统的日志
// 在nginx网站没有很好地文档化
// ngx_log_set_levels
// static const char *debug_levels[] = {
//     "debug_core", "debug_alloc", "debug_mutex", "debug_event",
//     "debug_http", "debug_mail", "debug_stream"
// };
#define ngx_log_debug(level, log, ...)                                        \
    if ((log)->log_level & level)                                             \
        ngx_log_error_core(NGX_LOG_DEBUG, log, __VA_ARGS__)

/*********************************/

#elif (NGX_HAVE_GCC_VARIADIC_MACROS)

#define NGX_HAVE_VARIADIC_MACROS  1

#define ngx_log_error(level, log, args...)                                    \
    if ((log)->log_level >= level) ngx_log_error_core(level, log, args)

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);

#define ngx_log_debug(level, log, args...)                                    \
    if ((log)->log_level & level)                                             \
        ngx_log_error_core(NGX_LOG_DEBUG, log, args)

/*********************************/

#else /* no variadic macros */

#define NGX_HAVE_VARIADIC_MACROS  0

void ngx_cdecl ngx_log_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, va_list args);
void ngx_cdecl ngx_log_debug_core(ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);


#endif /* variadic macros */


/*********************************/

// 只有在configure时使用--with-debug才会启用下面的debug宏
#if (NGX_DEBUG)

#if (NGX_HAVE_VARIADIC_MACROS)

#define ngx_log_debug0(level, log, err, fmt)                                  \
        ngx_log_debug(level, log, err, fmt)

#define ngx_log_debug1(level, log, err, fmt, arg1)                            \
        ngx_log_debug(level, log, err, fmt, arg1)

#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)                      \
        ngx_log_debug(level, log, err, fmt, arg1, arg2)

#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
        ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3)

#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
        ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4)

#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
        ngx_log_debug(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define ngx_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
        ngx_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6)

#define ngx_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
        ngx_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define ngx_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
        ngx_log_debug(level, log, err, fmt,                                   \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)


#else /* no variadic macros */

#define ngx_log_debug0(level, log, err, fmt)                                  \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt)

#define ngx_log_debug1(level, log, err, fmt, arg1)                            \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt, arg1)

#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)                      \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt, arg1, arg2)

#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)                \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3)

#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)          \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4)

#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)    \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5)

#define ngx_log_debug6(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6)                    \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)

#define ngx_log_debug7(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)              \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7)

#define ngx_log_debug8(level, log, err, fmt,                                  \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)        \
    if ((log)->log_level & level)                                             \
        ngx_log_debug_core(log, err, fmt,                                     \
                       arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

#endif

#else /* !NGX_DEBUG */

#define ngx_log_debug0(level, log, err, fmt)
#define ngx_log_debug1(level, log, err, fmt, arg1)
#define ngx_log_debug2(level, log, err, fmt, arg1, arg2)
#define ngx_log_debug3(level, log, err, fmt, arg1, arg2, arg3)
#define ngx_log_debug4(level, log, err, fmt, arg1, arg2, arg3, arg4)
#define ngx_log_debug5(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5)
#define ngx_log_debug6(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define ngx_log_debug7(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7)
#define ngx_log_debug8(level, log, err, fmt, arg1, arg2, arg3, arg4, arg5,    \
                       arg6, arg7, arg8)

#endif

/*********************************/

// 初始化日志
ngx_log_t *ngx_log_init(u_char *prefix);

// 直接以alert级别记录日志
void ngx_cdecl ngx_log_abort(ngx_err_t err, const char *fmt, ...);

// 在标准错误流输出信息，里面有nginx前缀
void ngx_cdecl ngx_log_stderr(ngx_err_t err, const char *fmt, ...);

u_char *ngx_log_errno(u_char *buf, u_char *last, ngx_err_t err);
ngx_int_t ngx_log_open_default(ngx_cycle_t *cycle);
ngx_int_t ngx_log_redirect_stderr(ngx_cycle_t *cycle);
ngx_log_t *ngx_log_get_file_log(ngx_log_t *head);
char *ngx_log_set_log(ngx_conf_t *cf, ngx_log_t **head);


/*
 * ngx_write_stderr() cannot be implemented as macro, since
 * MSVC does not allow to use #ifdef inside macro parameters.
 *
 * ngx_write_fd() is used instead of ngx_write_console(), since
 * CharToOemBuff() inside ngx_write_console() cannot be used with
 * read only buffer as destination and CharToOemBuff() is not needed
 * for ngx_write_stderr() anyway.
 */
static ngx_inline void
ngx_write_stderr(char *text)
{
    (void) ngx_write_fd(ngx_stderr, text, ngx_strlen(text));
}


static ngx_inline void
ngx_write_stdout(char *text)
{
    (void) ngx_write_fd(ngx_stdout, text, ngx_strlen(text));
}


extern ngx_module_t  ngx_errlog_module;
extern ngx_uint_t    ngx_use_stderr;


#endif /* _NGX_LOG_H_INCLUDED_ */
