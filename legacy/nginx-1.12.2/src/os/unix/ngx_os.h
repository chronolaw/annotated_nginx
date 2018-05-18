// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_OS_H_INCLUDED_
#define _NGX_OS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_IO_SENDFILE    1


// 收发数据的函数原型，封装了系统调用recv/send
typedef ssize_t (*ngx_recv_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*ngx_recv_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
typedef ssize_t (*ngx_send_pt)(ngx_connection_t *c, u_char *buf, size_t size);
typedef ngx_chain_t *(*ngx_send_chain_pt)(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

// unix基本的数据收发接口
// 屏蔽linux/bsd/darwin等的差异
// 在ngx_posix_init.c:ngx_os_init里初始化
typedef struct {
    ngx_recv_pt        recv;        // ngx_unix_recv
    ngx_recv_chain_pt  recv_chain;  // ngx_readv_chain
    ngx_recv_pt        udp_recv;    // ngx_udp_unix_recv
    ngx_send_pt        send;        // ngx_unix_send
    ngx_send_pt        udp_send;
    ngx_send_chain_pt  udp_send_chain;
    ngx_send_chain_pt  send_chain;  // ngx_writev_chain
    ngx_uint_t         flags;
} ngx_os_io_t;


// 在nginx.c的main()调用
// 初始化ngx_os_io结构体，设置基本的收发函数
// 基本的页大小,ngx_pagesize = getpagesize()
// 初始化随机数
// 实际工作在ngx_linux_init.c的ngx_os_specific_init()完成
// 关键操作ngx_os_io = ngx_linux_io;设置为linux的接口函数
ngx_int_t ngx_os_init(ngx_log_t *log);

// 仅打印notice日志，暂无意义
void ngx_os_status(ngx_log_t *log);

// 初始化ngx_os_io结构体，设置为linux的收发函数
// 在ngx_posix_init.c:ngx_os_init里调用
ngx_int_t ngx_os_specific_init(ngx_log_t *log);

// 仅打印notice日志，暂无意义
void ngx_os_specific_status(ngx_log_t *log);

// main()里调用，守护进程化
// 调用fork()，返回0是子进程，非0是父进程
// in ngx_daemon.c
ngx_int_t ngx_daemon(ngx_log_t *log);

// 被ngx_cycle.c里的ngx_signal_process()调用
// 发送reload/stop等信号
// in ngx_process.c
ngx_int_t ngx_os_signal_process(ngx_cycle_t *cycle, char *sig, ngx_pid_t pid);


// nginx实际调用的接收数据函数 in ngx_recv.c
// 从连接里获取读事件，使用系统调用recv读数据
// 尽量多读数据
// 如果数据长度为0，说明流已经结束，ready=0,eof=1
// 如果recv返回-1，表示出错，再检查是否是NGX_EAGAIN
ssize_t ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size);

ssize_t ngx_readv_chain(ngx_connection_t *c, ngx_chain_t *entry, off_t limit);
ssize_t ngx_udp_unix_recv(ngx_connection_t *c, u_char *buf, size_t size);

// ngx_unix_send不区分linux/bsd
// 从连接里获取写事件，使用系统调用send发送数据
// 要求的数据没发送完，说明暂时不能发送，缓冲区可能满了
// 置ready标志，写事件暂时不可用，即不可写
ssize_t ngx_unix_send(ngx_connection_t *c, u_char *buf, size_t size);

// 发送limit长度（字节数）的数据
// limit有限制，但基本上可以说是无限大了
// 如果事件not ready，即暂不可写，那么立即返回，无动作
// 要求缓冲区必须在内存里，否则报错
// 最后返回消费缓冲区之后的链表指针
// 发送出错、遇到again、发送完毕，这三种情况函数结束
ngx_chain_t *ngx_writev_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);

ssize_t ngx_udp_unix_send(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t *ngx_udp_unix_sendmsg_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);


// nginx分配iovec的最大数量，用在ngx_iovec_t.nalloc
#if (IOV_MAX > 64)
#define NGX_IOVS_PREALLOCATE  64
#else
#define NGX_IOVS_PREALLOCATE  IOV_MAX
#endif


// 系统调用writev/readv的结构体
// 封装了底层的iovec，表示多个内存块
typedef struct {
    // struct iovec {
    //     void  *iov_base;    /* Starting address */
    //     size_t iov_len;     /* Number of bytes to transfer */
    // };
    // 类似ngx_str_t，表示一个内存块
    struct iovec  *iovs;

    // iovs数组的长度，即内存块的个数
    ngx_uint_t     count;

    // 所有内存块里的总字节数
    size_t         size;

    // iovs数组的最大长度，count不能超过nalloc
    ngx_uint_t     nalloc;
} ngx_iovec_t;

// 缓冲区链表转换为iovec结构体
// 输出参数vec，存储iovec，输入参数in是nginx的缓冲区链表
// limit，发送数据的限制长度
// 要求缓冲区必须在内存里，否则报错
// 最后返回消费缓冲区之后的链表指针
ngx_chain_t *ngx_output_chain_to_iovec(ngx_iovec_t *vec, ngx_chain_t *in,
    size_t limit, ngx_log_t *log);


// 封装系统调用writev，发送多个内存块
// again，暂时不可写，需要等待事件可写再重试，返回again
// 被中断，需要立即重试，可能就成功了
// 其他的就是错误
ssize_t ngx_writev(ngx_connection_t *c, ngx_iovec_t *vec);


// nginx在linux里实际使用的操作系统接口调用
extern ngx_os_io_t  ngx_os_io;

extern ngx_int_t    ngx_ncpu;
extern ngx_int_t    ngx_max_sockets;
extern ngx_uint_t   ngx_inherited_nonblocking;
extern ngx_uint_t   ngx_tcp_nodelay_and_tcp_nopush;


#if (NGX_FREEBSD)
#include <ngx_freebsd.h>


#elif (NGX_LINUX)
#include <ngx_linux.h>


#elif (NGX_SOLARIS)
#include <ngx_solaris.h>


#elif (NGX_DARWIN)
#include <ngx_darwin.h>
#endif


#endif /* _NGX_OS_H_INCLUDED_ */
