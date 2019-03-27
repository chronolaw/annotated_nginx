// annotated by chrono since 2016
//
// * ngx_sockaddr_t
// * ngx_inet_addr
// * ngx_sock_ntop

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_INET_H_INCLUDED_
#define _NGX_INET_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// ipv4地址字符串长度
#define NGX_INET_ADDRSTRLEN   (sizeof("255.255.255.255") - 1)

// ipv6地址字符串长度
#define NGX_INET6_ADDRSTRLEN                                                 \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)

// unix domain socket地址字符串长度
#define NGX_UNIX_ADDRSTRLEN                                                  \
    (sizeof("unix:") - 1 +                                                   \
     sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#if (NGX_HAVE_UNIX_DOMAIN)
#define NGX_SOCKADDR_STRLEN   NGX_UNIX_ADDRSTRLEN
#elif (NGX_HAVE_INET6)
#define NGX_SOCKADDR_STRLEN   (NGX_INET6_ADDRSTRLEN + sizeof("[]:65535") - 1)
#else
#define NGX_SOCKADDR_STRLEN   (NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1)
#endif

/* compatibility */
#define NGX_SOCKADDRLEN       sizeof(ngx_sockaddr_t)


// 联合体，支持ipv4/ipv6等
typedef union {
    struct sockaddr           sockaddr;
    struct sockaddr_in        sockaddr_in;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
    struct sockaddr_un        sockaddr_un;
#endif
} ngx_sockaddr_t;


typedef struct {
    in_addr_t                 addr;
    in_addr_t                 mask;
} ngx_in_cidr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr           addr;
    struct in6_addr           mask;
} ngx_in6_cidr_t;

#endif


typedef struct {
    ngx_uint_t                family;
    union {
        ngx_in_cidr_t         in;
#if (NGX_HAVE_INET6)
        ngx_in6_cidr_t        in6;
#endif
    } u;
} ngx_cidr_t;


// nginx使用的ip地址结构体
typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 name;
} ngx_addr_t;


typedef struct {
    // url的字符串表示
    ngx_str_t                 url;

    ngx_str_t                 host;
    ngx_str_t                 port_text;
    ngx_str_t                 uri;

    in_port_t                 port;
    in_port_t                 default_port;

    // 1.15.10新增，range listen
    in_port_t                 last_port;

    int                       family;

    unsigned                  listen:1;
    unsigned                  uri_part:1;
    unsigned                  no_resolve:1;

    unsigned                  no_port:1;
    unsigned                  wildcard:1;

    socklen_t                 socklen;
    ngx_sockaddr_t            sockaddr;

    ngx_addr_t               *addrs;
    ngx_uint_t                naddrs;

    char                     *err;
} ngx_url_t;


// 把形如127.0.0.1的字符串转换为in_addr_t
// 调用的是htonl，转换为网络字节序的无符号整数
in_addr_t ngx_inet_addr(u_char *text, size_t len);

#if (NGX_HAVE_INET6)
ngx_int_t ngx_inet6_addr(u_char *p, size_t len, u_char *addr);
size_t ngx_inet6_ntop(u_char *p, u_char *text, size_t len);
#endif

// socket地址转换为字符串
// port是个标志量，是否输出端口号，不是实际的端口值
// 支持ipv4/v6，不需要再调用ntoa函数了
// 返回的是字符串长度
size_t ngx_sock_ntop(struct sockaddr *sa, socklen_t socklen, u_char *text,
    size_t len, ngx_uint_t port);

// 使用family socket地址转换为字符串
size_t ngx_inet_ntop(int family, void *addr, u_char *text, size_t len);

ngx_int_t ngx_ptocidr(ngx_str_t *text, ngx_cidr_t *cidr);

ngx_int_t ngx_cidr_match(struct sockaddr *sa, ngx_array_t *cidrs);

// 把形如127.0.0.1的字符串转换为ngx_addr_t
ngx_int_t ngx_parse_addr(ngx_pool_t *pool, ngx_addr_t *addr, u_char *text,
    size_t len);

ngx_int_t ngx_parse_addr_port(ngx_pool_t *pool, ngx_addr_t *addr,
    u_char *text, size_t len);

// 根据字符串的不同，调用不同的函数解析url，得到ip地址等信息
// 以unix:开头的是unix domain socket
// 以[开头的是ipv6
// 其他的是ipv4
ngx_int_t ngx_parse_url(ngx_pool_t *pool, ngx_url_t *u);

ngx_int_t ngx_inet_resolve_host(ngx_pool_t *pool, ngx_url_t *u);
ngx_int_t ngx_cmp_sockaddr(struct sockaddr *sa1, socklen_t slen1,
    struct sockaddr *sa2, socklen_t slen2, ngx_uint_t cmp_port);

// 1.11.x 新增
// 获取socket结构体里的端口
in_port_t ngx_inet_get_port(struct sockaddr *sa);

void ngx_inet_set_port(struct sockaddr *sa, in_port_t port);
ngx_uint_t ngx_inet_wildcard(struct sockaddr *sa);


#endif /* _NGX_INET_H_INCLUDED_ */
