// annotated by chrono since 2016
//
// * ngx_http_header_filter

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

// ngx_http_header_filter_module是modules数组里第一个header filter模块
// 因为nginx依据数组顺序设置链表指针
// 所以它是header过滤链表里的最后一个节点
// 作用是整理headers_out里的头信息，拼接成响应头字符串
// 最后交给ngx_http_write_filter输出，即发送到socket

// 初始化header过滤链表头节点，保证链表末尾不是空指针
// 此时头节点是ngx_http_header_filter
static ngx_int_t ngx_http_header_filter_init(ngx_conf_t *cf);

// 作用是整理headers_out里的头信息，拼接成响应头字符串
// 最后交给ngx_http_write_filter输出，即发送到socket
static ngx_int_t ngx_http_header_filter(ngx_http_request_t *r);


// 函数表里只有一个init函数，初始化链表指针
static ngx_http_module_t  ngx_http_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_header_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


// 没有其他配置相关的信息
ngx_module_t  ngx_http_header_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_header_filter_module_ctx,    /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 输出响应头里的server信息，短字符串，不含版本号
// server_tokens off使用此字符串
static u_char ngx_http_server_string[] = "Server: nginx" CRLF;

// 输出响应头里的server信息，长字符串，含版本号
// server_tokens on使用此字符串
static u_char ngx_http_server_full_string[] = "Server: " NGINX_VER CRLF;

// 1.11.10新增的build参数
static u_char ngx_http_server_build_string[] = "Server: " NGINX_VER_BUILD CRLF;


// 状态行字符串的关联数组
// 采用状态码减取基准的方法实现映射，很巧妙
// 例如201-200=1, 302-300 + 7
// 可以在这里加入自己的状态码定义
static ngx_str_t ngx_http_status_lines[] = {

    ngx_string("200 OK"),
    ngx_string("201 Created"),
    ngx_string("202 Accepted"),
    ngx_null_string,  /* "203 Non-Authoritative Information" */
    ngx_string("204 No Content"),
    ngx_null_string,  /* "205 Reset Content" */
    ngx_string("206 Partial Content"),

    /* ngx_null_string, */  /* "207 Multi-Status" */

#define NGX_HTTP_LAST_2XX  207

// 使用此偏移量计算3xx的位置
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)

    /* ngx_null_string, */  /* "300 Multiple Choices" */

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_string("303 See Other"),
    ngx_string("304 Not Modified"),
    ngx_null_string,  /* "305 Use Proxy" */
    ngx_null_string,  /* "306 unused" */
    ngx_string("307 Temporary Redirect"),
    ngx_string("308 Permanent Redirect"),

// 使用此偏移量计算4xx的位置
#define NGX_HTTP_LAST_3XX  309

#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string("400 Bad Request"),
    ngx_string("401 Unauthorized"),
    ngx_string("402 Payment Required"),
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_string("406 Not Acceptable"),
    ngx_null_string,  /* "407 Proxy Authentication Required" */
    ngx_string("408 Request Time-out"),
    ngx_string("409 Conflict"),
    ngx_string("410 Gone"),
    ngx_string("411 Length Required"),
    ngx_string("412 Precondition Failed"),
    ngx_string("413 Request Entity Too Large"),
    ngx_string("414 Request-URI Too Large"),
    ngx_string("415 Unsupported Media Type"),
    ngx_string("416 Requested Range Not Satisfiable"),
    ngx_null_string,  /* "417 Expectation Failed" */
    ngx_null_string,  /* "418 unused" */
    ngx_null_string,  /* "419 unused" */
    ngx_null_string,  /* "420 unused" */
    ngx_string("421 Misdirected Request"),
    ngx_null_string,  /* "422 Unprocessable Entity" */
    ngx_null_string,  /* "423 Locked" */
    ngx_null_string,  /* "424 Failed Dependency" */
    ngx_null_string,  /* "425 unused" */
    ngx_null_string,  /* "426 Upgrade Required" */
    ngx_null_string,  /* "427 unused" */
    ngx_null_string,  /* "428 Precondition Required" */
    ngx_string("429 Too Many Requests"),

// 使用此偏移量计算5xx的位置
// 1.12.0之前是422
#define NGX_HTTP_LAST_4XX  430

#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out"),
    ngx_string("505 HTTP Version Not Supported"),
    ngx_null_string,        /* "506 Variant Also Negotiates" */
    ngx_string("507 Insufficient Storage"),

    /* ngx_null_string, */  /* "508 unused" */
    /* ngx_null_string, */  /* "509 unused" */
    /* ngx_null_string, */  /* "510 Not Extended" */

#define NGX_HTTP_LAST_5XX  508

};


// 常用头与headers_out里成员的映射关系
// 使用了宏offsetof，直接得到成员的地址
// 本模块并不使用，供其他模块使用
ngx_http_header_out_t  ngx_http_headers_out[] = {
    { ngx_string("Server"), offsetof(ngx_http_headers_out_t, server) },
    { ngx_string("Date"), offsetof(ngx_http_headers_out_t, date) },
    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_out_t, content_length) },
    { ngx_string("Content-Encoding"),
                 offsetof(ngx_http_headers_out_t, content_encoding) },
    { ngx_string("Location"), offsetof(ngx_http_headers_out_t, location) },
    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_headers_out_t, last_modified) },
    { ngx_string("Accept-Ranges"),
                 offsetof(ngx_http_headers_out_t, accept_ranges) },
    { ngx_string("Expires"), offsetof(ngx_http_headers_out_t, expires) },
    { ngx_string("Cache-Control"),
                 offsetof(ngx_http_headers_out_t, cache_control) },
    { ngx_string("ETag"), offsetof(ngx_http_headers_out_t, etag) },

    { ngx_null_string, 0 }
};


// 作用是整理headers_out里的头信息，拼接成响应头字符串
// 首先检查r->header_sent，如果已经调用此函数（即已经发送了）则直接返回
// 计算状态行+响应头的长度
// 没有自定义状态行，那就需要根据状态码映射到标准描述信息
// 遍历响应头链表，添加自定义头，注意不检查是否有常用头（如server等）
// 所以常用头不应该放进链表，而应该使用指针直接赋值
// 最后交给ngx_http_write_filter输出，即发送到socket
static ngx_int_t
ngx_http_header_filter(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    ngx_str_t                  host, *status_line;
    ngx_buf_t                 *b;
    ngx_uint_t                 status, i, port;
    ngx_chain_t                out;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    u_char                     addr[NGX_SOCKADDR_STRLEN];

    // 首先检查r->header_sent，如果已经调用此函数（即已经发送了）则直接返回
    if (r->header_sent) {
        return NGX_OK;
    }

    // 设置r->header_sent，防止重复发送
    r->header_sent = 1;

    // 子请求不会发送头
    // 也就是说不会走socket，可以加入父请求的数据链里发送
    if (r != r->main) {
        return NGX_OK;
    }

    // http 协议不是1.0/1.1也不发送
    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_OK;
    }

    // 查看客户端发送请求的方法，如果是head请求
    // 表示不要求body，置header_only标志
    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    // 响应头里有last_modified_time
    // 但状态码不是正常，那么就清除此头
    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    // 下面开始计算状态行+响应头的长度

    // 首先是状态行
    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
          /* the end of the header */
          + sizeof(CRLF) - 1;

    /* status line */

    // 如果我们在headers_out设置了自己的状态信息
    // 那么就比较简单，直接使用即可
    if (r->headers_out.status_line.len) {

        // 长度加上headers_out.status_line的长度
        len += r->headers_out.status_line.len;

        // 状态行直接使用请求结构体里的字符串
        status_line = &r->headers_out.status_line;
#if (NGX_SUPPRESS_WARN)
        status = 0;
#endif

    } else {

        // 没有自定义状态行，那就需要根据状态码映射到标准描述信息

        // 获取状态码
        status = r->headers_out.status;

        // 2xx代码
        // 之后的3xx/4xx的逻辑基本相同
        if (status >= NGX_HTTP_OK
            && status < NGX_HTTP_LAST_2XX)
        {
            /* 2XX */

            if (status == NGX_HTTP_NO_CONTENT) {
                r->header_only = 1;
                ngx_str_null(&r->headers_out.content_type);
                r->headers_out.last_modified_time = -1;
                r->headers_out.last_modified = NULL;
                r->headers_out.content_length = NULL;
                r->headers_out.content_length_n = -1;
            }

            // 减去200，从&ngx_http_status_lines里得到状态码描述信息
            status -= NGX_HTTP_OK;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_MOVED_PERMANENTLY
                   && status < NGX_HTTP_LAST_3XX)
        {
            /* 3XX */

            if (status == NGX_HTTP_NOT_MODIFIED) {
                r->header_only = 1;
            }

            status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_BAD_REQUEST
                   && status < NGX_HTTP_LAST_4XX)
        {
            /* 4XX */
            status = status - NGX_HTTP_BAD_REQUEST
                            + NGX_HTTP_OFF_4XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR
                   && status < NGX_HTTP_LAST_5XX)
        {
            /* 5XX */
            status = status - NGX_HTTP_INTERNAL_SERVER_ERROR
                            + NGX_HTTP_OFF_5XX;

            status_line = &ngx_http_status_lines[status];
            len += ngx_http_status_lines[status].len;

        } else {
            // 不是标准http状态码
            len += NGX_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }

        if (status_line && status_line->len == 0) {
            status = r->headers_out.status;
            len += NGX_INT_T_LEN + 1 /* SP */;
            status_line = NULL;
        }
    }

    // 下面开始计算各种常用头

    // 本location的配置
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    // 是否是完整的server信息
    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            len += sizeof(ngx_http_server_full_string) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            len += sizeof(ngx_http_server_build_string) - 1;

        } else {
            len += sizeof(ngx_http_server_string) - 1;
        }
    }

    // 日期
    if (r->headers_out.date == NULL) {
        len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    // content_type
    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    // 内容长度
    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
    }

    // last_modified
    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
    }

    c = r->connection;

    // location
    if (r->headers_out.location
        && r->headers_out.location->value.len
        && r->headers_out.location->value.data[0] == '/'
        && clcf->absolute_redirect)
    {
        r->headers_out.location->hash = 0;

        if (clcf->server_name_in_redirect) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            host = cscf->server_name;

        } else if (r->headers_in.server.len) {
            host = r->headers_in.server;

        } else {
            host.len = NGX_SOCKADDR_STRLEN;
            host.data = addr;

            if (ngx_connection_local_sockaddr(c, &host, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

        port = ngx_inet_get_port(c->local_sockaddr);

        len += sizeof("Location: https://") - 1
               + host.len
               + r->headers_out.location->value.len + 2;

        if (clcf->port_in_redirect) {

#if (NGX_HTTP_SSL)
            if (c->ssl)
                port = (port == 443) ? 0 : port;
            else
#endif
                port = (port == 80) ? 0 : port;

        } else {
            port = 0;
        }

        if (port) {
            len += sizeof(":65535") - 1;
        }

    } else {
        ngx_str_null(&host);
        port = 0;
    }

    // 是否是chunked编码
    if (r->chunked) {
        len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
    }

    // keepalive
    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        len += sizeof("Connection: upgrade" CRLF) - 1;

    } else if (r->keepalive) {
        len += sizeof("Connection: keep-alive" CRLF) - 1;

        /*
         * MSIE and Opera ignore the "Keep-Alive: timeout=<N>" header.
         * MSIE keeps the connection alive for about 60-65 seconds.
         * Opera keeps the connection alive very long.
         * Mozilla keeps the connection alive for N plus about 1-10 seconds.
         * Konqueror keeps the connection alive for about N seconds.
         */

        if (clcf->keepalive_header) {
            len += sizeof("Keep-Alive: timeout=") - 1 + NGX_TIME_T_LEN + 2;
        }

    } else {
        len += sizeof("Connection: close" CRLF) - 1;
    }

    // gzip
#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += sizeof("Vary: Accept-Encoding" CRLF) - 1;

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

    // 常用头处理完毕，下面是自定义头

    // 遍历响应头链表
    part = &r->headers_out.headers.part;
    header = part->elts;

    // 注意，这里不检查是否有常用头（如server等）
    // 所以常用头不应该放进链表，而应该使用指针直接赋值
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        // hash==0就忽略，所以可以用这种方法“删除”头
        if (header[i].hash == 0) {
            continue;
        }

        len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len
               + sizeof(CRLF) - 1;
    }

    // 所有状态行和响应头的长度都已经计算完
    // 可以分配内存了

    // len长度可以容纳所有的响应头信息
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    /* "HTTP/1.x " */
    b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */

    // 有状态行就拷贝数据
    // 注意用ngx_copy会返回拷贝后的末尾位置信息，方便继续拷贝
    if (status_line) {
        b->last = ngx_copy(b->last, status_line->data, status_line->len);

    } else {
        // 没有状态行信息，只能把数字打印出来
        b->last = ngx_sprintf(b->last, "%03ui ", status);
    }

    // 状态行结束，加上\r\n
    *b->last++ = CR; *b->last++ = LF;

    // server
    if (r->headers_out.server == NULL) {
        if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_ON) {
            p = ngx_http_server_full_string;
            len = sizeof(ngx_http_server_full_string) - 1;

        } else if (clcf->server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD) {
            p = ngx_http_server_build_string;
            len = sizeof(ngx_http_server_build_string) - 1;

        } else {
            p = ngx_http_server_string;
            len = sizeof(ngx_http_server_string) - 1;
        }

        b->last = ngx_cpymem(b->last, p, len);
    }

    // date
    if (r->headers_out.date == NULL) {
        b->last = ngx_cpymem(b->last, "Date: ", sizeof("Date: ") - 1);
        b->last = ngx_cpymem(b->last, ngx_cached_http_time.data,
                             ngx_cached_http_time.len);

        *b->last++ = CR; *b->last++ = LF;
    }

    // content_type
    if (r->headers_out.content_type.len) {
        b->last = ngx_cpymem(b->last, "Content-Type: ",
                             sizeof("Content-Type: ") - 1);
        p = b->last;
        b->last = ngx_copy(b->last, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            b->last = ngx_cpymem(b->last, "; charset=",
                                 sizeof("; charset=") - 1);
            b->last = ngx_copy(b->last, r->headers_out.charset.data,
                               r->headers_out.charset.len);

            /* update r->headers_out.content_type for possible logging */

            r->headers_out.content_type.len = b->last - p;
            r->headers_out.content_type.data = p;
        }

        *b->last++ = CR; *b->last++ = LF;
    }

    // content_length
    // 通常我们不需要写字符串，让nginx在这里打印为字符串
    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        b->last = ngx_sprintf(b->last, "Content-Length: %O" CRLF,
                              r->headers_out.content_length_n);
    }

    // last_modified
    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        b->last = ngx_cpymem(b->last, "Last-Modified: ",
                             sizeof("Last-Modified: ") - 1);
        b->last = ngx_http_time(b->last, r->headers_out.last_modified_time);

        *b->last++ = CR; *b->last++ = LF;
    }

    // location
    if (host.data) {

        p = b->last + sizeof("Location: ") - 1;

        b->last = ngx_cpymem(b->last, "Location: http",
                             sizeof("Location: http") - 1);

#if (NGX_HTTP_SSL)
        if (c->ssl) {
            *b->last++ ='s';
        }
#endif

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';
        b->last = ngx_copy(b->last, host.data, host.len);

        if (port) {
            b->last = ngx_sprintf(b->last, ":%ui", port);
        }

        b->last = ngx_copy(b->last, r->headers_out.location->value.data,
                           r->headers_out.location->value.len);

        /* update r->headers_out.location->value for possible logging */

        r->headers_out.location->value.len = b->last - p;
        r->headers_out.location->value.data = p;
        ngx_str_set(&r->headers_out.location->key, "Location");

        *b->last++ = CR; *b->last++ = LF;
    }

    // chunked
    if (r->chunked) {
        b->last = ngx_cpymem(b->last, "Transfer-Encoding: chunked" CRLF,
                             sizeof("Transfer-Encoding: chunked" CRLF) - 1);
    }

    // keepalive
    if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
        b->last = ngx_cpymem(b->last, "Connection: upgrade" CRLF,
                             sizeof("Connection: upgrade" CRLF) - 1);

    } else if (r->keepalive) {
        b->last = ngx_cpymem(b->last, "Connection: keep-alive" CRLF,
                             sizeof("Connection: keep-alive" CRLF) - 1);

        if (clcf->keepalive_header) {
            b->last = ngx_sprintf(b->last, "Keep-Alive: timeout=%T" CRLF,
                                  clcf->keepalive_header);
        }

    } else {
        b->last = ngx_cpymem(b->last, "Connection: close" CRLF,
                             sizeof("Connection: close" CRLF) - 1);
    }

    // gzip
#if (NGX_HTTP_GZIP)
    if (r->gzip_vary) {
        b->last = ngx_cpymem(b->last, "Vary: Accept-Encoding" CRLF,
                             sizeof("Vary: Accept-Encoding" CRLF) - 1);
    }
#endif

    // 自定义头逐个添加
    // 不检查是否与server等常用头冲突
    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        // hash==0就忽略，所以可以用这种方法“删除”头
        if (header[i].hash == 0) {
            continue;
        }

        b->last = ngx_copy(b->last, header[i].key.data, header[i].key.len);

        // 这里在冒号后有一个空格
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = ngx_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "%*s", (size_t) (b->last - b->pos), b->pos);

    /* the end of HTTP header */

    // 响应头结束，再加上一个\r\n
    *b->last++ = CR; *b->last++ = LF;

    // 两个指针相减，得到头的长度
    r->header_size = b->last - b->pos;

    // 检查是否只需要返回头
    if (r->header_only) {
        // 标记为最后一块数据，之后就不能再发送给客户端了
        b->last_buf = 1;
    }

    // 添加进数据链表
    out.buf = b;
    out.next = NULL;

    // 定义在ngx_http_write_filter_module.c
    // 真正的向客户端发送数据，调用send_chain
    // 如果数据发送不完，就保存在r->out里，返回again
    // 需要再次发生可写事件才能发送
    // 不是last、flush，且数据量较小（默认1460）
    // 那么这次就不真正调用write发送，减少系统调用的次数，提高性能
    // 在此函数里处理限速
    return ngx_http_write_filter(r, &out);
}


// 初始化header过滤链表头节点，保证链表末尾不是空指针
// 此时头节点是ngx_http_header_filter
static ngx_int_t
ngx_http_header_filter_init(ngx_conf_t *cf)
{
    ngx_http_top_header_filter = ngx_http_header_filter;

    return NGX_OK;
}
