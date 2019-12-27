// annotated by chrono since 2016
//
// 工作在CONTENT阶段
// 读取磁盘上的静态文件作为响应内容
// 提供Nginx作为Web服务器最基本的功能

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// 读取磁盘上的静态文件作为响应内容
static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r);

// postconfiguration，注册处理函数
static ngx_int_t ngx_http_static_init(ngx_conf_t *cf);


// 仅一个函数指针，注册处理函数
static ngx_http_module_t  ngx_http_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_static_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_static_module = {
    NGX_MODULE_V1,
    &ngx_http_static_module_ctx,           /* module context */
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


// 读取磁盘上的静态文件作为响应内容
static ngx_int_t
ngx_http_static_handler(ngx_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    // 检查method，必须是get/head/post
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // 检查uri，最后一个字符不能是'/'，也就是说不允许操作目录
    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    // 把uri映射到磁盘目录path
    // 根据root/alias指令决定正确的文件位置
    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // last是计算后的末尾位置，减去开始地址就是path长度
    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    // 获取core loc conf
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    // 设置打开文件的选项
    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    // 不允许符号链接
    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        ngx_http_clear_location(r);

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && r->args.len == 0) {
            location = path.data + root;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                ngx_http_clear_location(r);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    // 不允许post数据到一个文件
    // 即只允许get/head
    if (r->method == NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // 丢弃请求体
    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    // 设置响应头信息：状态码，长度，修改时间
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    // 设置etag头
    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // content type
    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // r != r->main 子请求
    // of.size == 0 文件长度是0
    // 那么就只发送头，没有实际的响应数据
    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    // 允许range请求
    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    // 创建一个缓冲区结构体，注意不分配实际内存
    // before 1.14.0
    // b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 创建一个文件结构体，用于描述磁盘文件
    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 先发送头
    rc = ngx_http_send_header(r);

    // 发送出错，或者head请求，就无需发送body
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    // 设置缓冲区里的file位置信息
    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;

    // 如果是主请求，那么last_buf，即最后一块数据
    b->last_buf = (r == r->main) ? 1: 0;

    // 因为只有一块数据，链里的唯一一个也就是最后一个
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    // 把缓冲区放进链表里
    out.buf = b;

    // 重要操作，链表的指针必须是nullptr，否则会发生严重错误
    out.next = NULL;

    // 调用过滤链表，走过滤模块，最终发送给客户端
    return ngx_http_output_filter(r, &out);
}


// postconfiguration，注册处理函数
static ngx_int_t
ngx_http_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    // 获取core模块的main conf
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // 使用CONTENT_PHASE
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    // 添加到phases数组，完成注册
    *h = ngx_http_static_handler;

    return NGX_OK;
}
