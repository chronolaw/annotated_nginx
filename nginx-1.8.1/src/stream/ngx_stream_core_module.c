// annotated by chrono since 2016

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


// 主要初始化配置结构体里的servers、listen数组
static void *ngx_stream_core_create_main_conf(ngx_conf_t *cf);

// 创建stream模块的srv配置，记录server{}块定义所在的文件和行号
static void *ngx_stream_core_create_srv_conf(ngx_conf_t *cf);

// 配置解析完成后的检查合并配置工作
// 每个server块必须有一个处理handler，否则报错
// 设置errlog和tcp_nodelay
static char *ngx_stream_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

// 设置错误日志
static char *ngx_stream_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 解析server{}指令，定义一个tcp server
static char *ngx_stream_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

// 解析stream/server{}里的listen指令，监听tcp端口
// 遍历已经添加的端口，如果重复则报错
// 检查其他参数，如bind/backlog等，但没有sndbuf/rcvbuf
static char *ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


// stream_core模块的指令，主要是server、listen
// 与http_core类似
static ngx_command_t  ngx_stream_core_commands[] = {

    // 定义一个tcpserver
    { ngx_string("server"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      // 解析server{}指令，定义一个tcp server
      ngx_stream_core_server,
      0,
      0,
      NULL },

    // server监听的端口
    { ngx_string("listen"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      // 解析stream/server[]里的listen指令，监听tcp端口
      // 遍历已经添加的端口，如果重复则报错
      // 检查其他参数，如bind/backlog等，但没有sndbuf/rcvbuf
      ngx_stream_core_listen,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    // 错误日志，可以在stream_main里出现，用于合并配置
    { ngx_string("error_log"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_core_error_log,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    // 可以在stream_main里出现，用于合并配置
    { ngx_string("tcp_nodelay"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_core_module_ctx = {
    NULL,                                  /* postconfiguration */

    // 主要初始化配置结构体里的servers、listen数组
    ngx_stream_core_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    // 创建stream模块的srv配置，记录server{}块定义所在的文件和行号
    ngx_stream_core_create_srv_conf,       /* create server configuration */
    ngx_stream_core_merge_srv_conf         /* merge server configuration */
};


ngx_module_t  ngx_stream_core_module = {
    NGX_MODULE_V1,
    &ngx_stream_core_module_ctx,           /* module context */

    // stream_core模块的指令，主要是server、listen
    ngx_stream_core_commands,              /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// 主要初始化配置结构体里的servers、listen数组
static void *
ngx_stream_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(ngx_stream_core_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_stream_listen_t))
        != NGX_OK)
    {
        return NULL;
    }

    return cmcf;
}


// 创建stream模块的srv配置，记录server{}块定义所在的文件和行号
static void *
ngx_stream_core_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_core_srv_conf_t  *cscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->tcp_nodelay = NGX_CONF_UNSET;

    return cscf;
}


// 配置解析完成后的检查合并配置工作
// 每个server块必须有一个处理handler，否则报错
// 设置errlog和tcp_nodelay
static char *
ngx_stream_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_core_srv_conf_t *prev = parent;
    ngx_stream_core_srv_conf_t *conf = child;

    // 每个server块必须有一个处理handler，否则报错
    if (conf->handler == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no handler for server in %s:%ui",
                      conf->file_name, conf->line);
        return NGX_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    // 默认tcp_nodelay=1
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    return NGX_CONF_OK;
}


// 设置错误日志
static char *
ngx_stream_core_error_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf = conf;

    return ngx_log_set_log(cf, &cscf->error_log);
}


// 解析server{}指令，定义一个tcp server
static char *
ngx_stream_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                         *rv;
    void                         *mconf;
    ngx_uint_t                    m;
    ngx_conf_t                    pcf;
    ngx_stream_module_t          *module;
    ngx_stream_conf_ctx_t        *ctx, *stream_ctx;
    ngx_stream_core_srv_conf_t   *cscf, **cscfp;
    ngx_stream_core_main_conf_t  *cmcf;

    // 创建当前server的配置
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    // 保存stream{}的配置上下文
    // 也就是stream{}里的ngx_stream_conf_ctx_t
    stream_ctx = cf->ctx;

    // main_conf直接指向stream{}的main_conf
    ctx->main_conf = stream_ctx->main_conf;

    /* the server{}'s srv_conf */

    // 分配存储srv_conf的数组，数量是ngx_stream_max_module
    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    // 遍历模块数组，调用每个stream模块create_srv_conf，创建配置结构体
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是流模块的函数表，用于解析配置时调用
        module = ngx_modules[m]->ctx;

        // 创建每个模块的srv_conf
        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    // 以下代码存储了各个server{}的配置，注意！！

    // 获取stream_core模块的srv配置
    // 注意这里是当前server{}里的配置数组，不是main的
    cscf = ctx->srv_conf[ngx_stream_core_module.ctx_index];

    // 存储关联此server{}块的配置数组！
    // ctx是刚才刚创建的配置结构体
    // 这样在stream_core配置里的ctx就存储了此server的全部配置信息(实际上只是指针)
    cscf->ctx = ctx;

    // 获取stream_core模块的main配置
    // 虽然使用的是当前server的ctx，但实际上是stream{}里的main conf
    // cmcf只有一个
    cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];

    // stream_core模块的server配置加入main_conf的servers数组
    // 这样用一个main conf就存储了所有的server信息
    // 在cmcf->servers里遍历查找即可
    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    // 暂存当前的解析上下文
    pcf = *cf;

    // 设置stream模块的新解析上下文
    // 使用刚才刚创建的配置结构体存储模块的配置信息
    cf->ctx = ctx;
    cf->cmd_type = NGX_STREAM_SRV_CONF;

    // 递归解析事件相关模块
    rv = ngx_conf_parse(cf, NULL);

    // 恢复之前保存的解析上下文
    *cf = pcf;

    return rv;
}


// 解析stream/server{}里的listen指令，监听tcp端口
// 遍历已经添加的端口，如果重复则报错
// 检查其他参数，如bind/backlog等，但没有sndbuf/rcvbuf
static char *
ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    size_t                        len, off;
    in_port_t                     port;
    ngx_str_t                    *value;
    ngx_url_t                     u;
    ngx_uint_t                    i;
    struct sockaddr              *sa;
    struct sockaddr_in           *sin;
    ngx_stream_listen_t          *ls;
    ngx_stream_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6          *sin6;
#endif

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    // 获取stream core模块的main_conf，只有一个
    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    // 准备添加监听端口
    ls = cmcf->listen.elts;

    // 遍历已经添加的端口，如果重复则报错
    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = &ls[i].u.sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            off = offsetof(struct sockaddr_in6, sin6_addr);
            len = 16;
            sin6 = &ls[i].u.sockaddr_in6;
            port = sin6->sin6_port;
            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            off = offsetof(struct sockaddr_un, sun_path);
            len = sizeof(((struct sockaddr_un *) sa)->sun_path);
            port = 0;
            break;
#endif

        default: /* AF_INET */
            off = offsetof(struct sockaddr_in, sin_addr);
            len = 4;
            sin = &ls[i].u.sockaddr_in;
            port = sin->sin_port;
            break;
        }

        if (ngx_memcmp(ls[i].u.sockaddr_data + off, u.sockaddr + off, len)
            != 0)
        {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    // 向数组里添加一个ngx_stream_listen_t结构体
    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_stream_listen_t));

    ngx_memcpy(&ls->u.sockaddr, u.sockaddr, u.socklen);

    // 从ngx_url_t里拷贝信息
    ls->socklen = u.socklen;
    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->wildcard = u.wildcard;

    // 注意这里,存储了cf->ctx，也就是此server的配置数组ngx_stream_conf_ctx_t
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    ls->ipv6only = 1;
#endif

    // 检查其他参数，如bind/backlog等，但没有sndbuf/rcvbuf
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            u_char  buf[NGX_SOCKADDR_STRLEN];

            sa = &ls->u.sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 0;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "invalid ipv6only flags \"%s\"",
                                       &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, ls->socklen, buf,
                                    NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ipv6only is not supported "
                                   "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "reuseport") == 0) {
#if (NGX_HAVE_REUSEPORT)
            ls->reuseport = 1;
            ls->bind = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_STREAM_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_stream_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (ngx_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (ngx_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                ngx_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = ngx_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = ngx_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = ngx_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == NGX_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
                    && ls->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return NGX_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
