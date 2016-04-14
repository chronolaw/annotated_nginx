// annotated by chrono since 2016
//
// * ngx_stream_block

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>


// 解析stream{}配置块，与events类似
// tcp流处理的配置结构体，里面有main_conf/srv_conf两个数组
// 在cycle里存储配置指针
// 设置stream模块的ctx_index
// 分配存储main_conf/srv_conf的数组，数量是ngx_stream_max_module
// 遍历模块数组，调用每个stream模块create_xxx_conf，创建配置结构体
// 之后解析配置，解析完成后初始化main_conf，合并srv_conf,调用postconfiguration
// 得到stream_core里的监听端口
// 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
// 设置有连接发生时的回调函数ngx_stream_init_connection
static char *ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 把监听结构体添加进ports数组
// 多个相同的监听端口用一个数组元素，在addrs.opt里保存
static ngx_int_t ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_stream_listen_t *listen);

// 对已经整理好的监听端口数组排序
// 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
// 设置有连接发生时的回调函数ngx_stream_init_connection
static char *ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);

static ngx_int_t ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_stream_add_addrs6(ngx_conf_t *cf,
    ngx_stream_port_t *stport, ngx_stream_conf_addr_t *addr);
#endif

// 根据wildcard、bind对port排序
static ngx_int_t ngx_stream_cmp_conf_addrs(const void *one, const void *two);


// 计数器，得到所有的stream模块数量
// 1.9.11后改用cycle里的变量
ngx_uint_t  ngx_stream_max_module;


// stream模块只有一个指令，解析stream{}配置块，与events类似
static ngx_command_t  ngx_stream_commands[] = {

    { ngx_string("stream"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,

      // 解析stream{}配置块，与events类似
      // tcp流处理的配置结构体，里面有main_conf/srv_conf两个数组
      // 在cycle里存储配置指针
      // 设置stream模块的ctx_index
      // 分配存储main_conf/srv_conf的数组，数量是ngx_stream_max_module
      // 遍历模块数组，调用每个stream模块create_xxx_conf，创建配置结构体
      // 之后解析配置，解析完成后初始化main_conf，合并srv_conf,调用postconfiguration
      // 得到stream_core里的监听端口
      // 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
      // 设置有连接发生时的回调函数ngx_stream_init_connection
      ngx_stream_block,

      0,
      0,
      NULL },

      ngx_null_command
};


// 没有create/init函数，只有出现stream指令才创建配置结构体
static ngx_core_module_t  ngx_stream_module_ctx = {
    ngx_string("stream"),
    NULL,
    NULL
};


ngx_module_t  ngx_stream_module = {
    NGX_MODULE_V1,

    // 没有create/init函数，只有出现stream指令才创建配置结构体
    &ngx_stream_module_ctx,                /* module context */

    // stream模块只有一个指令，解析stream{}配置块，与events类似
    ngx_stream_commands,                   /* module directives */

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


// 解析stream{}配置块，与events类似
// tcp流处理的配置结构体，里面有main_conf/srv_conf两个数组
// 在cycle里存储配置指针
// 设置stream模块的ctx_index
// 分配存储main_conf/srv_conf的数组，数量是ngx_stream_max_module
// 遍历模块数组，调用每个stream模块create_xxx_conf，创建配置结构体
// 之后解析配置，解析完成后初始化main_conf，合并srv_conf,调用postconfiguration
// 得到stream_core里的监听端口
// 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
// 设置有连接发生时的回调函数ngx_stream_init_connection
static char *
ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                          *rv;
    ngx_uint_t                     i, m, mi, s;
    ngx_conf_t                     pcf;
    ngx_array_t                    ports;
    ngx_stream_listen_t           *listen;
    ngx_stream_module_t           *module;
    ngx_stream_conf_ctx_t         *ctx;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_core_main_conf_t   *cmcf;

    // tcp流处理的配置结构体，里面有main_conf/srv_conf两个数组
    // 不允许重复配置
    if (*(ngx_stream_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main stream context */

    // 创建配置结构体
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    // 在cycle里存储这个指针
    *(ngx_stream_conf_ctx_t **) conf = ctx;

    /* count the number of the stream modules and set up their indices */

    // 得到所有的stream模块数量
    // 设置stream模块的ctx_index
    ngx_stream_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // 设置stream模块的ctx_index
        ngx_modules[m]->ctx_index = ngx_stream_max_module++;
    }


    /* the stream main_conf context, it's the same in the all stream contexts */

    // 分配存储main_conf的数组，数量是ngx_stream_max_module
    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_stream_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the stream null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    // 分配存储srv_conf的数组，数量是ngx_stream_max_module
    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all stream modules
     */

    // 遍历模块数组，调用每个stream模块create_xxx_conf，创建配置结构体
    // 这些配置结构体存储在最顶层，也就是stream_main
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        // 创建每个模块的main_conf
        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        // 创建每个模块的srv_conf
        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the stream{} block */

    // 初始的解析环境已经准备好，下面开始解析stream{}配置

    // 暂存当前的解析上下文
    pcf = *cf;

    // 设置事件模块的新解析上下文
    cf->ctx = ctx;

    cf->module_type = NGX_STREAM_MODULE;
    cf->cmd_type = NGX_STREAM_MAIN_CONF;

    // 递归解析事件相关模块
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        // 恢复之前保存的解析上下文
        *cf = pcf;
        return rv;
    }


    /* init stream{} main_conf's, merge the server{}s' srv_conf's */

    // 检查stream_core的main配置结构体
    cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];

    // 得到配置的server数量
    cscfp = cmcf->servers.elts;

    // 初始化main_conf，合并srv_conf
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是流模块的函数表，用于解析配置时调用
        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init stream{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    // 配置解析完毕，调用模块的postconfiguration
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是流模块的函数表，用于解析配置时调用
        module = ngx_modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    // 恢复之前保存的解析上下文
    *cf = pcf;


    // 初始化一个动态数组，准备存储监听端口
    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_stream_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    // 得到stream_core里的监听端口
    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        // 把监听结构体添加进ports数组
        // 多个相同的监听端口用一个数组元素，在addrs.opt里保存
        if (ngx_stream_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    // 对已经整理好的监听端口数组排序
    // 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
    // 设置有连接发生时的回调函数ngx_stream_init_connection
    return ngx_stream_optimize_servers(cf, &ports);
}


// 把监听结构体添加进ports数组
// 多个相同的监听端口用一个数组元素，在addrs.opt里保存
static ngx_int_t
ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_stream_listen_t *listen)
{
    in_port_t                p;
    ngx_uint_t               i;
    struct sockaddr         *sa;
    struct sockaddr_in      *sin;
    ngx_stream_conf_port_t  *port;
    ngx_stream_conf_addr_t  *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6     *sin6;
#endif

    // 得到监听端口结构体里的socket地址
    sa = &listen->u.sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = &listen->u.sockaddr_in6;
        p = sin6->sin6_port;
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        p = 0;
        break;
#endif

    default: /* AF_INET */
        sin = &listen->u.sockaddr_in;
        p = sin->sin_port;
        break;
    }

    // 判断端口是否已经添加过了
    // 因为可能多个server都用listen监听同一个端口
    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    // 没有添加过，是一个新的端口
    // 加入动态数组
    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    // 把listen结构体存储在addrs数组里供以后使用
    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_stream_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    // 把listen结构体存储在addrs数组里供以后使用
    addr->opt = *listen;

    return NGX_OK;
}



// 对已经整理好的监听端口数组排序
// 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
// 设置有连接发生时的回调函数ngx_stream_init_connection
static char *
ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
    ngx_uint_t                   i, p, last, bind_wildcard;
    ngx_listening_t             *ls;
    ngx_stream_port_t           *stport;
    ngx_stream_conf_port_t      *port;
    ngx_stream_conf_addr_t      *addr;
    ngx_stream_core_srv_conf_t  *cscf;

    // 遍历已经整理好的监听端口数组
    // 由ngx_stream_add_ports添加
    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        // 根据wildcard、bind对port排序
        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_stream_conf_addr_t), ngx_stream_cmp_conf_addrs);

        // addrs.elts里存储的是监听端口结构体ngx_stream_listen_t
        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].opt.wildcard) {
            addr[last - 1].opt.bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].opt.bind) {
                i++;
                continue;
            }

            // 添加到cycle的监听端口数组，只是添加，没有其他动作
            ls = ngx_create_listening(cf, &addr[i].opt.u.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            // 设置监听端口的其他参数
            ls->addr_ntop = 1;

            // 重要！
            // 设置有连接发生时的回调函数
            ls->handler = ngx_stream_init_connection;
            ls->pool_size = 256;

            cscf = addr->opt.ctx->srv_conf[ngx_stream_core_module.ctx_index];

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            // 端口的backlog
            ls->backlog = addr[i].opt.backlog;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

#if (NGX_HAVE_REUSEPORT)
            // 新的reuseport设置
            ls->reuseport = addr[i].opt.reuseport;
#endif

            stport = ngx_palloc(cf->pool, sizeof(ngx_stream_port_t));
            if (stport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = stport;

            stport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (ngx_stream_add_addrs6(cf, stport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (ngx_stream_add_addrs(cf, stport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            // reuseport专用的函数，1.8.x没有
            if (ngx_clone_listening(cf, ls) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr)
{
    u_char                *p;
    size_t                 len;
    ngx_uint_t             i;
    struct sockaddr_in    *sin;
    ngx_stream_in_addr_t  *addrs;
    u_char                 buf[NGX_SOCKADDR_STRLEN];

    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_stream_in_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin = &addr[i].opt.u.sockaddr_in;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].opt.ctx;
#if (NGX_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif

        len = ngx_sock_ntop(&addr[i].opt.u.sockaddr, addr[i].opt.socklen, buf,
                            NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_stream_add_addrs6(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr)
{
    u_char                 *p;
    size_t                  len;
    ngx_uint_t              i;
    struct sockaddr_in6    *sin6;
    ngx_stream_in6_addr_t  *addrs6;
    u_char                  buf[NGX_SOCKADDR_STRLEN];

    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_stream_in6_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin6 = &addr[i].opt.u.sockaddr_in6;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;
#if (NGX_STREAM_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif

        len = ngx_sock_ntop(&addr[i].opt.u.sockaddr, addr[i].opt.socklen, buf,
                            NGX_SOCKADDR_STRLEN, 1);

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}

#endif


// 根据wildcard、bind对port排序
static ngx_int_t
ngx_stream_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_stream_conf_addr_t  *first, *second;

    first = (ngx_stream_conf_addr_t *) one;
    second = (ngx_stream_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
