// annotated by chrono since 2016
//
// * ngx_stream_block
// * ngx_stream_init_phase_handlers
// * ngx_stream_optimize_servers

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

// 初始化stream的handler数组
// 注意只有6个，content handler只有一个，不需要数组
static ngx_int_t ngx_stream_init_phases(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);

// 在配置解析的过程中stream模块把handler添加进了数组
// 此函数整理数组，填入引擎数组
static ngx_int_t ngx_stream_init_phase_handlers(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf);

// 把监听结构体添加进ports数组
// 多个相同的监听端口用一个数组元素，在addrs.opt里保存
static ngx_int_t ngx_stream_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_stream_listen_t *listen);

// 对已经整理好的监听端口数组排序
// 调用ngx_create_listening添加到cycle的监听端口数组，只是添加，没有其他动作
// 设置有连接发生时的回调函数ngx_stream_init_connection
static char *ngx_stream_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);

// 处理ipv4的地址
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


// 1.11.5，过滤机制
ngx_stream_filter_pt  ngx_stream_top_filter;


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
    //
    // conf里存储的是ngx_stream_conf_ctx_t *
    // 注意指针的转型,可以理解为(ngx_stream_conf_ctx_t*)*
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
    // conf里存储的是ngx_stream_conf_ctx_t *
    // 注意指针的转型,可以理解为(ngx_stream_conf_ctx_t*)*
    *(ngx_stream_conf_ctx_t **) conf = ctx;

    /* count the number of the stream modules and set up their indices */

    // 得到所有的stream模块数量
    // 设置stream模块的ctx_index
    // 1.10不再遍历模块数组，不直接使用ngx_stream_max_module
    ngx_stream_max_module = ngx_count_modules(cf->cycle, NGX_STREAM_MODULE);


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
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是流模块的函数表，用于解析配置时调用
        module = cf->cycle->modules[m]->ctx;

        mi = cf->cycle->modules[m]->ctx_index;

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


    // 初始的解析环境已经准备好，下面开始解析stream{}配置

    // 暂存当前的解析上下文
    pcf = *cf;

    // 设置事件模块的新解析上下文
    // 之前的ctx是cycle->conf_ctx
    // 此时ctx是ngx_stream_conf_ctx_t指针，里面存储了配置数组
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the stream{} block */

    // 设定之后解析的模块类型必须是stream
    cf->module_type = NGX_STREAM_MODULE;

    // 指令的作用域是stream main
    cf->cmd_type = NGX_STREAM_MAIN_CONF;

    // 递归解析stream模块
    // 里面解析了server、listen等指令
    // 在cmcf->servers里添加了server的配置srv_conf
    // 在cmcf->listen里添加监听端口
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        // 恢复之前保存的解析上下文
        *cf = pcf;
        return rv;
    }

    // 此时stream{}配置已经全部解析完毕
    // 其中包含了server定义cmcf->servers、监听的端口信息cmcf->listen

    /* init stream{} main_conf's, merge the server{}s' srv_conf's */

    // 检查stream_core的main配置结构体
    cmcf = ctx->main_conf[ngx_stream_core_module.ctx_index];

    // 得到配置的server数量
    cscfp = cmcf->servers.elts;

    // 初始化main_conf，合并srv_conf
    // 注意cf->ctx会不断变化
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是流模块的函数表，用于解析配置时调用
        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init stream{} main_conf's */

        // 当前的ctx回到stream{}的数组
        // 这样下面的操作才能获得正确的配置结构体
        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        // 遍历每一个server{}配置块
        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            // 从server的ctx里得到server的配置数组，修改ctx
            // 这样才能获得server正确的配置
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

    // 初始化stream的handler数组
    // 注意只有6个，content handler只有一个，不需要数组
    if (ngx_stream_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // 配置解析完毕，调用模块的postconfiguration
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是stream模块的函数表，用于解析配置时调用
        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    if (ngx_stream_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // 最后恢复之前保存的解析上下文
    *cf = pcf;

    // 在配置解析的过程中stream模块把handler添加进了数组
    // 此函数整理数组，填入引擎数组
    if (ngx_stream_init_phase_handlers(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    // 初始化一个动态数组，准备存储监听端口
    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_stream_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    // 得到stream_core里的监听端口
    // ngx_stream_core_listen添加，可能多个server都监听相同的端口
    // 故listen数组里可能会有端口相同的元素
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


// 初始化stream的handler数组
// 注意只有6个，content handler只有一个，不需要数组
static ngx_int_t
ngx_stream_init_phases(ngx_conf_t *cf, ngx_stream_core_main_conf_t *cmcf)
{
    if (ngx_array_init(&cmcf->phases[NGX_STREAM_POST_ACCEPT_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_stream_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_STREAM_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_stream_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_STREAM_ACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_stream_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_stream_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_stream_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_array_init(&cmcf->phases[NGX_STREAM_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_stream_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


// 在配置解析的过程中stream模块把handler添加进了数组
// 此函数整理数组，填入引擎数组
static ngx_int_t
ngx_stream_init_phase_handlers(ngx_conf_t *cf,
    ngx_stream_core_main_conf_t *cmcf)
{
    ngx_int_t                     j;
    ngx_uint_t                    i, n;
    ngx_stream_handler_pt        *h;
    ngx_stream_phase_handler_t   *ph;
    ngx_stream_phase_handler_pt   checker;

    // n至少是1，因为每一个server必须有一个content handler
    n = 1 /* content phase */;

    // 计算所有handler的数量
    for (i = 0; i < NGX_STREAM_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    // 内存池创建数组
    ph = ngx_pcalloc(cf->pool,
                     n * sizeof(ngx_stream_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NGX_ERROR;
    }

    cmcf->phase_engine.handlers = ph;
    n = 0;

    // 遍历handler数组，填入引擎
    // 不同的阶段使用不同的checker
    for (i = 0; i < NGX_STREAM_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;

        switch (i) {

        // preread阶段使用ngx_stream_core_preread_phase
        case NGX_STREAM_PREREAD_PHASE:
            checker = ngx_stream_core_preread_phase;
            break;

        // content阶段使用ngx_stream_core_content_phase
        case NGX_STREAM_CONTENT_PHASE:
            ph->checker = ngx_stream_core_content_phase;

            // content只能有一个handler，所以直接加1，跳过后面的代码
            n++;
            ph++;

            continue;

        // 其他的post_accept/access等阶段都使用ngx_stream_core_generic_phase
        default:
            checker = ngx_stream_core_generic_phase;
        }

        // 计算此阶段的所有handler数量
        n += cmcf->phases[i].handlers.nelts;

        for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
            ph->checker = checker;
            ph->handler = h[j];
            ph->next = n;
            ph++;
        }
    }

    return NGX_OK;
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
    ngx_stream_conf_port_t  *port;
    ngx_stream_conf_addr_t  *addr;

    // 得到监听端口结构体里的socket地址
    // before 1.15.10
    //sa = &listen->sockaddr.sockaddr;

    sa = listen->sockaddr;

    // 得到监听端口结构体里的端口
    // 1.11.x后使用函数ngx_inet_get_port
    p = ngx_inet_get_port(sa);

    // 判断端口是否已经添加过了
    // 因为可能多个server都用listen监听同一个端口
    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {

        if (p == port[i].port
            && listen->type == port[i].type
            && sa->sa_family == port[i].family)
        {
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

    // 这里设置了type，标志tcp/udp
    port->type = listen->type;

    port->port = p;

    // 把stream listen结构体存储在addrs数组里供以后使用
    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_stream_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    // 监听端口相同也会走到这里
    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    // 把stream listen结构体存储在addrs数组里供以后使用
    // 注意使用的是opt字段，完全拷贝
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

        // port[p].addrs里存储的是监听相同端口的不同server{}的ngx_stream_listen_t
        // 根据wildcard、bind对server排序
        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_stream_conf_addr_t), ngx_stream_cmp_conf_addrs);

        // addrs.elts.opt里存储的是监听端口结构体ngx_stream_listen_t
        // addr 数组首地址， last 数组长度
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

            // before 1.15.10
            //ls = ngx_create_listening(cf, &addr[i].opt.sockaddr.sockaddr,

            // 添加到cycle的监听端口数组，只是添加，没有其他动作
            // 这里的ls是ngx_listening_t
            ls = ngx_create_listening(cf, addr[i].opt.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            // 设置监听端口的其他参数
            ls->addr_ntop = 1;

            // 重要！
            // 设置有连接发生时的回调函数
            ls->handler = ngx_stream_init_connection;

            // 设置连接的内存池是256bytes，不可配置
            ls->pool_size = 256;

            // addrs.elts.opt里存储的是监听端口结构体ngx_stream_listen_t
            ls->type = addr[i].opt.type;

            // addr[i].opt就是ngx_stream_listen_t
            // 在ngx_stream_add_ports里添加
            // addr->opt.ctx就是server的配置数组ngx_stream_conf_ctx_t

            // 这里没有使用addr[i].opt.ctx
            // 因为addr的前进与i++并不同步
            // 获取此server配置数组里的cscf
            cscf = addr->opt.ctx->srv_conf[ngx_stream_core_module.ctx_index];

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

            // 端口的backlog
            ls->backlog = addr[i].opt.backlog;
            ls->rcvbuf = addr[i].opt.rcvbuf;
            ls->sndbuf = addr[i].opt.sndbuf;

            ls->wildcard = addr[i].opt.wildcard;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_INET6)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

#if (NGX_HAVE_REUSEPORT)
            // 新的reuseport设置
            // 这时把http/stream指令设置的reuseport选项拷贝到了listening_t里
            ls->reuseport = addr[i].opt.reuseport;
#endif

            // 存储本server信息
            stport = ngx_palloc(cf->pool, sizeof(ngx_stream_port_t));
            if (stport == NULL) {
                return NGX_CONF_ERROR;
            }

            // 存储在ngx_listening_t.servers里
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

                // 处理ipv4的地址
                // 拷贝到stport，也就是存储在了ls里
                if (ngx_stream_add_addrs(cf, stport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            // reuseport专用的函数，1.8.x没有
            // 拷贝了worker数量个的监听结构体, in ngx_connection.c
            // removed since 1.15.2
            // if (ngx_clone_listening(cf, ls) != NGX_OK) {
            //     return NGX_CONF_ERROR;
            // }

            // 数组指针前进到下一个元素，即下一个server
            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


// 处理ipv4的地址
static ngx_int_t
ngx_stream_add_addrs(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr)
{
    ngx_uint_t             i;
    struct sockaddr_in    *sin;
    ngx_stream_in_addr_t  *addrs;

    // 分配内存，数量是stport->naddrs
    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_stream_in_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    // 指针赋值，数组的起始位置
    addrs = stport->addrs;

    // 为数组元素赋值
    for (i = 0; i < stport->naddrs; i++) {

        //sin = &addr[i].opt.sockaddr.sockaddr_in;

        // 从ngx_stream_listen_t里得到ip地址
        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;

        // 拷贝到数组里
        addrs[i].addr = sin->sin_addr.s_addr;

        // 监听端口所在的配置结构体数组
        // 即定义该端口的server{}
        addrs[i].conf.ctx = addr[i].opt.ctx;

#if (NGX_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        // before 1.15.10
        // socket地址转换为字符串
        // 参数1表示字符串里含有端口，即xxxx:port
        //len = ngx_sock_ntop(&addr[i].opt.sockaddr.sockaddr, addr[i].opt.socklen,
        //                    buf, NGX_SOCKADDR_STRLEN, 1);

        //// 分配内存，准备拷贝地址字符串
        //p = ngx_pnalloc(cf->pool, len);
        //if (p == NULL) {
        //    return NGX_ERROR;
        //}

        //// 拷贝地址字符串
        //ngx_memcpy(p, buf, len);

        //// 设置地址字符串
        //addrs[i].conf.addr_text.len = len;
        //addrs[i].conf.addr_text.data = p;

        addrs[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_stream_add_addrs6(ngx_conf_t *cf, ngx_stream_port_t *stport,
    ngx_stream_conf_addr_t *addr)
{
    ngx_uint_t              i;
    struct sockaddr_in6    *sin6;
    ngx_stream_in6_addr_t  *addrs6;

    stport->addrs = ngx_pcalloc(cf->pool,
                                stport->naddrs * sizeof(ngx_stream_in6_addr_t));
    if (stport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;
#if (NGX_STREAM_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs6[i].conf.addr_text = addr[i].opt.addr_text;
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
