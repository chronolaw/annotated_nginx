// annotated by chrono since 2016
//
// * ngx_stream_core_listen
// * ngx_stream_core_run_phases
// * ngx_stream_core_generic_phase
// * ngx_stream_core_preread_phase

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>


// 目前仅初始化了一些stream框架内置变量
static ngx_int_t ngx_stream_core_preconfiguration(ngx_conf_t *cf);

// 主要初始化配置结构体里的servers、listen数组
static void *ngx_stream_core_create_main_conf(ngx_conf_t *cf);

static char *ngx_stream_core_init_main_conf(ngx_conf_t *cf, void *conf);

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
// 检查其他参数，如bind/backlog等
// 1.13.0加入sndbuf/rcvbuf
static char *ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static char *ngx_stream_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


// stream_core模块的指令，主要是server、listen
// 与http_core类似
static ngx_command_t  ngx_stream_core_commands[] = {

    { ngx_string("variables_hash_max_size"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_core_main_conf_t, variables_hash_max_size),
      NULL },

    { ngx_string("variables_hash_bucket_size"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_core_main_conf_t, variables_hash_bucket_size),
      NULL },

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
      // 检查其他参数，如bind/backlog等
      // 1.13.0加入sndbuf/rcvbuf
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

    { ngx_string("resolver"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_core_resolver,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("resolver_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, resolver_timeout),
      NULL },

    { ngx_string("proxy_protocol_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, proxy_protocol_timeout),
      NULL },

    // 可以在stream_main里出现，用于合并配置
    // 默认开启(=1)
    { ngx_string("tcp_nodelay"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

    { ngx_string("preread_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, preread_buffer_size),
      NULL },

    { ngx_string("preread_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_core_srv_conf_t, preread_timeout),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_core_module_ctx = {
    // 目前仅初始化了一些stream框架内置变量
    ngx_stream_core_preconfiguration,      /* preconfiguration */

    NULL,                                  /* postconfiguration */

    // 主要初始化配置结构体里的servers、listen数组
    ngx_stream_core_create_main_conf,      /* create main configuration */
    ngx_stream_core_init_main_conf,        /* init main configuration */

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


// ngx_stream_session_handler调用
// 读事件触发，执行处理引擎
// 启动引擎数组处理请求
// 从phase_handler的位置开始调用模块处理
void
ngx_stream_core_run_phases(ngx_stream_session_t *s)
{
    ngx_int_t                     rc;
    ngx_stream_phase_handler_t   *ph;
    ngx_stream_core_main_conf_t  *cmcf;

    // 得到core main配置
    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    // 获取引擎里的handler数组
    ph = cmcf->phase_engine.handlers;

    // 从phase_handler的位置开始调用模块处理
    // 外部请求的引擎数组起始序号是0，从头执行引擎数组,即先从Post accept开始
    while (ph[s->phase_handler].checker) {

        // 调用引擎数组里的checker
        // ngx_stream_core_generic_phase:
        //      post_accept/preaccess/access/ssl
        // ngx_stream_core_preread_phase:
        //      preread
        // ngx_stream_core_content_phase:
        //      content
        rc = ph[s->phase_handler].checker(s, &ph[s->phase_handler]);

        // checker会检查handler的返回值
        // 如果handler返回again/done那么就返回ok
        // 退出引擎数组的处理
        // 等待下一次读/写事件触发
        //
        // 如果checker返回again，那么继续在引擎数组里执行
        // 模块由s->phase_handler指定，可能会有阶段的跳跃
        if (rc == NGX_OK) {
            return;
        }
    }
}


// 处理post_accept/preaccess/access/ssl等阶段
ngx_int_t
ngx_stream_core_generic_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph)
{
    ngx_int_t  rc;

    /*
     * generic phase checker,
     * used by all phases, except for preread and content
     */

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "generic phase: %ui", s->phase_handler);

    // 执行模块的handler函数
    rc = ph->handler(s);

    // 检查处理结果

    // 如果OK，那么跳过本阶段其他模块
    // 进入下一个阶段继续处理
    // 返回again，引擎继续运行
    if (rc == NGX_OK) {
        s->phase_handler = ph->next;
        return NGX_AGAIN;
    }

    // 返回declined，模块未能处理
    // 本阶段下一个模块继续处理，也可能进入下一个阶段
    // 返回again，引擎继续运行
    if (rc == NGX_DECLINED) {
        s->phase_handler++;
        return NGX_AGAIN;
    }

    // again/done，模块暂时无法继续处理
    // 返回ok，退出引擎，下次有事件触发时继续运行
    if (rc == NGX_AGAIN || rc == NGX_DONE) {
        return NGX_OK;
    }

    // 出错，设置为500错误
    if (rc == NGX_ERROR) {
        rc = NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    // 结束回话
    // 关闭stream连接，销毁内存池
    ngx_stream_finalize_session(s, rc);

    // ok也会退出引擎，但不会再有事件触发了
    return NGX_OK;
}


// 处理preread阶段，帮模块读一些数据
ngx_int_t
ngx_stream_core_preread_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph)
{
    size_t                       size;
    ssize_t                      n;
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_stream_core_srv_conf_t  *cscf;

    // 取连接对象
    c = s->connection;

    c->log->action = "prereading client data";

    // 取配置
    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    // 超时就不再读了
    if (c->read->timedout) {
        rc = NGX_STREAM_OK;

    // 有定时器，需要读
    } else if (c->read->timer_set) {
        rc = NGX_AGAIN;

    } else {
        // 执行preread模块的处理函数
        // 如果是第一次进入就会返回again
        rc = ph->handler(s);
    }

    // 反复预读取数据，直至无数据或出错
    while (rc == NGX_AGAIN) {

        // 分配供客户端读取的内存
        if (c->buffer == NULL) {
            c->buffer = ngx_create_temp_buf(c->pool, cscf->preread_buffer_size);
            if (c->buffer == NULL) {
                rc = NGX_ERROR;
                break;
            }
        }

        // 缓冲区大小
        size = c->buffer->end - c->buffer->last;

        // 满则不能再读
        // 退出循环，不再读取数据
        if (size == 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "preread buffer full");
            rc = NGX_STREAM_BAD_REQUEST;
            break;
        }

        // 客户端关闭连接
        // 退出循环，不再读取数据
        if (c->read->eof) {
            rc = NGX_STREAM_OK;
            break;
        }

        // 不可读，需要加入事件监控
        // 退出循环，不再读取数据
        if (!c->read->ready) {
            break;
        }

        // 读取数据
        n = c->recv(c, c->buffer->last, size);

        if (n == NGX_ERROR || n == 0) {
            rc = NGX_STREAM_OK;
            break;
        }

        // again，已无数据可读
        // 退出循环，不再读取数据
        // 不再返回循环开头判断
        if (n == NGX_AGAIN) {
            break;
        }

        // 读取了n字节
        // 小于0也可能是成功的，因为udp已经存进了buffer
        c->buffer->last += n;

        // 执行preread模块的处理函数
        // 处理读取的部分数据
        rc = ph->handler(s);
    }

    // 无数据（again）、ok、出错
    // 结束循环

    // again暂时不可读，需要加入事件监控
    if (rc == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return NGX_OK;
        }

        if (!c->read->timer_set) {
            ngx_add_timer(c->read, cscf->preread_timeout);
        }

        // 下次读事件发生（有数据）再继续执行此阶段
        c->read->handler = ngx_stream_session_handler;

        return NGX_OK;
    }

    // 到这里，preread模块应该是处理完了

    // 不再需要检查超时
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    // 如果OK，那么跳过本阶段其他模块
    // 进入下一个阶段继续处理
    // 返回again，引擎继续运行
    if (rc == NGX_OK) {
        s->phase_handler = ph->next;
        return NGX_AGAIN;
    }

    // 返回declined，模块未能处理
    // 本阶段下一个模块继续处理，也可能进入下一个阶段
    // 返回again，引擎继续运行
    if (rc == NGX_DECLINED) {
        s->phase_handler++;
        return NGX_AGAIN;
    }

    // done，模块暂时无法继续处理
    // 返回ok，退出引擎，下次有事件触发时继续运行
    if (rc == NGX_DONE) {
        return NGX_OK;
    }

    // 最后是出错
    if (rc == NGX_ERROR) {
        rc = NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    // 结束回话
    // 关闭stream连接，销毁内存池
    ngx_stream_finalize_session(s, rc);

    return NGX_OK;
}


// 比较简单，运行content handler
ngx_int_t
ngx_stream_core_content_phase(ngx_stream_session_t *s,
    ngx_stream_phase_handler_t *ph)
{
    ngx_connection_t            *c;
    ngx_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = NULL;

    // 取server配置
    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    // tcp协议则设置nodelay
    if (c->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && ngx_tcp_nodelay(c) != NGX_OK)
    {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    // 执行content handler
    cscf->handler(s);

    // 返回OK，引擎结束
    // 但可能在handler里设置了读写事件，还会再次进入此函数继续处理
    return NGX_OK;
}


// 目前仅初始化了一些stream框架内置变量
static ngx_int_t
ngx_stream_core_preconfiguration(ngx_conf_t *cf)
{
    return ngx_stream_variables_add_core_vars(cf);
}


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

    cmcf->variables_hash_max_size = NGX_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = NGX_CONF_UNSET_UINT;

    return cmcf;
}


static char *
ngx_stream_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_stream_core_main_conf_t *cmcf = conf;

    ngx_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    ngx_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               ngx_align(cmcf->variables_hash_bucket_size, ngx_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return NGX_CONF_OK;
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
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->proxy_protocol_timeout = NGX_CONF_UNSET_MSEC;
    cscf->tcp_nodelay = NGX_CONF_UNSET;
    cscf->preread_buffer_size = NGX_CONF_UNSET_SIZE;
    cscf->preread_timeout = NGX_CONF_UNSET_MSEC;

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

    ngx_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in stream {} context
             * to inherit it in all servers
             */

            prev->resolver = ngx_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

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

    ngx_conf_merge_msec_value(conf->proxy_protocol_timeout,
                              prev->proxy_protocol_timeout, 30000);

    // 默认tcp_nodelay=1
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    ngx_conf_merge_size_value(conf->preread_buffer_size,
                              prev->preread_buffer_size, 16384);

    ngx_conf_merge_msec_value(conf->preread_timeout,
                              prev->preread_timeout, 30000);

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
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        // module是流模块的函数表，用于解析配置时调用
        module = cf->cycle->modules[m]->ctx;

        // 创建每个模块的srv_conf
        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
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

    if (rv == NGX_CONF_OK && !cscf->listen) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return NGX_CONF_ERROR;
    }

    return rv;
}


// 解析stream/server{}里的listen指令，监听tcp端口
// 遍历已经添加的端口，如果重复则报错
// 向cmcf->listen数组里添加一个ngx_stream_listen_t结构体
// 检查其他参数，如bind/backlog等
// 1.13.0加入sndbuf/rcvbuf
static char *
ngx_stream_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf = conf;

    ngx_str_t                    *value, size;
    ngx_url_t                     u;
    ngx_uint_t                    i, n, backlog;
    ngx_stream_listen_t          *ls, *als;
    ngx_stream_core_main_conf_t  *cmcf;

    // 标志位，此server{}已经定义了监听端口
    cscf->listen = 1;

    // 获取指令后的参数数组
    value = cf->args->elts;

    // 准备解析url
    ngx_memzero(&u, sizeof(ngx_url_t));

    // 设置url为第一个参数，也就是端口
    u.url = value[1];

    // 设置为监听url
    u.listen = 1;

    // 解析url，得到地址等信息
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

    // before 1.15.10
    //ls = ngx_array_push(&cmcf->listen);
    // 向数组里添加一个ngx_stream_listen_t结构体
    // 注意是在cmcf里
    ls = ngx_array_push_n(&cmcf->listen, u.naddrs);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_stream_listen_t));

    // 拷贝ip地址
    //ngx_memcpy(&ls->sockaddr.sockaddr, &u.sockaddr, u.socklen);

    // 从ngx_url_t里拷贝信息
    //ls->socklen = u.socklen;

    ls->backlog = NGX_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->type = SOCK_STREAM;

    //ls->wildcard = u.wildcard;

    // 注意这里,存储了cf->ctx，也就是此server的配置数组ngx_stream_conf_ctx_t
    // 也就是监听端口关联了定义listen的server{}
    ls->ctx = cf->ctx;

#if (NGX_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    backlog = 0;

    // 检查其他参数，如bind/backlog/sndbuf/rcvbuf
    for (i = 2; i < cf->args->nelts; i++) {

        // 是否是udp协议，如果是udp那么type就是DGRAM，否则是STREAM
        // win32不支持udp协议
#if !(NGX_WIN32)
        if (ngx_strcmp(value[i].data, "udp") == 0) {
            ls->type = SOCK_DGRAM;
            continue;
        }
#endif

        // 是否bind地址
        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        // tcp协议支持backlog选项
        if (ngx_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = ngx_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == NGX_ERROR || ls->backlog == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            backlog = 1;

            continue;
        }

        if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->rcvbuf = ngx_parse_size(&size);
            ls->bind = 1;

            if (ls->rcvbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->sndbuf = ngx_parse_size(&size);
            ls->bind = 1;

            if (ls->sndbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
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
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        // reuseport选项，可以不用accept_mutex负载均衡
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
            ngx_stream_ssl_conf_t  *sslcf;

            sslcf = ngx_stream_conf_get_module_srv_conf(cf,
                                                        ngx_stream_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_stream_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        // tcp的keepalive
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

        if (ngx_strcmp(value[i].data, "proxy_protocol") == 0) {
            ls->proxy_protocol = 1;
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }
    // for循环检查参数结束

    // udp协议做检查，有的选项不可用: backlog/ssl/so_keepalive
    if (ls->type == SOCK_DGRAM) {
        if (backlog) {
            return "\"backlog\" parameter is incompatible with \"udp\"";
        }

#if (NGX_STREAM_SSL)
        if (ls->ssl) {
            return "\"ssl\" parameter is incompatible with \"udp\"";
        }
#endif

        if (ls->so_keepalive) {
            return "\"so_keepalive\" parameter is incompatible with \"udp\"";
        }

        if (ls->proxy_protocol) {
            return "\"proxy_protocol\" parameter is incompatible with \"udp\"";
        }
    }

    als = cmcf->listen.elts;

    for (n = 0; n < u.naddrs; n++) {
        ls[n] = ls[0];

        ls[n].sockaddr = u.addrs[n].sockaddr;
        ls[n].socklen = u.addrs[n].socklen;
        ls[n].addr_text = u.addrs[n].name;
        ls[n].wildcard = ngx_inet_wildcard(ls[n].sockaddr);

        for (i = 0; i < cmcf->listen.nelts - u.naddrs + n; i++) {
            if (ls[n].type != als[i].type) {
                continue;
            }

            if (ngx_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
                                 ls[n].sockaddr, ls[n].socklen, 1)
                != NGX_OK)
            {
                continue;
            }

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"%V\" address and port pair",
                               &ls[n].addr_text);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t  *cscf = conf;

    ngx_str_t  *value;

    if (cscf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cscf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
