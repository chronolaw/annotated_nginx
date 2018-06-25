// annotated by chrono since 2016
//
// sudo apt-get install google-perftools
// ./configure --with-google_perftools_module
// google_perftools_profiles /tmp/ngx.perf;
// pprof --pdf /usr/local/nginx/sbin/nginx ./ngx.perf.17449 > a.pdf

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
 * declare Profiler interface here because
 * <google/profiler.h> is C++ header file
 */

int ProfilerStart(u_char* fname);
void ProfilerStop(void);
void ProfilerRegisterThread(void);


static void *ngx_google_perftools_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_google_perftools_worker(ngx_cycle_t *cycle);


// 配置结构体，存储profile的文件名
typedef struct {
    ngx_str_t  profiles;
} ngx_google_perftools_conf_t;


// 在配置文件里配置
// 例如：google_perftools_profiles /tmp/ngx.perf;
static ngx_command_t  ngx_google_perftools_commands[] = {

    { ngx_string("google_perftools_profiles"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_google_perftools_conf_t, profiles),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_google_perftools_module_ctx = {
    ngx_string("google_perftools"),
    ngx_google_perftools_create_conf,
    NULL
};


ngx_module_t  ngx_google_perftools_module = {
    NGX_MODULE_V1,
    &ngx_google_perftools_module_ctx,      /* module context */
    ngx_google_perftools_commands,         /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_google_perftools_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_google_perftools_create_conf(ngx_cycle_t *cycle)
{
    ngx_google_perftools_conf_t  *gptcf;

    gptcf = ngx_pcalloc(cycle->pool, sizeof(ngx_google_perftools_conf_t));
    if (gptcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc()
     *
     *     gptcf->profiles = { 0, NULL };
     */

    return gptcf;
}


// worker进程启动时开始profiler
static ngx_int_t
ngx_google_perftools_worker(ngx_cycle_t *cycle)
{
    u_char                       *profile;
    ngx_google_perftools_conf_t  *gptcf;

    // 取配置
    gptcf = (ngx_google_perftools_conf_t *)
                ngx_get_conf(cycle->conf_ctx, ngx_google_perftools_module);

    // 没有文件名则不会profiler
    if (gptcf->profiles.len == 0) {
        return NGX_OK;
    }

    // 真正的文件名需要加上进程号
    // 分配一个临时的内存
    profile = ngx_alloc(gptcf->profiles.len + NGX_INT_T_LEN + 2, cycle->log);
    if (profile == NULL) {
        return NGX_OK;
    }

    // 避免外部的环境变量干扰
    if (getenv("CPUPROFILE")) {
        /* disable inherited Profiler enabled in master process */
        ProfilerStop();
    }

    // 实际产生的文件名，加进程号
    ngx_sprintf(profile, "%V.%d%Z", &gptcf->profiles, ngx_pid);

    // 启动profiler
    if (ProfilerStart(profile)) {
        /* start ITIMER_PROF timer */
        // 多线程支持
        ProfilerRegisterThread();

    } else {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
                      "ProfilerStart(%s) failed", profile);
    }

    // 文件名不再需要，释放
    ngx_free(profile);

    return NGX_OK;
}


/* ProfilerStop() is called on Profiler destruction */
