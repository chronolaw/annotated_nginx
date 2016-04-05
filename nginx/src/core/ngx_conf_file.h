// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONF_FILE_H_INCLUDED_
#define _NGX_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

// nginx指令可以接受的参数数量
#define NGX_CONF_NOARGS      0x00000001
#define NGX_CONF_TAKE1       0x00000002
#define NGX_CONF_TAKE2       0x00000004
#define NGX_CONF_TAKE3       0x00000008
#define NGX_CONF_TAKE4       0x00000010
#define NGX_CONF_TAKE5       0x00000020
#define NGX_CONF_TAKE6       0x00000040
#define NGX_CONF_TAKE7       0x00000080

// 最多只能接受8个参数
#define NGX_CONF_MAX_ARGS    8

// 组合之前的参数，可以简化代码
#define NGX_CONF_TAKE12      (NGX_CONF_TAKE1|NGX_CONF_TAKE2)
#define NGX_CONF_TAKE13      (NGX_CONF_TAKE1|NGX_CONF_TAKE3)

#define NGX_CONF_TAKE23      (NGX_CONF_TAKE2|NGX_CONF_TAKE3)

#define NGX_CONF_TAKE123     (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3)
#define NGX_CONF_TAKE1234    (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3   \
                              |NGX_CONF_TAKE4)

// 特殊的指令属性
#define NGX_CONF_ARGS_NUMBER 0x000000ff
#define NGX_CONF_BLOCK       0x00000100     //指令是配置块，即{...}
#define NGX_CONF_FLAG        0x00000200     //指令接受on/off，转化为ngx_flag_t
#define NGX_CONF_ANY         0x00000400
#define NGX_CONF_1MORE       0x00000800
#define NGX_CONF_2MORE       0x00001000
#define NGX_CONF_MULTI       0x00000000  /* compatibility */

#define NGX_DIRECT_CONF      0x00010000

#define NGX_MAIN_CONF        0x01000000     //指令出现在配置文件的最外层
#define NGX_ANY_CONF         0x0F000000     //指令可以在任意位置出现



// nginx自己的nil/none，表示无效值，在C语言里需要做强制类型转换，C++可以用模板
#define NGX_CONF_UNSET       -1
#define NGX_CONF_UNSET_UINT  (ngx_uint_t) -1
#define NGX_CONF_UNSET_PTR   (void *) -1
#define NGX_CONF_UNSET_SIZE  (size_t) -1
#define NGX_CONF_UNSET_MSEC  (ngx_msec_t) -1


// 配置解析的成功和失败，实际的类型是char*，在C++里要用reinterpret_cast
#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1

// 配置解析时的标志量，表示解析的状态
#define NGX_CONF_BLOCK_START 1
#define NGX_CONF_BLOCK_DONE  2
#define NGX_CONF_FILE_DONE   3

// 最基本的两个模块的标志，core模块和conf模块
#define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */


#define NGX_MAX_CONF_ERRSTR  1024


// 指令结构体，用于定义nginx指令
// ngx_command_t (ngx_core.h)
struct ngx_command_s {
    //指令的名字
    ngx_str_t             name;

    //指令的类型，是NGX_CONF_XXX的组合，决定指令出现的位置、参数数量、类型等
    ngx_uint_t            type;

    // 指令解析函数，是函数指针
    // 预设有ngx_conf_set_flag_slot等，见本文件
    // cf：解析的环境结构体,重要的是cf->args，是指令字符串数组
    // cmd：该指令的结构体
    // conf当前的配置结构体
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

    //专门给http模块使用，决定存储在main/srv/loc的哪个层次
    // NGX_HTTP_MAIN_CONF/NGX_HTTP_SRV_CONF/NGX_HTTP_LOC_CONF
    ngx_uint_t            conf;
    ngx_uint_t            offset;   //变量在conf结构体里的偏移量，可用offsetof得到
    void                 *post;     //解析后处理的数据
};

// 空指令，用于在指令数组的最后当做哨兵，结束数组，避免指定长度，类似NULL的作用
#define ngx_null_command  { ngx_null_string, 0, NULL, 0, 0, NULL }


struct ngx_open_file_s {
    ngx_fd_t              fd;
    ngx_str_t             name;

    void                (*flush)(ngx_open_file_t *file, ngx_log_t *log);
    void                 *data;
};


// 填充宏，填充ngx_module_t的前7个字段，即ctx_index...version
#define NGX_MODULE_V1          0, 0, 0, 0, 0, 0, 1

// 填充宏，填充ngx_module_t的最后8个字段，设置为空指针
#define NGX_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0

// 重要的数据结构，定义nginx模块
// 重要的模块ngx_core_module/ngx_event_module/ngx_http_module
// 1.9.11后有变化，改到了ngx_module.h，可以定义动态模块，使用了spare0等字段
struct ngx_module_s {
    // 下面的几个成员通常使用宏NGX_MODULE_V1填充

    // 每类(http/event)模块各自的index
    ngx_uint_t            ctx_index;

    // 在ngx_modules数组里的唯一索引，main()里赋值
    // 使用计数器变量ngx_max_module
    ngx_uint_t            index;

    ngx_uint_t            spare0;
    ngx_uint_t            spare1;
    ngx_uint_t            spare2;
    ngx_uint_t            spare3;

    ngx_uint_t            version;

    // 模块不同含义不同,通常是函数指针表
    // core模块的ctx
    //typedef struct {
    //    ngx_str_t             name;
    //    void               *(*create_conf)(ngx_cycle_t *cycle);
    //    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
    //} ngx_core_module_t;
    void                 *ctx;

    // 模块支持的指令，数组形式，最后用空对象表示结束
    ngx_command_t        *commands;

    // 模块的类型标识，相当于RTTI,如CORE/HTTP/MAIL等
    ngx_uint_t            type;

    // 以下7个函数会在进程的启动或结束阶段被调用

    // init_master目前nginx不会调用
    ngx_int_t           (*init_master)(ngx_log_t *log);

    // 在ngx_init_cycle里被调用
    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    // 在ngx_single_process_cycle/ngx_worker_process_init里调用
    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);

    // init_thread目前nginx不会调用
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);

    // exit_thread目前nginx不会调用
    void                (*exit_thread)(ngx_cycle_t *cycle);

    // 在ngx_worker_process_exit调用
    void                (*exit_process)(ngx_cycle_t *cycle);

    // exit_master目前nginx不会调用
    void                (*exit_master)(ngx_cycle_t *cycle);

    // 下面7个成员通常用用NGX_MODULE_V1_PADDING填充
    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};


// 核心模块的ctx结构，比较简单，只有创建和初始化配置结构函数
// create_conf函数返回的是void*指针
typedef struct {
    ngx_str_t             name;
    void               *(*create_conf)(ngx_cycle_t *cycle);
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_core_module_t;


typedef struct {
    ngx_file_t            file;
    ngx_buf_t            *buffer;
    ngx_uint_t            line;
} ngx_conf_file_t;


typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
    ngx_command_t *dummy, void *conf);


// 配置解析的环境结构体
struct ngx_conf_s {
    char                 *name;
    ngx_array_t          *args;         //保存解析到的指令字符串,0是指令名，其他的是参数

    ngx_cycle_t          *cycle;
    ngx_pool_t           *pool;
    ngx_pool_t           *temp_pool;
    ngx_conf_file_t      *conf_file;
    ngx_log_t            *log;

    void                 *ctx;          //重要参数，解析时的上下文
    ngx_uint_t            module_type;
    ngx_uint_t            cmd_type;

    ngx_conf_handler_pt   handler;
    char                 *handler_conf;
};


typedef char *(*ngx_conf_post_handler_pt) (ngx_conf_t *cf,
    void *data, void *conf);

typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_conf_post_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} ngx_conf_deprecated_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_int_t                 low;
    ngx_int_t                 high;
} ngx_conf_num_bounds_t;


typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                value;
} ngx_conf_enum_t;


#define NGX_CONF_BITMASK_SET  1

typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                mask;
} ngx_conf_bitmask_t;



char * ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data);
char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data);


#define ngx_get_conf(conf_ctx, module)  conf_ctx[module.index]



// 简单的初始化函数宏，针对各种类型操作
#define ngx_conf_init_value(conf, default)                                   \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_init_ptr_value(conf, default)                               \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define ngx_conf_init_uint_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_size_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_msec_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

// 合并函数宏，同样根据类型选择
#define ngx_conf_merge_value(conf, prev, default)                            \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = (prev == NGX_CONF_UNSET_PTR) ? default : prev;                \
    }

#define ngx_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = (prev == NGX_CONF_UNSET_UINT) ? default : prev;               \
    }

#define ngx_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = (prev == NGX_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define ngx_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_size_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = (prev == NGX_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define ngx_conf_merge_off_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

// 字符串的合并比较特殊，要检查空指针
#define ngx_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define ngx_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define ngx_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *ngx_conf_param(ngx_conf_t *cf);
char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);
char *ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_int_t ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name,
    ngx_uint_t conf_prefix);
ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name);
void ngx_cdecl ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf,
    ngx_err_t err, const char *fmt, ...);


// 预设的解析指令函数，可以解析bool/字符串/数字/秒等
char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


// 声明nginx模块计数器变量，静态模块，nginx.c
extern ngx_uint_t     ngx_max_module;

// nginx模块数组，存储所有的模块指针，由make生成在objs/ngx_modules.c
extern ngx_module_t  *ngx_modules[];


#endif /* _NGX_CONF_FILE_H_INCLUDED_ */
