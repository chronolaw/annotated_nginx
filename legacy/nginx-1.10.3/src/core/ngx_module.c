// annotated by chrono since 2016
//
// * ngx_preinit_modules
// * ngx_init_modules
// * ngx_count_modules
// * ngx_add_module

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


// 动态模块最多加载128个
#define NGX_MAX_DYNAMIC_MODULES  128


// 从头开始查找所有模块
// 最后找到了一个未使用的序号
// 通常是数组里的最后一个位置
static ngx_uint_t ngx_module_index(ngx_cycle_t *cycle);

// 从头开始查找特定类型的模块
// 如果这个序号被已有的模块使用
// 那么序号加1，再重新查找
// 例如，一开始所有模块的序号都是-1，那么返回0，之后就是1、2、3
// 对于静态模块很简单，返回值就是index
static ngx_uint_t ngx_module_ctx_index(ngx_cycle_t *cycle, ngx_uint_t type,
    ngx_uint_t index);


// 在ngx_preinit_modules里统计得到静态模块的总数
// 之后加上128，是模块数量的上限
ngx_uint_t         ngx_max_module;

// 模块计数器，模块数组的最后一个可用序号
static ngx_uint_t  ngx_modules_n;


// main()里调用
// 计算所有的静态模块数量
// ngx_modules是nginx模块数组，存储所有的模块指针，由make生成在objs/ngx_modules.c
// 这里赋值每个模块的index成员
// ngx_modules_n保存了最后一个可用的序号
// ngx_max_module是模块数量的上限
ngx_int_t
ngx_preinit_modules(void)
{
    ngx_uint_t  i;

    // 从0开始，为所有静态模块设置序号和名字
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = i;
        ngx_modules[i]->name = ngx_module_names[i];
    }

    // ngx_modules_n保存了最后一个可用的序号
    ngx_modules_n = i;

    // ngx_max_module是模块数量的上限
    ngx_max_module = ngx_modules_n + NGX_MAX_DYNAMIC_MODULES;

    return NGX_OK;
}


// main -> ngx_init_cycle里调用
// 内存池创建一个数组，可以容纳所有的模块，大小是ngx_max_module + 1
// 拷贝脚本生成的静态模块数组到本cycle
// 拷贝模块序号计数器到本cycle
// 完成cycle的模块初始化
ngx_int_t
ngx_cycle_modules(ngx_cycle_t *cycle)
{
    /*
     * create a list of modules to be used for this cycle,
     * copy static modules to it
     */

    // 内存池创建一个数组，可以容纳所有的模块，大小是ngx_max_module + 1
    // 注意使用的是ngx_pcalloc，内容全是0，即以null表示数组结束
    cycle->modules = ngx_pcalloc(cycle->pool, (ngx_max_module + 1)
                                              * sizeof(ngx_module_t *));
    if (cycle->modules == NULL) {
        return NGX_ERROR;
    }

    // 拷贝make生成的静态模块数组到本cycle
    // 之后ngx_modules数组不再使用
    ngx_memcpy(cycle->modules, ngx_modules,
               ngx_modules_n * sizeof(ngx_module_t *));

    // 拷贝模块序号计数器到本cycle
    // 同样之后ngx_modules_n不再使用
    cycle->modules_n = ngx_modules_n;

    // 完成cycle的模块初始化
    return NGX_OK;
}


// main -> ngx_init_cycle里调用，仅调用一次
// 调用所有模块的init_module函数指针，初始化模块
// 不使用全局的ngx_modules数组，而是使用cycle里的
// 这时可能已经加载了一些动态模块
ngx_int_t
ngx_init_modules(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    // 注意不使用全局的ngx_modules数组，而是使用cycle里的
    for (i = 0; cycle->modules[i]; i++) {

        // 调用所有模块的init_module函数指针，初始化模块
        if (cycle->modules[i]->init_module) {
            if (cycle->modules[i]->init_module(cycle) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


// 在ngx_event.c等调用，在解析配置块时
// 这时应该已经加载了动态模块，在模块数组里与静态模块无区别
// 得到cycle里所有的事件/http/stream模块数量
// 设置某类型模块的ctx_index
// type是模块的类型，例如NGX_EVENT_MODULE
// 返回此类型模块的数量
ngx_int_t
ngx_count_modules(ngx_cycle_t *cycle, ngx_uint_t type)
{
    ngx_uint_t     i, next, max;
    ngx_module_t  *module;

    // 模块的序号，初始是0
    next = 0;
    max = 0;

    /* count appropriate modules, set up their indices */

    // 遍历cycle里的模块数组，只关注特定类型的模块
    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        // 不是特定类型的模块则跳过
        if (module->type != type) {
            continue;
        }

        // 模块已经设置了序号
        if (module->ctx_index != NGX_MODULE_UNSET_INDEX) {

            /* if ctx_index was assigned, preserve it */

            // 更新max
            if (module->ctx_index > max) {
                max = module->ctx_index;
            }

            // next也要更新
            if (module->ctx_index == next) {
                next++;
            }

            continue;
        }

        /* search for some free index */

        // 通常情况下模块都是没有序号的（即-1）

        // 调用ngx_module_ctx_index获取一个序号
        //
        // 从头开始查找特定类型的模块
        // 如果这个序号被已有的模块使用
        // 那么序号加1，再重新查找
        // 例如，一开始所有模块的序号都是-1，那么返回0，之后就是1、2、3
        // 对于静态模块很简单，返回值就是next
        module->ctx_index = ngx_module_ctx_index(cycle, type, next);

        // 更新max
        if (module->ctx_index > max) {
            max = module->ctx_index;
        }

        // 序号加1，准备给下一个模块
        next = module->ctx_index + 1;
    }

    /*
     * make sure the number returned is big enough for previous
     * cycle as well, else there will be problems if the number
     * will be stored in a global variable (as it's used to be)
     * and we'll have to roll back to the previous cycle
     */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->type != type) {
                continue;
            }

            if (module->ctx_index > max) {
                max = module->ctx_index;
            }
        }
    }

    /* prevent loading of additional modules */

    // 标志位，cycle已经完成模块的初始化，不能再添加模块
    cycle->modules_used = 1;

    // +1是为了最后一个元素放null表示数组结束
    return max + 1;
}


// cycle->modules_n是模块计数器 如果超过最大数量则报错
// 使用模块里的各种信息进行检查，只有正确的才能加载
// 首先是版本号，必须一致，例如1.10的不能给1.9使用
// 比较签名字符串，里面是二进制兼容信息
// 看cycle里的模块数组里是否有重名的 也就是说每个模块的名字都不能相同
// 模块还没有加载，那么就给一个全局序号，不是ctx_index
// 把动态模块的指针加入cycle的模块数组
// 最后完成了一个动态模块的加载，放到了cycle模块数组里的合适位置
//
// file参数仅打错误日志使用
ngx_int_t
ngx_add_module(ngx_conf_t *cf, ngx_str_t *file, ngx_module_t *module,
    char **order)
{
    void               *rv;
    ngx_uint_t          i, m, before;
    ngx_core_module_t  *core_module;

    // cycle->modules_n是模块计数器
    // 如果超过最大数量则报错
    if (cf->cycle->modules_n >= ngx_max_module) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "too many modules loaded");
        return NGX_ERROR;
    }

    // 使用模块里的各种信息进行检查，只有正确的才能加载

    // 首先是版本号，必须一致，例如1.10的不能给1.9使用
    if (module->version != nginx_version) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "module \"%V\" version %ui instead of %ui",
                           file, module->version, (ngx_uint_t) nginx_version);
        return NGX_ERROR;
    }

    // 比较签名字符串，里面是二进制兼容信息
    if (ngx_strcmp(module->signature, NGX_MODULE_SIGNATURE) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "module \"%V\" is not binary compatible",
                           file);
        return NGX_ERROR;
    }

    // 看cycle里的模块数组里是否有重名的
    // 也就是说每个模块的名字都不能相同
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (ngx_strcmp(cf->cycle->modules[m]->name, module->name) == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "module \"%s\" is already loaded",
                               module->name);
            return NGX_ERROR;
        }
    }

    /*
     * if the module wasn't previously loaded, assign an index
     */

    // 模块还没有加载，那么就给一个全局序号，不是ctx_index
    if (module->index == NGX_MODULE_UNSET_INDEX) {

        // 从头开始查找所有模块
        // 最后找到了一个未使用的序号
        // 通常是数组里的最后一个位置
        module->index = ngx_module_index(cf->cycle);

        // 如果超过最大数量则报错
        if (module->index >= ngx_max_module) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "too many modules loaded");
            return NGX_ERROR;
        }
    }

    /*
     * put the module into the cycle->modules array
     */

    // cycle->modules_n是模块计数器
    // 是数组里的第一个空位置
    before = cf->cycle->modules_n;

    // 模块顺序只对http filter模块有意义
    // 其他模块不会走这里
    if (order) {
        for (i = 0; order[i]; i++) {
            if (ngx_strcmp(order[i], module->name) == 0) {
                i++;
                break;
            }
        }

        for ( /* void */ ; order[i]; i++) {

#if 0
            ngx_log_debug2(NGX_LOG_DEBUG_CORE, cf->log, 0,
                           "module: %s before %s",
                           module->name, order[i]);
#endif

            for (m = 0; m < before; m++) {
                if (ngx_strcmp(cf->cycle->modules[m]->name, order[i]) == 0) {

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cf->log, 0,
                                   "module: %s before %s:%i",
                                   module->name, order[i], m);

                    before = m;
                    break;
                }
            }
        }
    }
    // order逻辑结束

    /* put the module before modules[before] */

    // 如果位置不对就要调用memmove移动数组元素
    if (before != cf->cycle->modules_n) {
        ngx_memmove(&cf->cycle->modules[before + 1],
                    &cf->cycle->modules[before],
                    (cf->cycle->modules_n - before) * sizeof(ngx_module_t *));
    }

    // 把动态模块的指针加入cycle的模块数组
    cf->cycle->modules[before] = module;

    // cycle->modules_n模块计数器加1
    cf->cycle->modules_n++;

    // 动态核心模块还有特殊的处理
    // 要创建它的配置结构体
    if (module->type == NGX_CORE_MODULE) {

        /*
         * we are smart enough to initialize core modules;
         * other modules are expected to be loaded before
         * initialization - e.g., http modules must be loaded
         * before http{} block
         */

        core_module = module->ctx;

        if (core_module->create_conf) {
            rv = core_module->create_conf(cf->cycle);
            if (rv == NULL) {
                return NGX_ERROR;
            }

            cf->cycle->conf_ctx[module->index] = rv;
        }
    }

    // 最后完成了一个动态模块的加载，放到了cycle模块数组里的合适位置

    return NGX_OK;
}


// 从头开始查找所有模块
// 最后找到了一个未使用的序号
// 通常是数组里的最后一个位置
static ngx_uint_t
ngx_module_index(ngx_cycle_t *cycle)
{
    ngx_uint_t     i, index;
    ngx_module_t  *module;

    // 从0开始查找序号
    index = 0;

again:

    /* find an unused index */

    // 从头开始查找模块
    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        // 如果序号被使用那么加1
        if (module->index == index) {
            index++;
            goto again;
        }
    }

    // 最后找到了一个未使用的序号
    // 通常是数组里的最后一个位置

    /* check previous cycle */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->index == index) {
                index++;
                goto again;
            }
        }
    }

    return index;
}


// 从头开始查找特定类型的模块
// 如果这个序号被已有的模块使用
// 那么序号加1，再重新查找
// 例如，一开始所有模块的序号都是-1，那么返回0，之后就是1、2、3
// 对于静态模块很简单，返回值就是index
static ngx_uint_t
ngx_module_ctx_index(ngx_cycle_t *cycle, ngx_uint_t type, ngx_uint_t index)
{
    ngx_uint_t     i;
    ngx_module_t  *module;

again:

    /* find an unused ctx_index */

    // 从头开始查找特定类型的模块
    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        // 不是特定类型的模块则跳过
        if (module->type != type) {
            continue;
        }

        // 如果这个序号被已有的模块使用
        // 那么序号加1，再重新查找
        if (module->ctx_index == index) {
            index++;
            goto again;
        }
    }

    // 所有模块都遍历完毕，没有模块使用index序号

    /* check previous cycle */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->type != type) {
                continue;
            }

            if (module->ctx_index == index) {
                index++;
                goto again;
            }
        }
    }

    // 返回index
    return index;
}
