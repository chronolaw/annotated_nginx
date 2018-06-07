// annotated by chrono since 2018

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


// 使用内存池创建一个可容纳n个大小为size元素的数组，即分配了一块n*size大小的内存块
// size参数通常要使用sizeof(T)
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    // 内存池分配一个数组结构体
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }

    // 重新分配数组的内存空间，相当于resize
    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}


// “销毁”动态数组，不一定归还分配的内存
// 数组创建后如果又使用了内存池则不会回收内存
// 因为内存池不允许空洞
void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    // 数组使用的内存池
    p = a->pool;

    // 如果数组内存正好在池的last则回收
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    // 如果数组结构体正好在池的last则回收
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }

    // 数组创建后如果又使用了内存池则不会回收内存
    // d.last会移动
    // 因为内存池不允许空洞
}


// 向数组添加元素，用法比较特别，它们返回的是一个void*指针，用户必须把它转换为真正的元素类型再操作
// 不直接使用ngx_array_t.elts操作的原因是防止数组越界，函数内部会检查当前数组容量自动扩容
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;

    // 看数组是否已满
    if (a->nelts == a->nalloc) {

        /* the array is full */

        // 满则扩容，成本较高

        // 计算数组的当前大小
        size = a->size * a->nalloc;

        // 数组使用的内存池
        p = a->pool;

        // 数组在当前内存池里，且正好还可以分配1个元素
        // 条件比较特殊
        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            // 移动指针，直接扩容
            // 这时数组里的数据不会变
            p->d.last += a->size;

            // 容量加1
            a->nalloc++;

        } else {
            /* allocate a new array */

            // 通常不会那么正好，需要重新分配内存

            // 要一个两倍的空间，扩容
            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            // 拷贝原数据
            ngx_memcpy(new, a->elts, size);

            // 指向新的地址
            a->elts = new;

            // 容量加倍
            a->nalloc *= 2;
        }
    }

    // 新增加元素的地址
    elt = (u_char *) a->elts + a->size * a->nelts;

    // 元素数量加1
    a->nelts++;

    return elt;
}


void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
