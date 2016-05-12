// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 链表的节点
typedef struct ngx_list_part_s  ngx_list_part_t;

// 类似ngx_array_t，是一个简单的数组，也可以“泛型”存储数据
// next指针指向链表里的下一个节点
// 用于存储http头信息
struct ngx_list_part_s {
    void             *elts;     //数组元素指针
    ngx_uint_t        nelts;    //数组里的元素数量
    ngx_list_part_t  *next;     //下一个节点的指针
};


// 定义链表（实际上是头节点+元信息）
// 成员size、nalloc和pool与ngx_array_t含义是相同的，确定了节点里数组的元信息
typedef struct {
    ngx_list_part_t  *last;     //链表的尾节点
    ngx_list_part_t   part;     //链表的头节点
    size_t            size;     //链表存储元素的大小
    ngx_uint_t        nalloc;   //每个节点能够存储元素的数量
    ngx_pool_t       *pool;     //链表使用的内存池
} ngx_list_t;


// 使用内存池创建链表,每个节点可容纳n个大小为size的元素
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:         // 遍历链表的基本方法
 *
 *  part = &list.part;                      //获取链表的头节点
 *  data = part->elts;                      //获得节点内数组地址
 *
 *  for (i = 0 ;; i++) {                    //开始遍历链表
 *
 *      if (i >= part->nelts) {             //检查是否节点数组越界
 *          if (part->next == NULL) {       //下一个节点指针
 *              break;                      //指针为空表示链表结束
 *          }
 *
 *          part = part->next;              //跳到下一个节点
 *          data = part->elts;              //下一个节点的数组地址
 *          i = 0;                          //数组索引初始化
 *      }
 *
 *      ...  data[i] ...                    //在本节点内访问元素
 *
 *  }
 */


// 向链表里添加元素,返回一个void*指针，需要转型操作
void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
