// annotated by chrono since 2016
//
// * ngx_queue_s

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_QUEUE_H_INCLUDED_
#define _NGX_QUEUE_H_INCLUDED_


typedef struct ngx_queue_s  ngx_queue_t;

// 队列结构，两个指针
// 需作为结构体的成员使用
// 取原结构使用ngx_queue_data(q, type, link)
struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};


// 初始化头节点，把两个指针都指向自身
#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


// 检查头节点的前驱指针，判断是否是空队列
#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)


// 向队列的头插入数据节点
#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


// 在节点的后面插入数据
#define ngx_queue_insert_after   ngx_queue_insert_head


// 向队列的尾插入数据节点
// 在节点前插入数据
#define ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


// 获取队列的头尾指针，可以用它们来实现队列的正向或反向遍历
// 直到遇到头节点（ngx_queue_sentinel）停止
#define ngx_queue_head(h)                                                     \
    (h)->next


// 获取队列的头尾指针，可以用它们来实现队列的正向或反向遍历
// 直到遇到头节点（ngx_queue_sentinel）停止
#define ngx_queue_last(h)                                                     \
    (h)->prev


// 返回节点自身，对于头节点来说就相当于“哨兵”的作用
#define ngx_queue_sentinel(h)                                                 \
    (h)


// 节点的后继指针
#define ngx_queue_next(q)                                                     \
    (q)->next


// 节点的前驱指针
#define ngx_queue_prev(q)                                                     \
    (q)->prev


// “删除”当前节点，实际上它只是调整了节点的指针
// 把节点从队列里摘除，并没有真正从内存里删除数据
#if (NGX_DEBUG)

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


// 拆分队列
#define ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


// 合并两个队列
#define ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


// 从作为数据成员的ngx_queue_t结构访问到完整的数据节点
// q    ：指针，实际指向ngx_queue_t对象
// type ：节点的类型，是一个名字
// link ：节点里ngx_queue_t成员的名字
#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


// 队列的中间节点
ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);

// 使用一个比较函数指针对队列元素排序，但效率不是很高
void ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


#endif /* _NGX_QUEUE_H_INCLUDED_ */
