// annotated by chrono since 2016
//
// * ngx_rbtree_node_s
// * ngx_rbtree_s
// * ngx_rbtree_min

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 红黑树的key类型，无符号整数
// 通常我们使用这个key类型
typedef ngx_uint_t  ngx_rbtree_key_t;

// 红黑树的key类型，有符号整数
typedef ngx_int_t   ngx_rbtree_key_int_t;


// 红黑树节点
typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

// 红黑树节点
// 通常需要以侵入式的方式使用，即作为结构体的一个成员
// 在C语言里利用平坦内存特点，后面放自己的数据
// 使用宏offsetof(node, color)计算得到地址
// 参考ngx_http_limit_conn_module.c
struct ngx_rbtree_node_s {
    // 节点的key，用于二分查找
    ngx_rbtree_key_t       key;

    // 左子节点
    ngx_rbtree_node_t     *left;

    // 右子节点
    ngx_rbtree_node_t     *right;

    // 父节点
    ngx_rbtree_node_t     *parent;

    // 节点的颜色
    // 根节点是黑色
    // 新插入的节点必定是红色
    u_char                 color;

    // 节点数据，只有一个字节，通常无意义
    // 由用户定义自己的数据复用
    u_char                 data;
};


// 定义红黑树结构
typedef struct ngx_rbtree_s  ngx_rbtree_t;

// 插入红黑树的函数指针
typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// 定义红黑树结构
struct ngx_rbtree_s {
    // 必须的根节点
    ngx_rbtree_node_t     *root;

    // 哨兵节点，通常就是root，用于标记查找结束
    ngx_rbtree_node_t     *sentinel;

    // 节点的插入方法
    // 常用的是ngx_rbtree_insert_value、ngx_rbtree_insert_timer_value
    ngx_rbtree_insert_pt   insert;
};


// 初始化红黑树，最初根节点就是哨兵节点
#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i

#define ngx_rbtree_data(node, type, link)                                     \
    (type *) ((u_char *) (node) - offsetof(type, link))


// 向红黑树插入一个节点
// 插入后旋转红黑树，保持平衡
void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);

// 在红黑树里删除一个节点
void ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);

// 普通红黑树插入函数
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);

// 定时器红黑树专用插入函数
void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// 1.11.11新增，可以用来遍历红黑树
ngx_rbtree_node_t *ngx_rbtree_next(ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);


// 简单的函数宏，检查颜色
#define ngx_rbt_red(node)               ((node)->color = 1)
#define ngx_rbt_black(node)             ((node)->color = 0)
#define ngx_rbt_is_red(node)            ((node)->color)
#define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))
#define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

// 哨兵节点颜色是黑的
#define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)


// 在红黑树里查找最小值
// 二叉树，必定是最左边的节点
static ngx_inline ngx_rbtree_node_t *
ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NGX_RBTREE_H_INCLUDED_ */
