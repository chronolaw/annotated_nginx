// annotated by chrono since 2016
//
// * ngx_hash_elt_t
// * ngx_hash_init_t

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// 散列的桶，不定长结构体
// 末尾的1长度数组是C语言常用的技巧
typedef struct {
    // 指向实际的元素
    void             *value;

    // name的实际长度
    // name即散列表元素的key
    u_short           len;

    // 存储key
    // 在分配内存时会分配适当的大小
    u_char            name[1];
} ngx_hash_elt_t;


// 散列表结构体
// 表面上好像是使用开放寻址法
// 但实际上是开链法，只是链表表现为紧凑的数组
// 用链表存储key相同的元素
typedef struct {
    // 散列桶存储位置
    // 二维数组，里面存储的是指针
    ngx_hash_elt_t  **buckets;

    // 数组的长度
    // 即桶的数量
    ngx_uint_t        size;
} ngx_hash_t;


// 支持通配符的散列表
typedef struct {
    // 散列表结构体
    ngx_hash_t        hash;

    void             *value;
} ngx_hash_wildcard_t;


// 初始化散列表的数组元素
// 存放的是key、对应的hash和值
typedef struct {
    ngx_str_t         key;
    ngx_uint_t        key_hash;
    void             *value;
} ngx_hash_key_t;


// 计算散列值的函数原型
// nginx提供两个：
// ngx_uint_t ngx_hash_key(u_char *data, size_t len);
// ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


// 多用途的散列表
typedef struct {
    // 精确匹配的散列表
    ngx_hash_t            hash;

    // 通配符在前面的散列表
    ngx_hash_wildcard_t  *wc_head;

    // 通配符在后面的散列表
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;


// 初始化散列表的结构体
typedef struct {
    // 待初始化的散列表结构体
    ngx_hash_t       *hash;

    // 散列函数
    // 通常是ngx_hash_key_lc
    ngx_hash_key_pt   key;

    // 散列表里的最大桶数量
    ngx_uint_t        max_size;

    // 桶的大小，即ngx_hash_elt_t加自定义数据
    ngx_uint_t        bucket_size;

    // 散列表的名字，记录日志用
    char             *name;

    // 使用的内存池
    ngx_pool_t       *pool;

    // 临时用的内存池
    ngx_pool_t       *temp_pool;
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
    ngx_uint_t        hsize;

    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

    ngx_array_t       keys;
    ngx_array_t      *keys_hash;

    ngx_array_t       dns_wc_head;
    ngx_array_t      *dns_wc_head_hash;

    ngx_array_t       dns_wc_tail;
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


// 键值对结构, 主要用来表示HTTP头部信息
typedef struct {
    ngx_uint_t        hash;         //散列（哈希）标记
    ngx_str_t         key;          //键
    ngx_str_t         value;        //值
    u_char           *lowcase_key;  //key的小写字符串指针
} ngx_table_elt_t;


// 表面上好像是使用开放寻址法
// 但实际上是开链法，只是链表表现为紧凑的数组
// 用链表存储key相同的元素
void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);

void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

// 初始化散列表hinit
// 输入一个ngx_hash_key_t数组，长度散nelts
ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

// 初始化通配符散列表hinit
// 函数执行后把names数组里的元素放入散列表，可以hash查找
// Nginx散列表是只读的，初始化后不能修改，只能查找
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

// 简单地对单个字符计算散列
#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)

// 计算散列值
ngx_uint_t ngx_hash_key(u_char *data, size_t len);

// 小写后再计算hash
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);

// 小写化的同时计算出散列值
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
