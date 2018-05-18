// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_MURMURHASH_H_INCLUDED_
#define _NGX_MURMURHASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// MurmurHash是摘要算法家族里的新成员（发明于2008年），对文本字符串有很好的效果，具有更好的随机性。
// 原算法可以有一个hash初始值，nginx的实现写死了0,可以修改以适合自己的需要
// eg: h = seed ^ len;
uint32_t ngx_murmur_hash2(u_char *data, size_t len);


#endif /* _NGX_MURMURHASH_H_INCLUDED_ */
