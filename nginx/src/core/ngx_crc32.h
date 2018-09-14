// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CRC32_H_INCLUDED_
#define _NGX_CRC32_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// crc32可以用来当作简单的hash函数计算摘要
// 但速度较慢，推荐使用ngx_murmur_hash2
// 速度大约是crc32的10倍

extern uint32_t  *ngx_crc32_table_short;
extern uint32_t   ngx_crc32_table256[];

// 这两个函数的计算结果是相同的，区别仅在于内部实现
// ngx_crc32_short()使用了较小的查找表，处理短字符串（30~60）速度快
// 而ngx_crc32_long()在处理长字符串时更有优势。

static ngx_inline uint32_t
ngx_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = ngx_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = ngx_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static ngx_inline uint32_t
ngx_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = ngx_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}

// 分段计算crc32,相当于分解了ngx_crc32_long

#define ngx_crc32_init(crc)                                                   \
    crc = 0xffffffff


static ngx_inline void
ngx_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;

    while (len--) {
        c = ngx_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}


#define ngx_crc32_final(crc)                                                  \
    crc ^= 0xffffffff


ngx_int_t ngx_crc32_table_init(void);


#endif /* _NGX_CRC32_H_INCLUDED_ */
