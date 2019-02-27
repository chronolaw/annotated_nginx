// annotated by chrono since 2018
//
// * ngx_slab_init
// * ngx_slab_alloc_locked
// * ngx_slab_alloc_pages
// * ngx_slab_free_locked
// * ngx_slab_free_pages

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>


// 内存页的标记，即二进制11
// 在指针的后两位
#define NGX_SLAB_PAGE_MASK   3

// 整页分配，0,即memzero
// x >=ngx_slab_max_size
// ngx_slab_max_size = 4k/2 = 2k
#define NGX_SLAB_PAGE        0

// 较大数据
// ngx_slab_exact_size< x <ngx_slab_max_size
// 中等大小，64位系统是64
#define NGX_SLAB_BIG         1

// 中等大小的数据
// x = ngx_slab_exact_size
// 精确的大小，64位系统是64
#define NGX_SLAB_EXACT       2

// 小块的数据
// x < ngx_slab_exact_size
// 中等大小，64位系统是64
#define NGX_SLAB_SMALL       3

// 32位用掩码
#if (NGX_PTR_SIZE == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

// 64位用掩码
#else /* (NGX_PTR_SIZE == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif


// 跳过内存前面的管理结构，得到可用内存位置
// 64位系统上跳过200个字节
// 存放slots数组，管理8/16/32/64等字节管理页
#define ngx_slab_slots(pool)                                                  \
    (ngx_slab_page_t *) ((u_char *) (pool) + sizeof(ngx_slab_pool_t))

// 检查内存页的类型
// 取指针末两位
#define ngx_slab_page_type(page)   ((page)->prev & NGX_SLAB_PAGE_MASK)

// 去掉末两位，得到实际的指针
#define ngx_slab_page_prev(page)                                              \
    (ngx_slab_page_t *) ((page)->prev & ~NGX_SLAB_PAGE_MASK)

// 减去数组首地址，得到数组的下标序号,即偏移
// 因为一个元素代表4k的页面，所以左移4k
// 再加上起始地址，就是空闲页面的内存地址
// 例如序号2，就是第三个页，偏移2*4k，从start+8k开始
#define ngx_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << ngx_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


// 调试用宏，内存放入垃圾数据
// 正式环境不会起作用
#if (NGX_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)

#elif (NGX_HAVE_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)                                                \
    if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)

#else

#define ngx_slab_junk(p, size)

#endif

// 分配多个内存页
static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
    ngx_uint_t pages);

// 释放多个内存页，自1.7.x支持合并
static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages);

// 简单地记录日志
static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
    char *text);


// 最大slab，是page的一半，通常是2k
// 超过此大小则直接分配整页
static ngx_uint_t  ngx_slab_max_size;

// 中等大小，64位系统是64
// 1个指针大小的位图能够管理的大小
// '8'是一个字节里的位数
// 8 * sizeof(uintptr_t)即一个指针的总位数
// 所以一个uintptr_t用位图就可以管理一个页
static ngx_uint_t  ngx_slab_exact_size;

// exact的位移，即6
static ngx_uint_t  ngx_slab_exact_shift;


// 1.14.0新增
// 初始化上面的三个数字
// 在main里调用
void
ngx_slab_sizes_init(void)
{
    ngx_uint_t  n;

    // 最大slab，是page的一半
    // 超过此大小则直接分配整页
    // ngx_pagesize是4k
    ngx_slab_max_size = ngx_pagesize / 2;

    // 中等大小，64位系统是64
    // 1个指针大小的位图能够管理的大小
    // '8'是一个字节里的位数
    // 8 * sizeof(uintptr_t)即一个指针的总位数
    // 所以一个uintptr_t用位图就可以管理一个页
    // 4k/8*8 = 64
    // 如果增大pagesize，8k的话就是128字节，16k就是256字节
    ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));

    // 计算exact的位移，即64=2^6,exact_shift=6
    // 如果增大pagesize，8k的话就是7，16k就是8
    for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
        /* void */
    }
}


// 初始化slab结构
// 按slot和page管理这块共享内存，best-fit
// 之前需要初始化min_shift和end
// 自己使用可以把min_shift适当调整改大一点
// 分析以64位系统，4m共享内存为例
// 缺一个reinit函数，简单地清空共享内存
void
ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    ngx_int_t         m;
    ngx_uint_t        i, n, pages;
    ngx_slab_page_t  *slots, *page;

    // 左移得到最小大小，1<<3=8
    // ngx_init_zone_pool里设置
    pool->min_size = (size_t) 1 << pool->min_shift;

    // 跳过内存前面的管理结构，得到可用内存位置
    // 64位系统上跳过200个字节
    // 存放slots数组，管理8/16/32/64等字节管理页
    slots = ngx_slab_slots(pool);

    // slots数组地址，也是最初的可用内存位置
    p = (u_char *) slots;

    // 得到可用内存数量
    size = pool->end - p;

    // 调试用宏，内存放入垃圾数据
    // 正式环境不会起作用
    ngx_slab_junk(p, size);

    // ngx_os_init里初始化
    // page左移数,4k即2^12,值12
    // 12-3=9
    // 即8-4k之间的幂数量
    // 得到slots数组数量，管理不同的小块
    n = ngx_pagesize_shift - pool->min_shift;

    // 初始化slab管理数组，有9个元素
    // 9*24=216字节
    // 每个元素又是一个链表的头节点
    // 分别管理8/16/32/64/128/256/512/1024/2048等字节
    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */

        // slot的序号标记了自己管理的大小
        // 所以slab字段没有意义
        slots[i].slab = 0;

        // next指向自己
        // 表示还没有分配空闲内存页
        slots[i].next = &slots[i];

        // 不使用prev
        slots[i].prev = 0;
    }

    // 跳过刚才使用的数组空间
    // 9*24=216字节
    p += n * sizeof(ngx_slab_page_t);

    // 统计信息
    // 目前供商业模块ngx_api来调用
    // 目前暂无公开接口使用
    // 只能自己定位获取信息
    pool->stats = (ngx_slab_stat_t *) p;

    // 也有9个
    ngx_memzero(pool->stats, n * sizeof(ngx_slab_stat_t));

    // 跳过刚才的统计信息结构体
    // 9*32=288字节
    p += n * sizeof(ngx_slab_stat_t);

    // 目前可用的内存空间
    // 减去之前的slots和stats数组
    // 目前消耗大小 => 200 + 9*(24+32) => 704
    // 也就是说管理信息用了不到1k
    size -= n * (sizeof(ngx_slab_page_t) + sizeof(ngx_slab_stat_t));

    // 算一下有多少页
    // 4k页加上管理用的页数组
    // 一个ngx_slab_page_t大小是24字节，管理4k
    // 4000k需要1000*24=23k，这就是大概的管理成本
    // 4m共享内存=4096k，去掉消耗有1017页，是23k+17*24，约24k
    pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

    // 页数组起始地址
    pool->pages = (ngx_slab_page_t *) p;

    // 数组清空
    // 这样每个页都是NGX_SLAB_PAGE_FREE
    ngx_memzero(pool->pages, pages * sizeof(ngx_slab_page_t));

    // 数组的第一个元素
    page = pool->pages;

    /* only "next" is used in list head */
    // 空闲页链表头节点
    // 只使用next，其他无意义
    // 与slots类似
    pool->free.slab = 0;
    pool->free.next = page;

    // prev可能在调整链表时置值，但并无大用处
    pool->free.prev = 0;

    // 连续空闲页数量
    page->slab = pages;

    // 两个指针都指向头节点
    page->next = &pool->free;
    page->prev = (uintptr_t) &pool->free;

    // 此时free链表里仅有一个节点，是全部空闲页

    // 真正可用的内存空间，去掉页数组
    // 有指针对齐,对齐到4k，可能会有内存浪费
    // 704 + 23k + 17*24，比24k多，对齐到28k，浪费了3k多
    // 真正可用是4m-28k，利用率约99.3%
    // 可以简单地认为去掉内存的零头是真正可用的空间
    pool->start = ngx_align_ptr(p + pages * sizeof(ngx_slab_page_t),
                                ngx_pagesize);

    // 看真正可用空间是多少页
    m = pages - (pool->end - pool->start) / ngx_pagesize;

    // 修正pages页数
    // 记录到数组第一个元素里
    if (m > 0) {
        pages -= m;
        page->slab = pages;
    }

    // 数组末地址
    pool->last = pool->pages + pages;

    // 总空闲页数
    pool->pfree = pages;

    // 是否记录无内存异常
    pool->log_nomem = 1;

    // 日志用的对象
    // 可以之后由用户指定特殊字符串
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}


// 加锁分配内存
void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_alloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


// 不加锁分配内存
// 超过2k则直接分配整页
void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    ngx_uint_t        i, n, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;

    // 最大slab，是page的一半
    // 超过此大小(2k)则直接分配整页
    if (size > ngx_slab_max_size) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                       "slab alloc: %uz", size);

        // 分配多个内存页
        // 调整指针，从空闲链表里摘掉
        // 右移即除以4k，再看有无余数，计算得到分配的页数
        // 注意返回的是page数组地址，不是真正的内存地址
        page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
                                          + ((size % ngx_pagesize) ? 1 : 0));
        if (page) {
            // 成功分配了内存
            // 减去数组首地址，左移4k
            p = ngx_slab_page_addr(pool, page);

        } else {
            // 没有连续内存页，分配失败，指针为0
            p = 0;
        }

        goto done;
    }

    // 要分配的内存小于2k

    // 要分配的内存>8字节
    if (size > pool->min_size) {
        // 计算左移数，得到对应的slot数组位置
        // shift即2的幂
        // slot是对应的数组位置
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        // 要分配的内存<=8字节
        // 按8字节分配，即1/2/4都分配8字节
        shift = pool->min_shift;

        // 使用0号slot管理
        slot = 0;
    }

    // 对应的统计信息
    pool->stats[slot].reqs++;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    // 跳过内存前面的管理结构，得到可用内存位置
    // 存放slots数组，管理8/16/32/64等字节管理页
    slots = ngx_slab_slots(pool);

    // 找对应的管理页面
    // slot只是头节点，所以使用next
    page = slots[slot].next;

    // 已经分配了空闲内存页
    // 第一次分配内存不会进这里
    if (page->next != page) {

        // shift即2的幂，分配的数量小于64字节
        // NGX_SLAB_SMALL
        // 一个指针大小无法用bitmap全部管理
        // 需要用页前面的一部分做bitmap
        if (shift < ngx_slab_exact_shift) {

            // 空闲页首地址作为bitmap
            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

            // 计算需要多少个小块来管理
            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            // 逐个检查位图
            for (n = 0; n < map; n++) {

                // 不是全ff就可以分配
                if (bitmap[n] != NGX_SLAB_BUSY) {

                    // 在里面再找空位
                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if (bitmap[n] & m) {
                            continue;
                        }

                        // 找到空闲的就置该位，标记已经分配
                        bitmap[n] |= m;

                        // 计算偏移，得到分配的地址
                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;

                        p = (uintptr_t) bitmap + i;

                        // 使用数加1
                        pool->stats[slot].used++;

                        // busy是0xfffff,即此内存页已经全部分配，无空闲
                        if (bitmap[n] == NGX_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != NGX_SLAB_BUSY) {
                                    goto done;
                                }
                            }

                            // 找管理页
                            prev = ngx_slab_page_prev(page);

                            // 从slots的链表里摘除
                            // 可能slots的next==null，之后又需要分配新空闲页
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            // next和prev都不再作为指针
                            page->next = NULL;

                            // 标记页类型为small
                            page->prev = NGX_SLAB_SMALL;
                        }

                        goto done;
                    }
                }
            }

        // shift即2的幂，分配的数量正好是64字节
        // 即容纳32<x<=64的数据
        } else if (shift == ngx_slab_exact_shift) {

            // 检查位图映射
            // m左移，逐位检查bitmap是否是1
            // 1表示已经分配，0是空闲
            // 最后左移变成0,退出循环
            // i即第i个小内存块
            // 可以优化为__builtin_ffs(page->slab) - 1
            for (m = 1, i = 0; m; m <<= 1, i++) {
                if (page->slab & m) {
                    continue;
                }

                // 找到空闲的就置该位，标记已经分配
                page->slab |= m;

                // busy是0xfffff,即此内存页已经全部分配，无空闲
                if (page->slab == NGX_SLAB_BUSY) {

                    // 找前一页
                    prev = ngx_slab_page_prev(page);

                    // 从slots的链表里摘除
                    // 可能slots的next==null，之后又需要分配新空闲页
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    // next和prev都不再作为指针
                    page->next = NULL;

                    // 标记页类型为exact
                    page->prev = NGX_SLAB_EXACT;
                }

                // 先取空闲页地址，再计算偏移，得到分配的地址
                // i<<shift => i*64
                p = ngx_slab_page_addr(pool, page) + (i << shift);

                // 使用数加1
                pool->stats[slot].used++;

                goto done;
            }

        // shift即2的幂，分配的数量>64字节
        } else { /* shift > ngx_slab_exact_shift */

            // 计算掩码
            mask = ((uintptr_t) 1 << (ngx_pagesize >> shift)) - 1;

            // 移动到高32位
            mask <<= NGX_SLAB_MAP_SHIFT;

            // 检查位图映射
            // m左移，逐位检查bitmap是否是1
            // 1表示已经分配，0是空闲
            // 最后左移变成0,退出循环
            // i即第i个小内存块
            for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                if (page->slab & m) {
                    continue;
                }

                // 找到空闲的就置该位，标记已经分配
                page->slab |= m;

                // 高位是0xfffff,即此内存页已经全部分配，无空闲
                if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                    // 找管理页
                    prev = ngx_slab_page_prev(page);

                    // 从slots的链表里摘除
                    // 可能slots的next==null，之后又需要分配新空闲页
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    // next和prev都不再作为指针
                    page->next = NULL;

                    // 标记页类型为big
                    page->prev = NGX_SLAB_BIG;
                }

                // 先取空闲页地址，再计算偏移，得到分配的地址
                // i<<shift => i*128/256
                p = ngx_slab_page_addr(pool, page) + (i << shift);

                // 使用数加1
                pool->stats[slot].used++;

                goto done;
            }
        }

        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
        ngx_debug_point();
    }

    // (page->next == page) 表示还未分配实际管理的内存

    // 获取一个空闲页
    // 即分配了一块4k的内存
    page = ngx_slab_alloc_pages(pool, 1);

    // 获取成功
    if (page) {
        // shift即2的幂，分配的数量小于64字节
        // NGX_SLAB_SMALL
        // 一个指针大小无法用bitmap全部管理
        // 需要用页前面的一部分做bitmap
        if (shift < ngx_slab_exact_shift) {

            // 空闲页首地址作为bitmap
            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

            // 计算需要多少个小块
            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            // 至少分配1块
            if (n == 0) {
                n = 1;
            }

            /* "n" elements for bitmap, plus one requested */

            // 页面的前n块用做位图，不能用于分配，所以置busy
            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = NGX_SLAB_BUSY;
            }

            // 随后标记一块已经分配的内存
            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;

            // 剩下的位图置空，可以分配
            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            // page->slab不是位图，而是chunk的大小
            page->slab = shift;

            // 链接到管理头节点
            // prev和next都指向slots
            page->next = &slots[slot];

            // 设置页的标记，small，分配小于64字节
            // prev可以理解为此page的管理信息
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;

            // 两个页面串起来
            // 即该slot管理了一个page
            slots[slot].next = page;

            pool->stats[slot].total += (ngx_pagesize >> shift) - n;

            // 减去数组首地址，左移4k
            // 得到空闲页的地址
            p = ngx_slab_page_addr(pool, page) + (n << shift);

            // 统计信息
            pool->stats[slot].used++;

            goto done;

        // shift即2的幂，分配的数量正好是64字节
        // 即容纳32<x<=64的数据
        } else if (shift == ngx_slab_exact_shift) {

            // page->slab就可以用位标记内存分配情况
            // 8字节共64bit,64*64=4096Bytes
            // 低位置1，标记分配了第一个chunk
            page->slab = 1;

            // 链接到管理头节点
            // 相当于循环链表
            // prev和next都指向slots
            page->next = &slots[slot];

            // 设置页的标记，exact，精确分配
            // prev可以理解为此page的标志信息
            // prev有两部分信息，高位是指针，低位是标志
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;

            // 页面串到slot链表里
            // 即该slot管理了一个page
            slots[slot].next = page;

            // 统计信息，分配了64个
            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            // 减去数组首地址，左移4k
            // 得到空闲页的地址
            p = ngx_slab_page_addr(pool, page);

            // 统计信息
            pool->stats[slot].used++;

            goto done;

        // shift即2的幂，分配的数量>64字节
        } else { /* shift > ngx_slab_exact_shift */

            // 高32位是bitmap，置1,分配了一块
            // 因为块大，不用全部空间表示bitmap
            // 低32位表示块的大小，如128/256
            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;

            // 链接到管理头节点
            // prev和next都指向slots
            page->next = &slots[slot];

            // 设置页的标记，big，分配大于64字节
            // prev可以理解为此page的管理信息
            // prev有两部分信息，高位是指针，低位是标志
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;

            // 两个页面串起来
            // 即该slot管理了一个page
            slots[slot].next = page;

            // 统计信息
            pool->stats[slot].total += ngx_pagesize >> shift;

            // 减去数组首地址，左移4k
            // 得到空闲页的地址
            p = ngx_slab_page_addr(pool, page);

            // 统计信息
            pool->stats[slot].used++;

            goto done;
        }
    }

    // 获取空闲页失败
    // 分配内存失败
    p = 0;

    // 更新统计信息
    pool->stats[slot].fails++;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}


// 加锁分配内存并清空
void *
ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_calloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


// 不加锁分配内存并清空
void *
ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = ngx_slab_alloc_locked(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


// 加锁释放内存
void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    ngx_shmtx_lock(&pool->mutex);

    ngx_slab_free_locked(pool, p);

    ngx_shmtx_unlock(&pool->mutex);
}


// 不加锁释放内存
void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    ngx_uint_t        i, n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);

    // 检查指针是否属于本共享内存
    // 必须在start和end之间
    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        goto fail;
    }

    // 算出所使用的page数组位置
    // 指针减去内存池地址，再除以4k取整
    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;

    // 取对应的页面数组元素
    page = &pool->pages[n];

    // slab存储页面信息
    // 依类型含义不同
    slab = page->slab;

    // 检查内存页的类型
    // 取prev指针末两位
    type = ngx_slab_page_type(page);

    switch (type) {

    // 分配的内存块小于64字节
    case NGX_SLAB_SMALL:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
        n /= 8 * sizeof(uintptr_t);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));

        if (bitmap[n] & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
            }

            // 取反操作，刚才的位变成0
            // 标记位图，有可分配空间
            bitmap[n] &= ~m;

            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            i = n / (8 * sizeof(uintptr_t));
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;

            if (bitmap[i] & ~m) {
                goto done;
            }

            // 判断是否全空，即全部释放
            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                if (bitmap[i]) {
                    goto done;
                }
            }

            // 全空就回收整个页面
            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (ngx_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    // 分配的内存块等于64字节
    // slab就是位图
    case NGX_SLAB_EXACT:

        // 计算对应的bitmap
        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);

        // 大小就是64
        size = ngx_slab_exact_size;

        // 指针应该对齐
        // 即低位都是0
        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        // 检查位图，该位应该是1,即被分配出去
        if (slab & m) {
            // 找到对应的slot头节点
            slot = ngx_slab_exact_shift - pool->min_shift;

            // 看位图已经全部分配了，即全满页
            // 释放有有空间，可以参与之后的分配
            // 应该也可以用page->next=null来检查
            if (slab == NGX_SLAB_BUSY) {
                // 获取slots数组首地址
                // 存放slots数组，管理8/16/32/64等字节管理页
                slots = ngx_slab_slots(pool);

                // 挂回slots链表，可以参与之后的分配
                page->next = slots[slot].next;
                slots[slot].next = page;

                // 再做一下标记
                // prev指针可用
                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
            }

            // 取反操作，刚才的位变成0
            // 标记位图，有可分配空间
            page->slab &= ~m;

            // 判断是否全空，即全部释放
            if (page->slab) {
                goto done;
            }

            // 全空就回收整个页面
            ngx_slab_free_pages(pool, page, 1);

            // 回收后总分配数减少
            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    // 分配的内存块大于64字节
    // slab高位是bitmap，低位是大小的shift
    case NGX_SLAB_BIG:

        // 取低32位保存的块大小左移数
        shift = slab & NGX_SLAB_SHIFT_MASK;

        // 左移得到块大小
        size = (size_t) 1 << shift;

        // 指针应该对齐
        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        // 计算对应的bitmap
        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);

        // 检查位图，该位应该是1,即被分配出去
        if (slab & m) {
            // 找到对应的slot头节点
            slot = shift - pool->min_shift;

            // null表示不在链表里
            // 即全满页面
            if (page->next == NULL) {

                // 获取slots数组首地址
                // 存放slots数组，管理8/16/32/64等字节管理页
                slots = ngx_slab_slots(pool);

                // 挂回slots链表，可以参与之后的分配
                page->next = slots[slot].next;
                slots[slot].next = page;

                // 再做一下标记
                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
            }

            // 取反操作，刚才的位变成0
            // 标记位图，有可分配空间
            page->slab &= ~m;

            // 判断是否全空，即全部释放
            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            // 全空就回收整个页面
            ngx_slab_free_pages(pool, page, 1);

            // 回收后总分配数减少
            pool->stats[slot].total -= ngx_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

    // 分配的内存块大于2k
    // 整页分配的内存
    // 管理页必须有start标志位
    case NGX_SLAB_PAGE:

        // 指针应该对齐
        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        // 空闲首页必须有start标志位
        if (!(slab & NGX_SLAB_PAGE_START)) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NGX_SLAB_PAGE_BUSY) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): pointer to wrong page");
            goto fail;
        }

        // 算出使用的page数组位置
        // 指针减去内存池地址，再除以4k取整
        // 此处是冗余计算，在1.15.9后的版本里删除
        //n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
        //ngx_slab_free_pages(pool, &pool->pages[n], size);

        // 位运算去掉高位，得到连续页数量
        size = slab & ~NGX_SLAB_PAGE_START;

        // 释放多个内存页，支持合并
        ngx_slab_free_pages(pool, page, size);

        // 调试用宏，内存放入垃圾数据
        // 正式环境不会起作用
        ngx_slab_junk(p, size << ngx_pagesize_shift);

        // 直接返回，不用操作slot数组
        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    ngx_slab_junk(p, size);

    return;

wrong_chunk:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): chunk is already free");

fail:

    return;
}


// 分配多个内存页
// 调整指针，从空闲链表里摘掉
// 注意返回的是page数组地址，不是真正的内存地址
static ngx_slab_page_t *
ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
{
    ngx_slab_page_t  *page, *p;

    // 空闲链表里找满足的连续空闲页面
    for (page = pool->free.next; page != &pool->free; page = page->next) {

        // page->slab是连续空闲页面
        if (page->slab >= pages) {

            // 多个空闲页面
            if (page->slab > pages) {
                // 连续页面的最后一块，prev指向切分后的第一块
                // 从pages处被切成两部分
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                // 切分后的第一块的空闲数量
                page[pages].slab = page->slab - pages;

                // 重新加入空闲链表
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                // 调整指针，从空闲链表里摘掉
                p = (ngx_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                // 恰好等于要求的页面数量
                // 调整指针，从空闲链表里摘掉
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            // 置最高位标记
            // 低位标记页数
            page->slab = pages | NGX_SLAB_PAGE_START;

            page->next = NULL;

            // prev标记为整页分配，0,即memzero
            page->prev = NGX_SLAB_PAGE;

            // 总空闲页面数量减少
            pool->pfree -= pages;

            // 只分配了一页就不需要再调整
            if (--pages == 0) {
                return page;
            }

            // 后续页面都标记为busy
            // prev标记为整页分配，0,即memzero
            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    // 没有足够的连续空闲页面，报错
    if (pool->log_nomem) {
        ngx_slab_error(pool, NGX_LOG_CRIT,
                       "ngx_slab_alloc() failed: no memory");
    }

    return NULL;
}


// 释放多个内存页，自1.7.x支持合并
static void
ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages)
{
    ngx_slab_page_t  *prev, *join;

    // 总空闲页数量增加
    pool->pfree += pages;

    // 当前页的后续空闲数量，减去自己
    page->slab = pages--;

    // 后面连续多个页清空
    // 如果pages==1就没有后面的页面
    if (pages) {
        ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
    }

    // 调整链表结构
    // 从slot链表里摘掉
    if (page->next) {
        prev = ngx_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    // 合并空闲内存页

    // 看归还后的那个内存页join
    join = page + page->slab;

    if (join < pool->last) {

        // 后面的内存页可以合并
        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            // not null意思是在链表里可以合并
            // null是孤立的页面
            if (join->next != NULL) {
                // 空闲页数量增加
                pages += join->slab;
                page->slab += join->slab;

                // 调整队列指针
                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                //这个内存页标记为空闲
                join->slab = NGX_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = NGX_SLAB_PAGE;
            }
        }
    }

    // 再看前面的内存页
    if (page > pool->pages) {

        // join是前面的内存页
        join = page - 1;

        // 前面的内存页可以合并
        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            // 可以合并
            if (join->slab == NGX_SLAB_PAGE_FREE) {
                // 直接跳到第一个空闲页
                join = ngx_slab_page_prev(join);
            }

            if (join->next != NULL) {
                // 空闲页数量增加
                pages += join->slab;
                join->slab += page->slab;

                // 调整队列指针
                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                //这个内存页标记为空闲
                page->slab = NGX_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = NGX_SLAB_PAGE;

                // 移动空闲页指针
                page = join;
            }
        }
    }

    // 加入最后一页的prev，方便以后的合并查找
    if (pages) {
        page[pages].prev = (uintptr_t) page;
    }

    // 合并完成，加入空闲链表
    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    // 空闲链表头节点
    pool->free.next = page;
}


// 简单地记录日志
static void
ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
{
    ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
