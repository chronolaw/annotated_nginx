// annotated by chrono since 2016
//
// * ngx_http_upstream_rr_peer_s
// * ngx_http_upstream_rr_peers_s
// * ngx_http_upstream_rr_peer_data_t

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_upstream_rr_peer_s   ngx_http_upstream_rr_peer_t;

// 与每个服务器的具体IP地址一一对应
// 1.11.5新增slow_start、max_conns
// 但slow_start在开源版本中暂未使用
struct ngx_http_upstream_rr_peer_s {
    struct sockaddr                *sockaddr;
    socklen_t                       socklen;
    ngx_str_t                       name;
    ngx_str_t                       server;

    ngx_int_t                       current_weight;
    ngx_int_t                       effective_weight;
    ngx_int_t                       weight;

    // 活跃连接数
    ngx_uint_t                      conns;

    // 最大活跃连接数
    ngx_uint_t                      max_conns;

    ngx_uint_t                      fails;
    time_t                          accessed;
    time_t                          checked;

    ngx_uint_t                      max_fails;
    time_t                          fail_timeout;
    ngx_msec_t                      slow_start;
    ngx_msec_t                      start_time;

    // 是否下线
    ngx_uint_t                      down;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

    // 默认启用ngx_http_upstream_zone_module
#if (NGX_HTTP_UPSTREAM_ZONE)
    // 共享内存操作的锁
    // 可以单独锁定某一个peer读写
    // ngx_http_upstream_rr_peer_lock(peers, peer)
    ngx_atomic_t                    lock;
#endif

    // “下一个”peer的位置
    // 为了配合共享内存
    // nginx自1.9.0开始不再使用数组方式存储peer
    ngx_http_upstream_rr_peer_t    *next;

    NGX_COMPAT_BEGIN(32)
    NGX_COMPAT_END
};


typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;

// 管理IP地址列表
// backup/非backup服务器IP列表
// 关键成员是peer
struct ngx_http_upstream_rr_peers_s {
    // 服务器数量
    // 早期是peer数组的长度
    // 但1.9.0加入共享内存后是peer链表的长度
    ngx_uint_t                      number;

    // 默认启用ngx_http_upstream_zone_module
#if (NGX_HTTP_UPSTREAM_ZONE)
    // 指向共享内存里的slab池
    // 指针不空，即表示存储在共享内存里
    ngx_slab_pool_t                *shpool;

    // 共享内存操作的锁
    // 注意，用作读写锁，提高效率
    // ngx_http_upstream_rr_peers_rlock(peers)
    // ngx_http_upstream_rr_peers_unlock(peers)
    ngx_atomic_t                    rwlock;

    // 在共享内存里的下一组服务器列表
    // 多个upsteam{}可以存在一块共享内存里
    ngx_http_upstream_rr_peers_t   *zone_next;
#endif

    // 总权重
    ngx_uint_t                      total_weight;

    // 只有一台服务器时优化处理
    unsigned                        single:1;

    // 是否加权
    unsigned                        weighted:1;

    // upstream块的名字
    ngx_str_t                      *name;

    // backup服务器IP列表
    ngx_http_upstream_rr_peers_t   *next;

    // 非backup服务器IP列表
    // 是一个链表，用peer->next来访问
    ngx_http_upstream_rr_peer_t    *peer;
};


// 默认启用ngx_http_upstream_zone_module
// 使用共享内存才会发生锁操作，否则不需要锁
// 读写锁操作，使用原子变量自旋
#if (NGX_HTTP_UPSTREAM_ZONE)

#define ngx_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }

#else
// 不启用ngx_http_upstream_zone_module
// 锁操作都是空实现，无动作

#define ngx_http_upstream_rr_peers_rlock(peers)
#define ngx_http_upstream_rr_peers_wlock(peers)
#define ngx_http_upstream_rr_peers_unlock(peers)
#define ngx_http_upstream_rr_peer_lock(peers, peer)
#define ngx_http_upstream_rr_peer_unlock(peers, peer)

#endif


// 负载均衡算法使用的数据结构，从peers.peer就可以获得可用的IP地址列表
typedef struct {
    ngx_uint_t                      config;

    // 可用的IP地址列表
    // 分在用和备用两组
    ngx_http_upstream_rr_peers_t   *peers;

    ngx_http_upstream_rr_peer_t    *current;
    uintptr_t                      *tried;
    uintptr_t                       data;
} ngx_http_upstream_rr_peer_data_t;


ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
