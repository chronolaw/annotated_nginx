// annotated by chrono since 2016
//
// * ngx_udp_connection_s
// * ngx_event_recvmsg
// * ngx_lookup_udp_connection
// * ngx_udp_shared_recv

/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


// 1.15.0 udp移动到新的ngx_event_udp.c

#if !(NGX_WIN32)

// ngx_udp_connection_t
// udp连接的附加数据
// 作为ngx_connection_t的一个成员
// 串进红黑树，缓冲区里是客户端发送的数据
struct ngx_udp_connection_s {
    ngx_rbtree_node_t   node;
    ngx_connection_t   *connection;
    ngx_buf_t          *buffer;
};


// 专用的关闭函数
static void ngx_close_accepted_udp_connection(ngx_connection_t *c);

// 1.15新增
// 专用的udp读取函数
static ssize_t ngx_udp_shared_recv(ngx_connection_t *c, u_char *buf,
    size_t size);

// 新udp连接插入红黑树
// 使用crc32计算散列
// key是客户端地址+服务器地址
static ngx_int_t ngx_insert_udp_connection(ngx_connection_t *c);

// 红黑树查找是否已经有连接
// 使用crc32计算散列
// key是客户端地址+服务器地址
static ngx_connection_t *ngx_lookup_udp_connection(ngx_listening_t *ls,
    struct sockaddr *sockaddr, socklen_t socklen,
    struct sockaddr *local_sockaddr, socklen_t local_socklen);


// 1.10新增函数，接受udp连接的handler
// 流程类似ngx_event_accept
// 1.15使用红黑树保持udp连接，支持客户端发送多包
void
ngx_event_recvmsg(ngx_event_t *ev)
{
    ssize_t            n;
    ngx_buf_t          buf;
    ngx_log_t         *log;
    ngx_err_t          err;
    socklen_t          socklen, local_socklen;
    ngx_event_t       *rev, *wev;
    struct iovec       iov[1];
    struct msghdr      msg;
    ngx_sockaddr_t     sa, lsa;
    struct sockaddr   *sockaddr, *local_sockaddr;
    ngx_listening_t   *ls;
    ngx_event_conf_t  *ecf;
    ngx_connection_t  *c, *lc;

    // 接收数据的缓冲区
    // 这里写死了64k，即udp包不能超过这个大小
    static u_char      buffer[65535];

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

#if (NGX_HAVE_IP_RECVDSTADDR)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_addr))];
#elif (NGX_HAVE_IP_PKTINFO)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    u_char             msg_control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif

#endif

    // 事件已经超时
    if (ev->timedout) {
        // 遍历监听端口列表，重新加入epoll连接事件
        if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
            return;
        }

        ev->timedout = 0;
    }

    // 得到event core模块的配置，检查是否接受多个连接
    ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    // rtsig在nginx 1.9.x已经删除
    if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
        // epoll是否允许尽可能接受多个请求
        // 这里的ev->available仅使用1个bit的内存空间
        ev->available = ecf->multi_accept;
    }

    // 事件的连接对象
    lc = ev->data;

    // 事件对应的监听端口对象
    ls = lc->listening;

    // 此时还没有数据可读
    ev->ready = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

    // 循环调用recvmsg接收udp数据
    do {
        // 清空msghdr结构体，准备读取数据
        ngx_memzero(&msg, sizeof(struct msghdr));

        // 设置接收数据的缓冲区
        // 大小是65535字节
        iov[0].iov_base = (void *) buffer;
        iov[0].iov_len = sizeof(buffer);

        // 客户端的地址
        msg.msg_name = &sa;

        // 设置接收数据的缓冲区
        msg.msg_namelen = sizeof(ngx_sockaddr_t);

        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {

#if (NGX_HAVE_IP_RECVDSTADDR || NGX_HAVE_IP_PKTINFO)
            if (ls->sockaddr->sa_family == AF_INET) {
                msg.msg_control = &msg_control;
                msg.msg_controllen = sizeof(msg_control);
            }
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
            if (ls->sockaddr->sa_family == AF_INET6) {
                msg.msg_control = &msg_control6;
                msg.msg_controllen = sizeof(msg_control6);
            }
#endif
        }

#endif

        // 接收udp数据
        n = recvmsg(lc->fd, &msg, 0);

        // 调用失败直接返回
        if (n == -1) {
            err = ngx_socket_errno;

            if (err == NGX_EAGAIN) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, err,
                               "recvmsg() not ready");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "recvmsg() failed");

            return;
        }

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)
        if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "recvmsg() truncated data");
            continue;
        }
#endif

        // udp接收数据成功

        // 客户端的地址
        sockaddr = msg.msg_name;
        socklen = msg.msg_namelen;

        if (socklen > (socklen_t) sizeof(ngx_sockaddr_t)) {
            socklen = sizeof(ngx_sockaddr_t);
        }

        // 0长度是unix domain socket
        if (socklen == 0) {

            /*
             * on Linux recvmsg() returns zero msg_namelen
             * when receiving packets from unbound AF_UNIX sockets
             */

            socklen = sizeof(struct sockaddr);
            ngx_memzero(&sa, sizeof(struct sockaddr));
            sa.sockaddr.sa_family = ls->sockaddr->sa_family;
        }

        // 服务器的地址
        local_sockaddr = ls->sockaddr;
        local_socklen = ls->socklen;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

        if (ls->wildcard) {
            struct cmsghdr  *cmsg;

            ngx_memcpy(&lsa, local_sockaddr, local_socklen);
            local_sockaddr = &lsa.sockaddr;

            for (cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&msg, cmsg))
            {

#if (NGX_HAVE_IP_RECVDSTADDR)

                if (cmsg->cmsg_level == IPPROTO_IP
                    && cmsg->cmsg_type == IP_RECVDSTADDR
                    && local_sockaddr->sa_family == AF_INET)
                {
                    struct in_addr      *addr;
                    struct sockaddr_in  *sin;

                    addr = (struct in_addr *) CMSG_DATA(cmsg);
                    sin = (struct sockaddr_in *) local_sockaddr;
                    sin->sin_addr = *addr;

                    break;
                }

#elif (NGX_HAVE_IP_PKTINFO)

                if (cmsg->cmsg_level == IPPROTO_IP
                    && cmsg->cmsg_type == IP_PKTINFO
                    && local_sockaddr->sa_family == AF_INET)
                {
                    struct in_pktinfo   *pkt;
                    struct sockaddr_in  *sin;

                    pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
                    sin = (struct sockaddr_in *) local_sockaddr;
                    sin->sin_addr = pkt->ipi_addr;

                    break;
                }

#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)

                if (cmsg->cmsg_level == IPPROTO_IPV6
                    && cmsg->cmsg_type == IPV6_PKTINFO
                    && local_sockaddr->sa_family == AF_INET6)
                {
                    struct in6_pktinfo   *pkt6;
                    struct sockaddr_in6  *sin6;

                    pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
                    sin6 = (struct sockaddr_in6 *) local_sockaddr;
                    sin6->sin6_addr = pkt6->ipi6_addr;

                    break;
                }

#endif

            }
        }

#endif

        // 红黑树查找是否已经有连接
        // 使用crc32计算散列
        // key是客户端地址+服务器地址
        c = ngx_lookup_udp_connection(ls, sockaddr, socklen, local_sockaddr,
                                      local_socklen);

        // 有就直接复用，不新建
        if (c) {

#if (NGX_DEBUG)
            if (c->log->log_level & NGX_LOG_DEBUG_EVENT) {
                ngx_log_handler_pt  handler;

                handler = c->log->handler;
                c->log->handler = NULL;

                ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "recvmsg: fd:%d n:%z", c->fd, n);

                c->log->handler = handler;
            }
#endif

            // 清空缓冲区
            ngx_memzero(&buf, sizeof(ngx_buf_t));

            // 指向刚读取的数据
            // 即固定的64k空间
            buf.pos = buffer;
            buf.last = buffer + n;

            // 读事件
            rev = c->read;

            // 设置udp的缓冲区
            // 由ngx_udp_shared_recv读取
            c->udp->buffer = &buf;

            // udp连接可读
            rev->ready = 1;
            rev->active = 0;

            // 执行读回调函数ngx_stream_session_handler
            // 按阶段执行处理引擎，调用各个模块的handler
            // 从缓冲区读数据调用的是ngx_udp_shared_recv
            // 最终读取的是udp->buffer，即本函数的buffer
            rev->handler(rev);

            // 读完清空缓冲区
            if (c->udp) {
                c->udp->buffer = NULL;
            }

            // 此时不可读
            rev->ready = 0;
            rev->active = 1;

            // 完成一次udp accept，continue
            // 实际上是一次udp read
            goto next;
        }

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif
        // 红黑树里没有，是新连接

        // 负载均衡的阈值
        ngx_accept_disabled = ngx_cycle->connection_n / 8
                              - ngx_cycle->free_connection_n;

        // 接收数据成功，从连接池里获取一个新的连接
        c = ngx_get_connection(lc->fd, ev->log);
        if (c == NULL) {
            return;
        }

        // ？？？
        c->shared = 1;

        // udp类型的连接
        c->type = SOCK_DGRAM;
        c->socklen = socklen;

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

        // 为连接创建内存池
        c->pool = ngx_create_pool(ls->pool_size, ev->log);
        if (c->pool == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        c->sockaddr = ngx_palloc(c->pool, socklen);
        if (c->sockaddr == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        // 从msghdr里拷贝地址
        ngx_memcpy(c->sockaddr, sockaddr, socklen);

        // 连接使用一个新的日志对象
        log = ngx_palloc(c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        // 从监听端口拷贝
        *log = ls->log;

        // 1.15新增
        // 专用的udp读取函数
        // 之前udp的recv指针是null，无法读数据
        c->recv = ngx_udp_shared_recv;

        // udp发送函数
        c->send = ngx_udp_send;
        c->send_chain = ngx_udp_send_chain;

        c->log = log;
        c->pool->log = log;

        // 监听端口
        // c->listening里包含了server配置等关键信息
        // 决定了如何处理这个连接
        c->listening = ls;

        if (local_sockaddr == &lsa.sockaddr) {
            local_sockaddr = ngx_palloc(c->pool, local_socklen);
            if (local_sockaddr == NULL) {
                ngx_close_accepted_udp_connection(c);
                return;
            }

            ngx_memcpy(local_sockaddr, &lsa, local_socklen);
        }

        // 服务器地址
        c->local_sockaddr = local_sockaddr;
        c->local_socklen = local_socklen;

        // 创建连接用的缓冲区
        c->buffer = ngx_create_temp_buf(c->pool, n);
        if (c->buffer == NULL) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        // 把之前收到的数据拷贝到连接里的缓冲区
        // 注意这里，有数据拷贝的成本
        c->buffer->last = ngx_cpymem(c->buffer->last, buffer, n);

        // 设置读写事件
        rev = c->read;
        wev = c->write;

        // 连接立即可写
        rev->active = 1;
        wev->ready = 1;

        rev->log = log;
        wev->log = log;

        /*
         * TODO: MT: - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         *
         * TODO: MP: - allocated in a shared memory
         *           - ngx_atomic_fetch_add()
         *             or protection by critical section or light mutex
         */

        // 连接计数增加
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_STAT_STUB)
        (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

        // 拷贝客户端地址字符串
        if (ls->addr_ntop) {
            c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
            if (c->addr_text.data == NULL) {
                ngx_close_accepted_udp_connection(c);
                return;
            }

            c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                             c->addr_text.data,
                                             ls->addr_text_max_len, 0);
            if (c->addr_text.len == 0) {
                ngx_close_accepted_udp_connection(c);
                return;
            }
        }

#if (NGX_DEBUG)
        {
        ngx_str_t  addr;
        u_char     text[NGX_SOCKADDR_STRLEN];

        ngx_debug_accepted_connection(ecf, c);

        if (log->log_level & NGX_LOG_DEBUG_EVENT) {
            addr.data = text;
            addr.len = ngx_sock_ntop(c->sockaddr, c->socklen, text,
                                     NGX_SOCKADDR_STRLEN, 1);

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, log, 0,
                           "*%uA recvmsg: %V fd:%d n:%z",
                           c->number, &addr, c->fd, n);
        }

        }
#endif

        // 新udp连接插入红黑树
        // 使用crc32计算散列
        // key是客户端地址+服务器地址
        if (ngx_insert_udp_connection(c) != NGX_OK) {
            ngx_close_accepted_udp_connection(c);
            return;
        }

        log->data = NULL;
        log->handler = NULL;

        // 接受连接，收到请求的回调函数
        // stream模块里是ngx_stream_init_connection
        // 进入流水线阶段处理
        ls->handler(c);

    next:

        // epoll不处理
        if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
            ev->available -= n;
        }

    // 如果ev->available = ecf->multi_accept;
    // epoll尽可能接受多个请求，直至accept出错EAGAIN，即无新连接请求
    // 否则epoll只接受一个请求后即退出循环
    } while (ev->available);
}


// 专用的关闭函数
static void
ngx_close_accepted_udp_connection(ngx_connection_t *c)
{
    ngx_free_connection(c);

    c->fd = (ngx_socket_t) -1;

    if (c->pool) {
        ngx_destroy_pool(c->pool);
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif
}


// 1.15新增
// 专用的udp读取函数
static ssize_t
ngx_udp_shared_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    ngx_buf_t  *b;

    // udp连接必须有udp结构体
    if (c->udp == NULL || c->udp->buffer == NULL) {
        return NGX_AGAIN;
    }

    // 先看udp结构体里的缓冲
    b = c->udp->buffer;

    // 看里面有没有数据
    n = ngx_min(b->last - b->pos, (ssize_t) size);

    // 有就拷贝到输出缓冲区
    ngx_memcpy(buf, b->pos, n);

    // 清空缓冲区
    c->udp->buffer = NULL;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}


void
ngx_udp_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_int_t               rc;
    ngx_connection_t       *c, *ct;
    ngx_rbtree_node_t     **p;
    ngx_udp_connection_t   *udp, *udpt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            udp = (ngx_udp_connection_t *) node;
            c = udp->connection;

            udpt = (ngx_udp_connection_t *) temp;
            ct = udpt->connection;

            rc = ngx_cmp_sockaddr(c->sockaddr, c->socklen,
                                  ct->sockaddr, ct->socklen, 1);

            if (rc == 0 && c->listening->wildcard) {
                rc = ngx_cmp_sockaddr(c->local_sockaddr, c->local_socklen,
                                      ct->local_sockaddr, ct->local_socklen, 1);
            }

            p = (rc < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


// 新udp连接插入红黑树
// 使用crc32计算散列
// key是客户端地址+服务器地址
static ngx_int_t
ngx_insert_udp_connection(ngx_connection_t *c)
{
    uint32_t               hash;
    ngx_pool_cleanup_t    *cln;
    ngx_udp_connection_t  *udp;

    // 指针不空已经插入
    if (c->udp) {
        return NGX_OK;
    }

    // 分配内存
    udp = ngx_pcalloc(c->pool, sizeof(ngx_udp_connection_t));
    if (udp == NULL) {
        return NGX_ERROR;
    }

    // 指向本连接
    udp->connection = c;

    // 使用crc32计算散列
    // key是客户端地址+服务器地址
    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) c->sockaddr, c->socklen);

    if (c->listening->wildcard) {
        ngx_crc32_update(&hash, (u_char *) c->local_sockaddr, c->local_socklen);
    }

    // 完成crc32计算
    ngx_crc32_final(hash);

    udp->node.key = hash;

    // 清理函数，会删除红黑树节点
    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    // 清理函数，会删除红黑树节点
    cln->data = c;
    cln->handler = ngx_delete_udp_connection;

    // 插入红黑树
    ngx_rbtree_insert(&c->listening->rbtree, &udp->node);

    c->udp = udp;

    return NGX_OK;
}


// 清理函数，会删除红黑树节点
void
ngx_delete_udp_connection(void *data)
{
    ngx_connection_t  *c = data;

    if (c->udp == NULL) {
        return;
    }

    ngx_rbtree_delete(&c->listening->rbtree, &c->udp->node);

    c->udp = NULL;
}


// 红黑树查找是否已经有连接
// 使用crc32计算散列
// key是客户端地址+服务器地址
static ngx_connection_t *
ngx_lookup_udp_connection(ngx_listening_t *ls, struct sockaddr *sockaddr,
    socklen_t socklen, struct sockaddr *local_sockaddr, socklen_t local_socklen)
{
    uint32_t               hash;
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_udp_connection_t  *udp;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (sockaddr->sa_family == AF_UNIX) {
        struct sockaddr_un *saun = (struct sockaddr_un *) sockaddr;

        if (socklen <= (socklen_t) offsetof(struct sockaddr_un, sun_path)
            || saun->sun_path[0] == '\0')
        {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                           "unbound unix socket");
            return NULL;
        }
    }

#endif

    // 红黑树在监听端口结构体里
    node = ls->rbtree.root;
    sentinel = ls->rbtree.sentinel;

    // 使用crc32计算散列
    // key是客户端地址+服务器地址
    ngx_crc32_init(hash);
    ngx_crc32_update(&hash, (u_char *) sockaddr, socklen);

    if (ls->wildcard) {
        ngx_crc32_update(&hash, (u_char *) local_sockaddr, local_socklen);
    }

    // 完成crc32计算
    ngx_crc32_final(hash);

    // 红黑树查找
    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        // 强制转化成udp数据
        udp = (ngx_udp_connection_t *) node;

        // 本连接
        c = udp->connection;

        // 比较是否是同一个客户端
        rc = ngx_cmp_sockaddr(sockaddr, socklen,
                              c->sockaddr, c->socklen, 1);

        if (rc == 0 && ls->wildcard) {
            rc = ngx_cmp_sockaddr(local_sockaddr, local_socklen,
                                  c->local_sockaddr, c->local_socklen, 1);
        }

        // 相等，找到
        if (rc == 0) {
            return c;
        }

        // 不同，继续左右找
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

#else

void
ngx_delete_udp_connection(void *data)
{
    return;
}

#endif
