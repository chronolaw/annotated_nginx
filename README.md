# annotated_nginx
Annotated Nginx Source（中文）

# 简介
注解Nginx源码，帮助学习Nginx

当前使用的是1.8.1稳定版，待注解较完善后升级至1.9.x。

Nginx1.9.11的变动较大，增加了动态模块，完善了多线程，值得仔细研究。

请参考《Nginx模块开发指南：使用C++11和Boost程序库》。

# 已注解

###源码目录快捷入口
* [core](/nginx/src/core) - 20%
* [event](/nginx/src/event) - 50%，只注解核心模块和epoll，kqueue等不关注
* [http](/nginx/src/http) - todo
* [os/unix](/nginx/src/os/unix) - 20%

####部分关键源码（目录分类）

######core目录
* [nginx.c](/nginx/src/core/nginx.c)
* [ngx_conf_file.h](nginx/src/core/ngx_conf_file.h)
* [ngx_connection.c](/nginx/src/core/ngx_connection.c)

######event目录
* [ngx_event.h](/nginx/src/event/ngx_event.h)
* [ngx_event.c](/nginx/src/event/ngx_event.c)
* [ngx_event_accept.c](/nginx/src/event/ngx_event_accept.c)
* [ngx_event_timer.c](/nginx/src/event/ngx_event_timer.c)
* [ngx_epoll_module.c](/nginx/src/event/modules/ngx_epoll_module.c)

######http目录

######os/unix目录
* [ngx_process.c](nginx/src/os/unix/ngx_process.c)
* [ngx_process_cycle.c](nginx/src/os/unix/ngx_process_cycle.c)

####部分关键源码（功能分类）

######进程机制
* [nginx.c](/nginx/src/core/nginx.c)
* [ngx_conf_file.h](nginx/src/core/ngx_conf_file.h)
* [ngx_process.c](nginx/src/os/unix/ngx_process.c)
* [ngx_process_cycle.c](nginx/src/os/unix/ngx_process_cycle.c)

######事件机制
* [ngx_connection.h](/nginx/src/core/ngx_connection.h)
* [ngx_connection.c](/nginx/src/core/ngx_connection.c)
* [ngx_event.h](/nginx/src/event/ngx_event.h)
* [ngx_event.c](/nginx/src/event/ngx_event.c)
* [ngx_event_accept.c](/nginx/src/event/ngx_event_accept.c)
* [ngx_event_timer.c](/nginx/src/event/ngx_event_timer.c)
* [ngx_epoll_module.c](/nginx/src/event/modules/ngx_epoll_module.c)

######多线程机制

######http处理

# 不注解

* auto
* mail
