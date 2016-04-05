# annotated_nginx
Annotated Nginx Source（中文）

# 简介
注解Nginx源码，帮助学习Nginx

当前使用的是1.8.1稳定版，待注解较完善后升级至1.9.x。

Nginx1.9.11的变动较大，增加了动态模块，完善了多线程，值得仔细研究。

请参考《Nginx模块开发指南：使用C++11和Boost程序库》。

# 已注解

###目录
* [core](/nginx/src/core)
* [event](/nginx/src/event) - todo
* [http](/nginx/src/http) - todo
* [os/unix](/nginx/src/os/unix) - todo

###部分关键源码

#####core目录
* [nginx.c](/nginx/src/core/nginx.c)
* [ngx_conf_file.h](nginx/src/core/ngx_conf_file.h)
* [ngx_connection.c](/nginx/src/core/ngx_connection.c)

#####event目录

#####http目录

#####os/unix目录
* [ngx_process.c](nginx/src/os/unix/ngx_process.c)
* [ngx_process_cycle.c](nginx/src/os/unix/ngx_process_cycle.c)

# 不注解

* auto
* mail
