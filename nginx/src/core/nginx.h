// annotated by chrono since 2016

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGINX_H_INCLUDED_
#define _NGINX_H_INCLUDED_

// version number format
// 1'015'005


#define nginx_version      1019000
#define NGINX_VERSION      "1.19.0"
#define NGINX_VER          "nginx/" NGINX_VERSION

// nginx 1.7之后添加--build=Name选项
// 可以定制一些编译信息
// 例如--build="version: `git describe` , chrono build at `date +%Y%m%d`"

#ifdef NGX_BUILD
#define NGINX_VER_BUILD    NGINX_VER " (" NGX_BUILD ")"
#else
#define NGINX_VER_BUILD    NGINX_VER
#endif

// 用于在ngx_add_inherited_sockets()里获取环境变量
#define NGINX_VAR          "NGINX"
#define NGX_OLDPID_EXT     ".oldbin"


#endif /* _NGINX_H_INCLUDED_ */
