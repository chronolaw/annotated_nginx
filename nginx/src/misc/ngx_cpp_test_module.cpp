// annotated by chrono since 2016
//
// 测试Nginx编译C++的兼容性，并不是模块
// 在auto/modules里搜MISC

// stub module to test header files' C++ compatibility

// 在C++代码里使用nginx头文件需要用extern "C"
extern "C" {
  #include <ngx_config.h>
  #include <ngx_core.h>
  #include <ngx_event.h>
  #include <ngx_event_connect.h>
  #include <ngx_event_pipe.h>

  #include <ngx_http.h>

  #include <ngx_mail.h>
  #include <ngx_mail_pop3_module.h>
  #include <ngx_mail_imap_module.h>
  #include <ngx_mail_smtp_module.h>

  #include <ngx_stream.h>
}

// nginx header files should go before other, because they define 64-bit off_t
// #include <string>

// 没有更多的功能代码，仅仅是验证编译
// 但表示可以使用C++开发Nginx模块
// 不支持C++11特性，必须改auto/make

void ngx_cpp_test_handler(void *data);

void
ngx_cpp_test_handler(void *data)
{
    return;
}
