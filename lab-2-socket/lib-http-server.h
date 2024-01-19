// add protection
#ifndef LIB_HTTP_SERVER_H
#define LIB_HTTP_SERVER_H
#include "defs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "http-request.h"
#include "http-response.h"
#include <stdarg.h>
void http_enable_log();
void http_log_msg(const char* msg, ...);
// callback: what should I do when I connect with a client?
void http_server_init(void (*callback)());
void http_server_run();
void http_server_stop();

int http_read(char* buf, int len);
void http_send(const char* buf, int len);
#endif