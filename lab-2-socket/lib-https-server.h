// add protection
#ifndef LIB_HTTPS_SERVER_H
#define LIB_HTTPS_SERVER_H

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
#include "openssl/ssl.h"
#include "openssl/err.h"

// TODO: https and http has too many things in common
// I think I can make a common interface for them in the future
void https_enable_log();
void https_log_msg(const char* msg, ...);
// callback: what should I do when I connect with a client?
void https_server_init(void (*callback)());
void https_server_run();
void https_server_stop();
// encapsulate the SSL_read and SSL_write
// so that we have a uniform interface for different encryption libraries
int https_read(char* buf, int len);
void https_send(const char* buf, int len);
#endif