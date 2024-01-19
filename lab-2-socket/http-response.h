#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H
// http response
#include "defs.h"
#include "http-status-codes.h"
struct http_response {
    enum http_status_code status_code;
    int version_major;
    int version_minor;
    int content_length;
    char* location;
    char* url;
};

// declare a function to change a http_response to a string
int response_to_header(struct http_response* response, char* buf);
#endif