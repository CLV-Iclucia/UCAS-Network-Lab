#include "defs.h"
#include "http-response.h"
#include "http-status-codes.h"
#include <stdio.h>

int response_to_header(struct http_response* response, char* buf) {
    char* ptr = buf;
    enum http_status_code stat = response->status_code;
    ptr += sprintf(ptr, "HTTP/%d.%d %d %s\r\n", response->version_major, response->version_minor, 
    stat, reason_phrase(stat));
    ptr += sprintf(ptr, "Content-Length: %d\r\n", response->content_length);
    if (response->location != NULL)
        ptr += sprintf(ptr, "Location: %s\r\n", response->location);
    if (response->content_length > 0)
        ptr += sprintf(ptr, "\r\n");
    *ptr = '\0';
    return ptr - buf;
}