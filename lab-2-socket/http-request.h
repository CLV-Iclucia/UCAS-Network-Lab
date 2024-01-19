// add protection
#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H
#include "defs.h"
#include "http-status-codes.h"
#include "http-methods.h"
#include "tokenizer.h"
#include <stdbool.h>
// define a struct to store the request
// for now we only need method, url and range
struct http_request_line {
    enum http_method method;
    char* url;
    int version_major;
    int version_minor;
};
struct http_request_header {
    char* field;
    char* value;
    struct http_request_header* nxt;
};
struct http_request {
    struct http_request_line* request_line;
    struct http_request_header* header_front;
};
// declare a function to parse a request
// the request string will change after parsing
void parse_http_request(char* request, struct http_request* http_request, struct tokenizer* tk);
struct http_request_header* get_header(struct http_request* http_request, char* field);
void init_mem_pool();
void print_http_request(struct http_request* http_request);
void parse_range_value(char* value, int* start, int* end);
void free_http_request(struct http_request* http_request);
#endif