#include "http-request.h"
#include "http-methods.h"
#include "tokenizer.h"
#include <bits/pthreadtypes.h>
#include <ctype.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>

// now this is only a toy server so static small arrays + lock can serve as a toy mem pool
// TODO: in the future I may need to upgrade it
#define MEM_POOL_SIZE 32
static pthread_spinlock_t req_head_lock;
static struct http_request_header mem_pool[MEM_POOL_SIZE];
static bool mem_pool_used[MEM_POOL_SIZE];
static pthread_spinlock_t req_line_lock;
static struct http_request_line req_line_pool[MEM_POOL_SIZE];
static bool req_line_used[MEM_POOL_SIZE];

static struct http_request_line* new_request_line() {
    pthread_spin_lock(&req_line_lock);
    for (int i = 0; i < MEM_POOL_SIZE; i++) {
        if (!req_line_used[i]) {
            req_line_used[i] = true;
            pthread_spin_unlock(&req_line_lock);
            return &req_line_pool[i];
        }
    }
    pthread_spin_unlock(&req_line_lock);
    return NULL;
}

// request_line = method" "url" HTTP/"version_major"."version_minor
static struct http_request_line* parse_http_request_line(char* request_line, struct tokenizer* tk) {
    char* method = get_token(tk, " ");
    char* url = get_token(tk, " ");
    char* ver = get_token(tk, "\r\n");
    if (method == NULL || url == NULL || ver == NULL) return NULL;
    enum http_method m = string_to_method(method);
    if (m == INVALID) return NULL;
    ver = strstr(ver, "HTTP/");
    if (ver == NULL) return NULL;
    ver += 5;
    int v_major, v_minor;
    v_major = atoi(ver);
    ver++;
    if (*ver != '.') return NULL;
    ver++;
    v_minor = atoi(ver);
    struct http_request_line* req_line = new_request_line();
    req_line->method = m;
    req_line->url = url;
    req_line->version_major = v_major;
    req_line->version_minor = v_minor;
    nxt_token(tk);
    return req_line;
}

void init_mem_pool() {
    pthread_spin_init(&req_head_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&req_line_lock, PTHREAD_PROCESS_PRIVATE);
    for (int i = 0; i < MEM_POOL_SIZE; i++) {
        mem_pool_used[i] = false;
        req_line_used[i] = false;
    }
}

static struct http_request_header* alloc_request_header() {
    pthread_spin_lock(&req_head_lock);
    for (int i = 0; i < MEM_POOL_SIZE; i++) {
        if (!mem_pool_used[i]) {
            mem_pool_used[i] = true;
            pthread_spin_unlock(&req_head_lock);
            return &mem_pool[i];
        }
    }
    pthread_spin_unlock(&req_head_lock);
    return NULL;
}

static struct http_request_header* new_header() {
    // TODO: use a better mem pool
    struct http_request_header* header = alloc_request_header();
    header->nxt = NULL;
    return header;
}
// header = field": "value
static struct http_request_header* parse_http_request_header(char* header, struct tokenizer* tk) {
    if (header == NULL) return NULL;
    char *field, *value;
    field = get_token(tk, ": ");
    if (field == NULL) return NULL;
    value = get_token(tk, "\r\n");
    if (value == NULL) return NULL;
    struct http_request_header* req_header = new_header();
    req_header->field = field;
    req_header->value = value;
    return req_header;
}
// headers = (header"\r\n")+
static struct http_request_header* parse_http_request_headers(char* request_headers, struct tokenizer* tk) {
    if (request_headers == NULL) return NULL;
    struct http_request_header* header_list_tail = parse_http_request_header(request_headers, tk);
    if (header_list_tail == NULL) return NULL;
    struct http_request_header* header_list_head = header_list_tail;
    char* request_header = tk->str;
    while (request_header != NULL) {
        header_list_tail->nxt = parse_http_request_header(request_header, tk);
        header_list_tail = header_list_tail->nxt;
        request_header = tk->nxt;
    }
    return header_list_head;
}
// a simplified request:
// request = request-line "\r\n" header-list
void parse_http_request(char* request, struct http_request* http_request, struct tokenizer* tk) {
    init_tokenizer(tk, request);
    char* request_line = request;
    http_request->request_line = parse_http_request_line(request_line, tk);
    char* headers = tk->nxt;
    http_request->header_front = parse_http_request_headers(headers, tk);
}

void parse_range_value(char *value, int *start, int *end) {
    char *tok = strstr(value, "=");
    if (tok == NULL) return;
    tok = strstr(value, "-");
    if (tok == NULL) return;
    char* ptr = tok - 1;
    if (!isdigit(*ptr))
        *start = 0;
    else {
        while(isdigit(*ptr)) ptr--;
        ptr++;
        *start = atoi(ptr);
    } 
    tok++;
    if (*tok != '\0' && *tok != '\r')
        *end = atoi(tok);
    else *end = -1;
}

struct http_request_header* get_header(struct http_request* http_request, char* field) {
    struct http_request_header* header = http_request->header_front;
    while (header != NULL) {
        if (strcmp(header->field, field) == 0)
            return header;
        header = header->nxt;
    }
    return NULL;
}

static void print_http_request_line(struct http_request_line* req_line) {
    printf("%s ", method_to_string(req_line->method));
    printf("%s ", req_line->url);
    printf("HTTP/%d.%d\n", req_line->version_major, req_line->version_minor);
}

static void print_http_request_headers(struct http_request_header* req_header) {
    while (req_header != NULL) {
        printf("%s: %s\n", req_header->field, req_header->value);
        req_header = req_header->nxt;
    }
}

void print_http_request(struct http_request *http_request) {
    print_http_request_line(http_request->request_line);
    print_http_request_headers(http_request->header_front);
}

static void free_http_request_line(struct http_request_line *request_line) {
    pthread_spin_lock(&req_line_lock);
    int idx = request_line - req_line_pool;
    req_line_used[idx] = false;
    pthread_spin_unlock(&req_line_lock);
}

static void free_http_header(struct http_request_header *request_header) {
    pthread_spin_lock(&req_head_lock);
    int idx = request_header - mem_pool;
    mem_pool_used[idx] = false;
    pthread_spin_unlock(&req_head_lock);
}

void free_http_request(struct http_request* request) {
    free_http_request_line(request->request_line);
    while(request->header_front != NULL) {
        struct http_request_header* nxt = request->header_front->nxt;
        free_http_header(request->header_front);
        request->header_front = nxt;
    }
}