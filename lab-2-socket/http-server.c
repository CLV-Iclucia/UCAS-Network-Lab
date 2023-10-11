#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "defs.h"
#include "http-request.h"
#include "http-status-codes.h"
#include "lib-http-server.h"
#include "lib-https-server.h"
#include "tokenizer.h"
#include <pthread.h>
static struct tokenizer http_tokenizer, https_tokenizer;
#define SMALL_BUFFER_SIZE 64
void prepare_http_response(struct http_request* request, struct http_response* response) {
    static char buf[SMALL_BUFFER_SIZE];
    response->version_major = HTTP_VERSION_MAJOR;
    response->version_minor = HTTP_VERSION_MINOR;
    response->content_length = 0;
    // get host and url
    struct http_request_header* host = get_header(request, "Host");
    if (host == NULL) {
        response->status_code = BAD_REQUEST;
        return;
    }
    sprintf(buf, "https://%s%s", host->value, request->request_line->url);
    response->location = buf;
    response->status_code = MOVED_PERMANENTLY;
}

void my_http_handler() {
    static char recv_buf[BUFFER_SIZE];
    static char send_buf[BUFFER_SIZE];
    static struct http_response response;
    static struct http_request request;
    int n = http_read(recv_buf, sizeof(recv_buf));
    if (n == -1) {
        perror("Reading from socket failed");
        return;
    }
    http_log_msg("Request of length %d received. Start parsing request\n", n);
    http_log_msg("Request:\n %s\n", recv_buf);
    parse_http_request(recv_buf, &request, &http_tokenizer);
    recv_buf[n] = '\0';
    prepare_http_response(&request, &response);
    int header_len = response_to_header(&response, send_buf);
    if (header_len > BUFFER_SIZE) {
        http_log_msg("Response header too long\n");
        return;
    }
    http_log_msg("Sending response header of length %d:\n %s\n", header_len, send_buf);
    http_send(send_buf, header_len);
    free_http_request(&request);
}

void prepare_https_response(struct http_request* request, struct http_response* response, int* start, int* end) {
    static char path[SMALL_BUFFER_SIZE];
    sprintf(path, ".%s", request->request_line->url);
    FILE* fp = fopen(path, "r");
    response->url = path;
    response->version_major = HTTP_VERSION_MAJOR;
    response->version_minor = HTTP_VERSION_MINOR;
    if (fp == NULL) {
        response->status_code = NOT_FOUND;
        return;
    }
    struct http_request_header* range = get_header(request, "Range");
    if (range != NULL) {
        response->status_code = PARTIAL_CONTENT;
        parse_range_value(range->value, start, end);
        if (*end == -1) {
            // get file size
            fseek(fp, 0, SEEK_END);
            *end = ftell(fp) - 1;
        }
        response->content_length = (*end) - (*start) + 1;
    } else {
        response->status_code = OK;
        // get file size
        fseek(fp, 0, SEEK_END);
        response->content_length = ftell(fp);
        *start = 0;
        *end = response->content_length - 1;
    }
    response->location = NULL;
    fclose(fp);
}

void my_https_handler() {
    static char recv_buf[BUFFER_SIZE];
    static char send_buf[BUFFER_SIZE];
    static struct http_response response;
    static struct http_request request;
    https_log_msg("Start handling request\n");
    int n = https_read(recv_buf, sizeof(recv_buf));
    if (n == -1) {
        perror("Reading from socket failed");
        return;
    }
    https_log_msg("Request of length %d received. Start parsing request\n", n);
    https_log_msg("Request:\n %s\n", recv_buf);
    parse_http_request(recv_buf, &request, &https_tokenizer);
    recv_buf[n] = '\0';
    int start = -1, end = -2;
    prepare_https_response(&request, &response, &start, &end);
    if (response.status_code != NOT_FOUND && start < 0) {
        https_log_msg("Invalid range\n");
        return;
    }
    int header_len = response_to_header(&response, send_buf);
    int length = 0;
    if (header_len >= BUFFER_SIZE) {
        https_log_msg("Response header too long\n");
        return;
    }
    https_log_msg("Sending response header of length %d:\n %s\n", header_len, send_buf);
    https_send(send_buf, header_len);
    if (response.status_code == NOT_FOUND)
        return;
    FILE* fp = fopen(response.url, "r");
    if (fp == NULL) {
        https_log_msg("Opening file %s failed\n", response.url);
        perror("Opening file failed");
        return;
    }
    if (response.status_code == PARTIAL_CONTENT)
        fseek(fp, start, SEEK_SET);
    while (length < response.content_length) {
        int block_len = BUFFER_SIZE;
        if (length + block_len > response.content_length)
            block_len = response.content_length - length;
        int n = fread(send_buf, 1, block_len, fp);
        assert(n == block_len);
        https_send(send_buf, block_len);
        length += block_len;
        https_log_msg("Sending block of length %d\n", block_len);
    }
    free_http_request(&request);
}
void* my_http_server(void* arg) {
    http_server_init(&my_http_handler);
    http_server_run();
    http_server_stop();
    return NULL;
}
void* my_https_server(void* arg) {
    https_server_init(&my_https_handler);
    https_server_run();
    https_server_stop();
    return NULL;
}
extern void test_http_request_parser();
extern void test_http_response_to_request();
extern void test_https_response_to_request();
int main(int argc, char** argv) {
    // --http-enable-log: this arg enables logging for http server
    // --https-enable-log: this arg enables logging for https server
    // --test: this arg enables unit tests
    init_mem_pool();
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--http-enable-log") == 0)
            http_enable_log();
        else if (strcmp(argv[i], "--https-enable-log") == 0)
            https_enable_log();
        else if (strcmp(argv[i], "--test") == 0) {
            test_http_request_parser();
            test_http_response_to_request();
            test_https_response_to_request();
        }
    }
    // create a thread to handle http server
    pthread_t http_thread;
    pthread_create(&http_thread, NULL, my_http_server, NULL);
    pthread_t https_thread;
    pthread_create(&https_thread, NULL, my_https_server, NULL);
    pthread_join(http_thread, NULL);
    pthread_join(https_thread, NULL);
    return 0;
}