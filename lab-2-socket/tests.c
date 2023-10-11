#include "http-request.h"
#include "http-response.h"
#include "tokenizer.h"
#include <assert.h>
#include <stdio.h>

// some basic requests
void test_http_request_parser() {
    struct http_request http_request1;
    struct http_request http_request2;
    struct http_request http_request3;
    struct http_request http_request4;
    static char request1[] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n";
    static char request2[] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\nRange: bytes=0-10\r\n\r\n";
    static char request3[] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\nRange: bytes=0-\r\n\r\n";
    static char request4[] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\nRange: bytes=-10\r\n\r\n";
    printf("Testing http request parser...\n");
    // parse the requests
    struct tokenizer tk;
    parse_http_request(request1, &http_request1, &tk);
    parse_http_request(request2, &http_request2, &tk);
    parse_http_request(request3, &http_request3, &tk);
    parse_http_request(request4, &http_request4, &tk);
    print_http_request(&http_request1);
    print_http_request(&http_request2);
    print_http_request(&http_request3);
    print_http_request(&http_request4);
    // check the results by simple assertions
    assert(http_request1.request_line->method == GET);
    assert(http_request1.request_line->url != NULL);
    assert(strcmp(http_request1.request_line->url, "/") == 0);
    assert(http_request1.request_line->version_major == 1);
    assert(http_request1.request_line->version_minor == 1);
    assert(get_header(&http_request1, "Host") != NULL);
    assert(get_header(&http_request1, "User-Agent") != NULL);
    assert(get_header(&http_request1, "Accept") != NULL);
    assert(strcmp(get_header(&http_request1, "Host")->value, "localhost:8080") == 0);
    assert(strcmp(get_header(&http_request1, "User-Agent")->value, "curl/7.64.1") == 0);
    assert(strcmp(get_header(&http_request1, "Accept")->value, "*/*") == 0);
    assert(get_header(&http_request1, "Range") == NULL);
    assert(http_request2.request_line->method == GET);
    assert(http_request2.request_line->url != NULL);
    assert(strcmp(http_request2.request_line->url, "/") == 0);
    assert(http_request2.request_line->version_major == 1);
    assert(http_request2.request_line->version_minor == 1);
    assert(get_header(&http_request2, "Host") != NULL);
    assert(get_header(&http_request2, "User-Agent") != NULL);
    assert(get_header(&http_request2, "Accept") != NULL);
    assert(get_header(&http_request2, "Range") != NULL);
    assert(strcmp(get_header(&http_request2, "Host")->value, "localhost:8080") == 0);
    assert(strcmp(get_header(&http_request2, "User-Agent")->value, "curl/7.64.1") == 0);    
    assert(strcmp(get_header(&http_request2, "Accept")->value, "*/*") == 0);
    assert(strcmp(get_header(&http_request2, "Range")->value, "bytes=0-10") == 0);
    assert(http_request3.request_line->method == GET);
    assert(http_request3.request_line->url != NULL);
    assert(strcmp(http_request3.request_line->url, "/") == 0);
    assert(http_request3.request_line->version_major == 1);
    assert(http_request3.request_line->version_minor == 1);
    assert(get_header(&http_request3, "Host") != NULL);
    assert(get_header(&http_request3, "User-Agent") != NULL);
    assert(get_header(&http_request3, "Accept") != NULL);
    assert(get_header(&http_request3, "Range") != NULL);
    assert(strcmp(get_header(&http_request3, "Host")->value, "localhost:8080") == 0);
    assert(strcmp(get_header(&http_request3, "User-Agent")->value, "curl/7.64.1") == 0);
    assert(strcmp(get_header(&http_request3, "Accept")->value, "*/*") == 0);
    assert(strcmp(get_header(&http_request3, "Range")->value, "bytes=0-") == 0);
    assert(http_request4.request_line->method == GET);
    assert(http_request4.request_line->url != NULL);
    assert(strcmp(http_request4.request_line->url, "/") == 0);
    assert(http_request4.request_line->version_major == 1);
    assert(http_request4.request_line->version_minor == 1);
    assert(get_header(&http_request4, "Host") != NULL);
    assert(get_header(&http_request4, "User-Agent") != NULL);
    assert(get_header(&http_request4, "Accept") != NULL);
    assert(get_header(&http_request4, "Range") != NULL);
    assert(strcmp(get_header(&http_request4, "Host")->value, "localhost:8080") == 0);
    assert(strcmp(get_header(&http_request4, "User-Agent")->value, "curl/7.64.1") == 0);
    assert(strcmp(get_header(&http_request4, "Accept")->value, "*/*") == 0);
    assert(strcmp(get_header(&http_request4, "Range")->value, "bytes=-10") == 0);
    printf("All tests passed!\n");
    // check the results by printing them out
    free_http_request(&http_request1);
    free_http_request(&http_request2);
    free_http_request(&http_request3);
    free_http_request(&http_request4);
}

extern void prepare_http_response(struct http_request* request, struct http_response* response);
extern void prepare_https_response(struct http_request* request, struct http_response* response, int* start, int* end);
void test_http_response_to_request() {
    // allocate necessary static buffers
    char buffer[1024];
    char *response = buffer;
    // generate a request
    struct http_request http_request;
    struct tokenizer tk;
    static char request1[] = "GET / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\n\r\n";
    parse_http_request(request1, &http_request, &tk);
    // prepare a response
    struct http_response http_response;
    prepare_http_response(&http_request, &http_response);
    // convert the response to a string
    int len = response_to_header(&http_response, response);
    // print it out
    printf("Response:\n%s\n", response);
    free_http_request(&http_request);
}

void test_https_response_to_request() {
    // allocate necessary static buffers
    char buffer[1024];
    char *response = buffer;
    // generate a request
    struct http_request http_request;
    struct tokenizer tk;
    // generate a request with range
    char request1[] = "GET /index.html HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.64.1\r\nAccept: */*\r\nRange: bytes=50180-\r\n\r\n";
    parse_http_request(request1, &http_request, &tk);
    // prepare a response
    struct http_response http_response;
    int start, end;
    prepare_https_response(&http_request, &http_response, &start, &end);
    // convert the response to a string
    int len = response_to_header(&http_response, response);
    // print it out
    printf("Response:\n%s\n", response);
    free_http_request(&http_request);
}