#include "lib-http-server.h"
#include "defs.h"
#include "http-status-codes.h"
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

static int server_socket, client_socket;
static struct sockaddr_in server_addr, client_addr;
static socklen_t client_len = sizeof(client_addr);
static FILE* log_fp = NULL;
static bool http_log_enabled = false;
static void (*http_handler)() = NULL;

void http_enable_log() {
    http_log_enabled = true;
    log_fp = fopen("http.log", "w");
}

void http_server_stop() {
    close(server_socket);
    http_log_msg("Server stopped.\n");
    if (http_log_enabled)
        fclose(log_fp);
}

void http_log_msg(const char* format, ...) {
    if (!http_log_enabled) return ;
    va_list args;
    va_start(args, format);
    time_t current_time;
    struct tm *time_info;
    static char time_string[80];
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", time_info);
    fprintf(log_fp, "[%s] ", time_string);
    vfprintf(log_fp, format, args);
    fflush(log_fp);
    va_end(args);
}

static void http_error(const char* msg) {
    perror(msg);
    if (http_log_enabled)
        fprintf(log_fp, "[ERROR] %s\n", msg);
    http_server_stop();
    exit(1);
}

int http_read(char* buf, int len) {
    int n = read(client_socket, buf, len);
    if (n == -1) {
        perror("Reading from socket failed");
        return -1;
    }
    http_log_msg("Receive %d bytes from client socket.\n", n);
    return n;
}

void http_send(const char* buf, int len) {
    int n = send(client_socket, buf, len, 0);
    if (n == -1) {
        perror("Sending to socket failed");
        return;
    }
    http_log_msg("Send %d bytes to client socket.\n", n);
}

void http_server_init(void (*callback)()) {
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(1);
    }
    http_log_msg("Socket created\n");
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(HTTP_PORT);
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
        http_error("Binding failed");
    http_log_msg("Socket bound at port %d\n", ntohs(server_addr.sin_port));
    if (listen(server_socket, 5) == -1)
        http_error("Listening failed");
    http_log_msg("Listening on port %d.\n", ntohs(server_addr.sin_port));
    http_handler = callback;
}

static bool http_server_should_run() {
    return true;
}

void http_server_run() {
    while (http_server_should_run()) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("Accepting connection failed");
            continue;
        }
        http_log_msg("Connection from client socket %d accepted\n", client_socket);
        http_handler();
        close(client_socket);
        http_log_msg("Connection closed\n");
    }
}

