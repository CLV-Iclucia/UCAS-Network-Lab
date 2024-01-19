#include "lib-https-server.h"
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
static bool https_log_enabled = false;
static void (*https_handler)() = NULL;
static SSL_CTX* ctx = NULL;
static SSL* ssl = NULL;

void https_enable_log() {
    https_log_enabled = true;
    log_fp = fopen("https.log", "w");
}

void https_server_stop() {
    int sock = SSL_get_fd(ssl);
    if (sock < 0) {
        perror("SSL_get_fd failed");
        exit(1);
    }
    SSL_free(ssl);
    close(sock);
    https_log_msg("Server stopped.\n");
    SSL_CTX_free(ctx);
    https_log_msg("SSL context freed.\n");
    if (https_log_enabled)
        fclose(log_fp);
}

void https_log_msg(const char* format, ...) {
    if (!https_log_enabled) return ;
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

static void https_error(const char* msg) {
    perror(msg);
    if (https_log_enabled)
        fprintf(log_fp, "[ERROR] %s\n", msg);
    https_server_stop();
    exit(1);
}

void https_server_init(void (*callback)()) {
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(TLS_server_method());
	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
    https_log_msg("Certificate loaded\n");
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}
    https_log_msg("Private key loaded\n");
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(1);
    }
    https_log_msg("Socket created\n");
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(HTTPS_PORT);
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
        https_error("Binding failed");
    https_log_msg("Socket bound at port %d\n", ntohs(server_addr.sin_port));
    if (listen(server_socket, 5) == -1)
        https_error("Listening failed");
    https_log_msg("Listening on port %d.\n", ntohs(server_addr.sin_port));
    https_handler = callback;
}

static bool https_server_should_run() {
    return true;
}

int https_read(char* buf, int len) {
    int bytes = SSL_read(ssl, buf, len);
    if (bytes < 0) {
        perror("SSL_read failed");
        exit(1);
    }
    return bytes;
}

void https_send(const char* buf, int len) {
    SSL_write(ssl, buf, len);
}

void https_server_run() {
    while (https_server_should_run()) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("Accepting connection failed");
            continue;
        }
        https_log_msg("Connection accepted\n");
        ssl = SSL_new(ctx); 
		SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) == -1) {
		    perror("SSL_accept failed");
            continue;
	    }
        https_log_msg("SSL connection established\n");
        https_handler();
        close(client_socket);
        https_log_msg("Connection closed\n");
    }
   
}

