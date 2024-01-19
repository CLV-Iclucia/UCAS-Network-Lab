#ifndef HTTP_METHODS_H
#define HTTP_METHODS_H
#include <string.h>
enum http_method {
    GET, // in the future maybe I can add more
    INVALID,
};
static inline const char* method_to_string(enum http_method method) {
    switch (method) {
        case GET:
            return "GET";
        default:
            return "Unknown";
    }
}
static inline enum http_method string_to_method(const char* method) {
    if (strcmp(method, "GET") == 0) {
        return GET;
    } else {
        return INVALID;
    }
}
#endif 