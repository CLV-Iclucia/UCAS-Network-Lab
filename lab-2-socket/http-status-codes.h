#ifndef RETURN_CODES_H
#define RETURN_CODES_H

// use enum to define return codes: 200, 301, 206, 404
enum http_status_code {
    OK = 200,
    MOVED_PERMANENTLY = 301,
    PARTIAL_CONTENT = 206,
    BAD_REQUEST = 400,
    NOT_FOUND = 404
};

// add a function to get the string of a http_status_code
static inline const char* reason_phrase(enum http_status_code status_code) {
    switch (status_code) {
        case OK:
            return "OK";
        case MOVED_PERMANENTLY:
            return "Moved Permanently";
        case PARTIAL_CONTENT:
            return "Partial Content";
        case NOT_FOUND:
            return "Not Found";
        case BAD_REQUEST:
            return "Bad Request";
        default:
            return "Unknown";
    }
}
#endif