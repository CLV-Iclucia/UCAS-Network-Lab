#include "tokenizer.h"
char* get_token(struct tokenizer* tokenizer, char* delim) {
    char* token = tokenizer->nxt;
    if (token == NULL) {
        return NULL;
    }
    char* end = strstr(token, delim);
    if (end == NULL) {
        tokenizer->nxt = NULL;
        return token;
    }
    *end = '\0';
    tokenizer->nxt = end + strlen(delim);
    return token;
}