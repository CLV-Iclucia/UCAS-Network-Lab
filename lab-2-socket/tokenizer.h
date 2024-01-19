// add protection
#ifndef TOKENIZER_H
#define TOKENIZER_H
#include <string.h>
struct tokenizer {
    char* str;
    char* nxt;
};

static inline void init_tokenizer(struct tokenizer* tokenizer, char* str) {
    tokenizer->str = str;
    tokenizer->nxt = str;
}
static inline void nxt_token(struct tokenizer* tokenizer) {
    tokenizer->str = tokenizer->nxt;
}
char* get_token(struct tokenizer* tokenizer, char* delim);

#endif