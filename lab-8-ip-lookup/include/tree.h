#ifndef __TREE_H__
#define __TREE_H__

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#define std_vector(T) std_vector_##T##_t

#define std_vector_define(T) \
typedef struct std_vector(T) { \
    T* data; \
    uint32_t size; \
    uint32_t capacity; \
} std_vector(T); \

#define push_back(T) push_back_##T
#define push_back_define(T) \
static inline void push_back(T)(std_vector(T)* v, T x) {\
    if (v->size >= v->capacity) { \
        v->capacity = ((v->capacity) << 1); \
        v->data = (T*)realloc(v->data, sizeof(T) * (v->capacity)); \
    } \
    v->data[v->size++] = x; \
} \

#define at(T) at_##T
#define at_define(T) \
static inline T at(T)(std_vector(T)* v, uint32_t i) { \
    return v->data[i]; \
} \

#define reserve(T) reserve_##T
#define reserve_define(T) \
static inline void reserve(T)(std_vector(T)* v, uint32_t n) { \
    v->data = (T*)malloc(sizeof(T) * n); \
    v->capacity = n; \
} \

#define emplace_back(T) emplace_back_##T
#define emplace_back_define(T) \
static inline void emplace_back(T)(std_vector(T)* v) { \
    if (v->size >= v->capacity) { \
        v->capacity = ((v->capacity) << 1); \
        v->data = (T*)realloc(v->data, sizeof(T) * v->capacity); \
    } \
    v->size++; \
} \

#define vector_init(T) vector_init_##T
#define vector_init_define(T) \
static inline void vector_init(T)(std_vector(T)* v) { \
    v->data = (T*)malloc(sizeof(T)); \
    v->size = 0; \
    v->capacity = 1; \
} \

#define std_vector_instantiate(T) \
std_vector_define(T) \
push_back_define(T) \
at_define(T) \
reserve_define(T) \
emplace_back_define(T) \
vector_init_define(T) \

// do not change it
#define TEST_SIZE 100000

#define TRAIN_SIZE 697882 
// macro is not my style!
// #define I_NODE 0 // internal node
// #define M_NODE 1 // match node
#define LEFT 0
#define RIGHT 1

typedef enum node_type {
    I_NODE,
    M_NODE
} node_type_t;

#define MASK(x,y) (((x) & 0x000000ff) << (y))

typedef struct node {
    node_type_t type; //I_NODE or M_NODE
    uint32_t port;
    struct node* lchild;
    struct node* rchild;
} node_t;

typedef struct poptrie_node {
    uint64_t leafvec;
    uint64_t vector;
    uint32_t base[2];
} poptrie_node_t;

#define DIRECT_INDEX_BITS 12

std_vector_instantiate(poptrie_node_t);
std_vector_instantiate(char);

typedef struct poptrie {    
    uint32_t D[1 << DIRECT_INDEX_BITS];
    std_vector(poptrie_node_t) N;
    std_vector(char) L;
} poptrie_t;

void create_tree(const char*);
uint32_t *lookup_tree(uint32_t *);
void create_tree_advance(const char*);
uint32_t *lookup_tree_advance(uint32_t *);

uint32_t* read_test_data(const char* lookup_file);

#endif
