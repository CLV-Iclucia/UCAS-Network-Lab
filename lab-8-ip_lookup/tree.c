#include "tree.h"
#include "util.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 64
// return an array of ip represented by an unsigned integer, the length of array
// is TEST_SIZE

static node_t *trie;
static uint32_t ipstr_to_int(const char *ipstr);
static uint32_t ip_queries[TEST_SIZE];
uint32_t *read_test_data(const char *lookup_file) {
  char buf[BUFSIZE], data[BUFSIZE];
  FILE *fp = fopen(lookup_file, "r");
  if (fp == NULL) {
    fprintf(stderr, "Error: cannot open file %s\n", lookup_file);
    exit(1);
  }
  int cnt = 0;
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    sscanf(buf, "%s", data);
    ip_queries[cnt++] = ipstr_to_int(data);
  }
  fclose(fp);
  return ip_queries;
}

static uint32_t ipstr_to_int(const char *ipstr) {
  uint32_t result = 0;
  int octet, octet1, octet2, octet3;
  sscanf(ipstr, "%d.%d.%d.%d", &octet, &octet1, &octet2, &octet3);
  result |= (uint32_t)octet << 24;
  result |= (uint32_t)octet1 << 16;
  result |= (uint32_t)octet2 << 8;
  result |= (uint32_t)octet3;
  return result;
}

static node_t *new_trie_node(node_type_t type, uint32_t port) {
  node_t *node = malloc(sizeof(node_t));
  node->lchild = NULL;
  node->rchild = NULL;
  node->type = type;
  node->port = port;
  return node;
}

static void trie_insert(node_t *trie, uint32_t ip, uint32_t mask,
                        uint32_t port) {
  node_t *curr = trie;
  for (int i = 0; i < mask; i++) {
    int bit = (ip >> (31 - i)) & 1;
    if (bit) {
      if (curr->rchild == NULL)
        curr->rchild = new_trie_node(I_NODE, -1);
      curr = curr->rchild;
    } else {
      if (curr->lchild == NULL)
        curr->lchild = new_trie_node(I_NODE, -1);
      curr = curr->lchild;
    }
  }
  curr->type = M_NODE;
  curr->port = port;
}

static void free_trie(node_t *trie) {
  if (trie->lchild != NULL)
    free_trie(trie->lchild);
  if (trie->rchild != NULL)
    free_trie(trie->rchild);
  free(trie);
}

// Constructing an basic trie-tree to lookup according to `forward_file`
// in fact binary tree like this can be compactly storaged
// but I shall not modify the original definition of node_t and do not optimize
// it making this too fast is not a good thing
void create_tree(const char *forward_file) {
  char buf[BUFSIZ], data[BUFSIZ];
  FILE *fp = fopen(forward_file, "r");
  if (fp == NULL) {
    fprintf(stderr, "Error: cannot open file %s\n", forward_file);
    exit(1);
  }
  trie = new_trie_node(I_NODE, -1);
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    uint32_t mask, port;
    sscanf(buf, "%s %d %d", data, &mask, &port);
    uint32_t ip = ipstr_to_int(data);
    trie_insert(trie, ip, mask, port);
  }
  fclose(fp);
}

static uint32_t ans[TEST_SIZE];

uint32_t trie_lookup(node_t *trie, int limit, uint32_t ip) {
  node_t *curr = trie;
  uint32_t port = -1;
  for (int i = 0; i < limit; i++) {
    int bit = (ip >> (31 - i)) & 1;
    if (bit) {
      if (curr->rchild == NULL)
        break;
      curr = curr->rchild;
    } else {
      if (curr->lchild == NULL)
        break;
      curr = curr->lchild;
    }

    if (curr->type == M_NODE)
      port = curr->port;
  }
  return port;
}

// Look up the ports of ip in file `ip_to_lookup.txt` using the basic tree,
// input is read from `read_test_data` func
uint32_t *lookup_tree(uint32_t *ip_vec) {
  for (int i = 0; i < TEST_SIZE; i++)
    ans[i] = trie_lookup(trie, 32, ip_vec[i]);
  return ans;
}

static poptrie_t pop_trie;

#define extract(ip, offset, len)                                               \
  (((ip) >> (32 - (offset) - (len))) & ((1 << (len)) - 1))

// keep the first len bits of ip
#define keep(ip, len) (((ip) >> (32 - (len))) << (32 - (len)))

typedef struct poptrie_raw_node {
  node_type_t type;
  uint32_t port;
  bool has_child;
  int8_t longest[1 << 5];
  struct poptrie_raw_node *ch[1 << 5];
} poptrie_raw_node_t;

static node_t *direct_prefix_trie;
static node_t *direct_map_trie;

typedef poptrie_raw_node_t *poptrie_raw_node_ptr_t;

std_vector_instantiate(poptrie_raw_node_ptr_t);

static std_vector(poptrie_raw_node_ptr_t) raw_poptrie;

static poptrie_raw_node_t *new_poptrie_raw_node(node_type_t type) {
  poptrie_raw_node_t *node =
      (poptrie_raw_node_t *)malloc(sizeof(poptrie_raw_node_t));
  node->type = type;
  node->port = -1;
  node->has_child = false;
  memset(node->longest, -1, sizeof(node->longest));
  memset(node->ch, 0, sizeof(node->ch));
  return node;
}

static void poptrie_raw_insert(uint32_t ip, uint32_t mask, uint32_t port) {
  uint32_t index = keep(ip, DIRECT_INDEX_BITS);
  if (mask <= DIRECT_INDEX_BITS) {
    trie_insert(direct_prefix_trie, index, mask, port);
    return;
  }
  uint32_t dindex = trie_lookup(direct_map_trie, DIRECT_INDEX_BITS, index);
  if (dindex == (uint32_t)-1) {
    push_back(poptrie_raw_node_ptr_t)(&raw_poptrie,
                                      new_poptrie_raw_node(I_NODE));
    dindex = raw_poptrie.size - 1;
    trie_insert(direct_map_trie, index, DIRECT_INDEX_BITS, dindex);
  }
  poptrie_raw_node_t *curr = raw_poptrie.data[dindex];
  int i = DIRECT_INDEX_BITS;
  for (; i + 5 < mask; i += 5) {
    int value = extract(ip, i, 5);
    if (curr->ch[value] == NULL) {
      curr->ch[value] = new_poptrie_raw_node(I_NODE);
      curr->has_child = true;
    }
    curr = curr->ch[value];
  }
  int value = extract(ip, i, 5);
  int rest_prefix_length = mask - i;
  for (int prefix = 0; prefix < (1 << 5); prefix++) {
    if (extract(prefix, 27, rest_prefix_length) !=
        extract(value, 27, rest_prefix_length))
      continue;
    if (curr->ch[prefix] == NULL) {
      curr->has_child = true;
      curr->ch[prefix] = new_poptrie_raw_node(M_NODE);
      curr->longest[prefix] = rest_prefix_length;
      curr->ch[prefix]->port = port;
    }
    if (curr->longest[prefix] == -1 || curr->longest[prefix] < rest_prefix_length) {
      curr->ch[prefix]->port = port;
      curr->longest[prefix] = rest_prefix_length;
    }
  }
}

static uint8_t port_bucket[1 << 5];

static void poptrie_flatten(poptrie_raw_node_t *raw, int index) {
  uint32_t base[2] = {-1, -1}, vector = 0, leafvec = 0;
  memset(port_bucket, 0, sizeof(port_bucket));
  uint8_t last_port = 0;
  for (int i = 0; i < (1 << 5); i++) {
    if (raw->ch[i] != NULL) {
      if (raw->ch[i]->type == M_NODE) {
        if (raw->ch[i]->port != last_port && raw->ch[i]->port != -1) {
          push_back(uint8_t)(&pop_trie.L, raw->ch[i]->port);
          if (base[0] == (uint32_t)(-1))
            base[0] = pop_trie.L.size - 1;
          leafvec |= (1ull << i);
          last_port = raw->ch[i]->port;
        }
      }
      if (raw->ch[i]->has_child) {
        emplace_back(poptrie_node_t)(&pop_trie.N);
        if (base[1] == (uint32_t)(-1))
          base[1] = pop_trie.N.size - 1;
        vector |= (1ull << i);
      }
    }
  }
  pop_trie.N.data[index].base[0] = base[0];
  pop_trie.N.data[index].base[1] = base[1];
  pop_trie.N.data[index].vector = vector;
  pop_trie.N.data[index].leafvec = leafvec;
  for (int i = 0; i < 32; i++)
    if (vector & (1 << i))
      poptrie_flatten(raw->ch[i],
                      base[1] + popcount(vector & ((2ull << i) - 1)) - 1);
  free(raw);
  raw = NULL;
}

static uint32_t poptrie_lookup(uint32_t ip) {
  uint32_t index = extract(ip, 0, DIRECT_INDEX_BITS);
  uint32_t dindex = pop_trie.D[index];
  if ((dindex & (1ul << 31))) {
    if (dindex == -1)
      return -1;
    return dindex & ((1ul << 31) - 1);
  }
  index = dindex;
  uint32_t offset = DIRECT_INDEX_BITS;

  uint32_t value = extract(ip, offset, 5);
  printf("%d %d\n", ip >> 15, (ip >> 15) & 31);
  uint32_t vector = pop_trie.N.data[index].vector;
  uint32_t base;
  uint32_t bc;
  while (vector & (1ull << value)) {
    base = pop_trie.N.data[index].base[1];
    bc = popcount(vector & ((2ull << value) - 1));
    index = base + bc - 1;
    offset += 5;
    value = extract(ip, offset, 5);
    vector = pop_trie.N.data[index].vector;
  }
  base = pop_trie.N.data[index].base[0];
  if (base == -1)
    return -1;
  bc = popcount(pop_trie.N.data[index].leafvec & ((2ull << value) - 1));
  return pop_trie.L.data[base + bc - 1]; 
}
// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree_advance(const char *forward_file) {
  char buf[BUFSIZ], data[BUFSIZ];
  FILE *fp = fopen(forward_file, "r");
  if (fp == NULL) {
    fprintf(stderr, "Error: cannot open file %s\n", forward_file);
    exit(1);
  }
  memset(pop_trie.D, 0xff, sizeof(pop_trie.D));
  vector_init(poptrie_raw_node_ptr_t)(&raw_poptrie);
  vector_init(poptrie_node_t)(&pop_trie.N);
  vector_init(uint8_t)(&pop_trie.L);
  direct_map_trie = new_trie_node(I_NODE, -1);
  direct_prefix_trie = new_trie_node(I_NODE, -1);
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    uint32_t mask, port;
    sscanf(buf, "%s %d %d", data, &mask, &port);
    uint32_t ip = ipstr_to_int(data);
    poptrie_raw_insert(keep(ip, mask), mask, port);
  }
  fclose(fp);
  memset(pop_trie.D, 0xff, sizeof(pop_trie.D));
  for (uint32_t ip = 0; ip < (1 << DIRECT_INDEX_BITS); ip++) {
    uint32_t dindex = trie_lookup(direct_map_trie, DIRECT_INDEX_BITS,
                                  ip << (32 - DIRECT_INDEX_BITS));
    if (dindex == (uint32_t)-1) {
      dindex = trie_lookup(direct_prefix_trie, DIRECT_INDEX_BITS,
                           ip << (32 - DIRECT_INDEX_BITS));
      // assume: there are no more tha 2^30 ports
      // so if dindex is -1, it indicates that no entry is found
      pop_trie.D[ip] = dindex | (1ul << 31);
    } else {
      poptrie_raw_node_t *raw = raw_poptrie.data[dindex];
      if (pop_trie.D[ip] == -1) {
        emplace_back(poptrie_node_t)(&pop_trie.N);
        pop_trie.D[ip] = pop_trie.N.size - 1;
        poptrie_flatten(raw, pop_trie.D[ip]);
      }
    }
  }
  free_trie(direct_map_trie);
  free_trie(direct_prefix_trie);
}

// Look up the ports of ip in file `ip_to_lookup.txt` using the advanced tree
// input is read from `read_test_data` func
uint32_t *lookup_tree_advance(uint32_t *ip_vec) {
  for (int i = 0; i <= 1; i++) {
    ans[i] = poptrie_lookup(ip_vec[i]);
    printf("%d\n", ans[i]);
  }

  return ans;
}