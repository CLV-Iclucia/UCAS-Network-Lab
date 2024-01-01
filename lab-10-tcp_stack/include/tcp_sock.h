#ifndef __TCP_SOCK_H__
#define __TCP_SOCK_H__

#include <pthread.h>

#include "list.h"
#include "ring_buffer.h"
#include "synch_wait.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "types.h"

#define PORT_MIN 12345
#define PORT_MAX 23456

struct sock_addr {
  u32 ip;
  u16 port;
} __attribute__((packed));

// the main structure that manages a connection locally
struct tcp_sock {
  // sk_ip, sk_sport, sk_sip, sk_dport are the 4-tuple that represents a
  // connection
  struct sock_addr local;
  struct sock_addr peer;
#define sk_sip local.ip
#define sk_sport local.port
#define sk_dip peer.ip
#define sk_dport peer.port

  // pointer to parent tcp sock, a tcp sock which bind and listen to a port
  // is the parent of tcp socks when *accept* a connection request
  struct tcp_sock *parent;

  // represents the number that the tcp sock is referred, if this number
  // decreased wato zero, the tcp sock should be released
  int ref_cnt;

  // hash_list is used to hash tcp sock into listen_table or established_table,
  // bind_hash_list is used to hash into bind_table
  struct list_head hash_list;
  struct list_head bind_hash_list;

  // when a passively opened tcp sock receives a SYN packet, it mallocs a child
  // tcp sock to serve the incoming connection, which is pending in the
  // listen_queue of parent tcp sock
  struct list_head listen_queue;
  // when receiving the last packet (ACK) of the 3-way handshake, the tcp sock
  // in listen_queue will be moved into accept_queue, waiting for *accept* by
  // parent tcp sock
  struct list_head accept_queue;

#define TCP_MAX_BACKLOG 128
  // the number of pending tcp sock in accept_queue
  int accept_backlog;
  // the maximum number of pending tcp sock in accept_queue
  int backlog;

  // the list node used to link listen_queue or accept_queue of parent tcp sock
  struct list_head list;
  // tcp timer used during TCP_TIME_WAIT state
  struct tcp_timer timewait;

  // used for timeout retransmission
  struct tcp_timer retrans_timer;

  // synch waiting structure of *connect*, *accept*, *recv*, and *send*
  struct synch_wait *wait_connect;
  struct synch_wait *wait_accept;
  struct synch_wait *wait_recv;
  struct synch_wait *wait_send;

  // receiving buffer
  struct ring_buffer *rcv_buf;
  // used to pend unacked packets
  struct list_head send_buf;
  // used to pend out-of-order packets
  struct list_head rcv_ofo_buf;
  pthread_mutex_t send_lock;
  // tcp state, see enum tcp_state in tcp.h
  int state;

  // initial sending sequence number
  u32 iss;

  // the highest byte that is ACKed by peer
  u32 snd_una;
  // the highest byte sent
  u32 snd_nxt;

  // the highest byte ACKed by itself (i.e. the byte expected to receive next)
  u32 rcv_nxt;

  // used to indicate the end of fast recovery
  u32 recovery_point;

  // min(adv_wnd, cwnd)
  u32 snd_wnd;
  // the receiving window advertised by peer
  u32 adv_wnd;

  // the size of receiving window (advertised by tcp sock itself)
  u16 rcv_wnd;

  // congestion window
  u32 cwnd;

  // slow start threshold
  u32 ssthresh;
};

struct tcp_ofo_packet {
  struct list_head list;
  struct tcp_cb cb;
  char *packet;
};

struct pending_packet {
  struct list_head list;
  char *packet;
  bool is_data_pack;
  int retrans_times;
  int seq, seq_end, len;
};


// initialize tcp header according to the arguments
static inline void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq,
                         u32 ack, u8 flags, u16 rwnd) {
  memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

  tcp->sport = htons(sport);
  tcp->dport = htons(dport);
  tcp->seq = htonl(seq);
  tcp->ack = htonl(ack);
  tcp->off = TCP_HDR_OFFSET;
  tcp->flags = flags;
  tcp->rwnd = htons(rwnd);
}

static inline struct pending_packet *alloc_pending_packet(char *packet, int seq,
                                                   int seq_end) {
  struct pending_packet *pp = malloc(sizeof(struct pending_packet));
  pp->packet = packet;
  pp->seq = seq;
  pp->seq_end = seq_end;
  pp->retrans_times = 0;
  pp->list.next = pp->list.prev = &pp->list;
  return pp;
}

static inline void insert_data_send_buffer(struct tcp_sock *tsk, char *packet,
                                            int len) {
  pthread_mutex_lock(&tsk->send_lock);
  struct pending_packet *pp = malloc(sizeof(struct pending_packet));
  int packet_len = len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  assert(len);
  pp->len = len;
  pp->packet = malloc(packet_len);
  memcpy(pp->packet, packet, packet_len);
  pp->is_data_pack = true;
  pp->retrans_times = 0;
  struct tcphdr *tcp = packet_to_tcp_hdr(packet);
  pp->seq = ntohl(tcp->seq);
  pp->seq_end = pp->seq + len + ((tcp->flags & (TCP_SYN | TCP_FIN)) ? 1 : 0);
  pp->list.next = pp->list.prev = &pp->list;
  list_add_tail(&pp->list, &tsk->send_buf);
  pthread_mutex_unlock(&tsk->send_lock);
}

static inline void insert_control_send_buffer(struct tcp_sock* tsk, char *packet, int packet_len) {
  pthread_mutex_lock(&tsk->send_lock);
  struct pending_packet *pp = malloc(sizeof(struct pending_packet));
  pp->packet = malloc(packet_len);
  pp->list.next = pp->list.prev = &pp->list;
  memcpy(pp->packet, packet, packet_len);
  pp->is_data_pack = false;
  pp->retrans_times = 0;
  struct tcphdr *tcp = packet_to_tcp_hdr(packet);
  pp->seq = ntohl(tcp->seq);
  pp->seq_end = pp->seq + ((tcp->flags & (TCP_SYN | TCP_FIN)) ? 1 : 0);
  list_add_tail(&pp->list, &tsk->send_buf);
  log(DEBUG, "add packet to buffer, seq = %d, seq_end = %d", pp->seq, pp->seq_end);
  pthread_mutex_unlock(&tsk->send_lock);
}

void tcp_set_state(struct tcp_sock *tsk, int state);

int tcp_sock_accept_queue_full(struct tcp_sock *tsk);
void tcp_sock_accept_enqueue(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk);

int tcp_hash(struct tcp_sock *tsk);
void tcp_unhash(struct tcp_sock *tsk);
void tcp_bind_unhash(struct tcp_sock *tsk);
struct tcp_sock *alloc_tcp_sock();
void free_tcp_sock(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb);

u32 tcp_new_iss();

void tcp_send_reset(struct tcp_cb *cb);

void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags, bool prep_for_retrans);
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len,
                     bool initial_trans);
// seq = snd_nxt, ack = rcv_nxt, rwnd = rcv_wnd
int tcp_send_data(struct tcp_sock *tsk, char *buf, int len);

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);

void init_tcp_stack();

int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr);
int tcp_sock_listen(struct tcp_sock *tsk, int backlog);
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr);
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk);
void tcp_sock_close(struct tcp_sock *tsk);

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len);
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len);

// retrans the first packet of tsk->send_buf
static inline void retrans_packet(struct tcp_sock* tsk) {
  pthread_mutex_lock(&tsk->send_lock);
  assert(!list_empty(&tsk->send_buf));
  if (list_empty(&tsk->send_buf)) {
    pthread_mutex_unlock(&tsk->send_lock);
    return;
  }
  struct pending_packet* pos =
      list_entry(tsk->send_buf.next, struct pending_packet, list);
  char* packet = pos->packet;
  int packet_len = pos->len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE +
                   TCP_BASE_HDR_SIZE;
  ip_send_packet(packet, packet_len);
  pthread_mutex_unlock(&tsk->send_lock);
}
#endif
