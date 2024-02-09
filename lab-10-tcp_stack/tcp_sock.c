#include "tcp_sock.h"

#include "ip.h"
#include "log.h"
#include "rtable.h"
#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_timer.h"
#include "reporter.h"

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table tcp_sock_table.established_table
#define tcp_listen_sock_table tcp_sock_table.listen_table
#define tcp_bind_sock_table tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock* tsk, int state) {
  log(DEBUG, IP_FMT ":%hu switch state, from %s to %s.",
      HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, tcp_state_str[tsk->state],
      tcp_state_str[state]);

  tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack() {
  for (int i = 0; i < TCP_HASH_SIZE; i++)
    init_list_head(&tcp_established_sock_table[i]);

  for (int i = 0; i < TCP_HASH_SIZE; i++)
    init_list_head(&tcp_listen_sock_table[i]);

  for (int i = 0; i < TCP_HASH_SIZE; i++)
    init_list_head(&tcp_bind_sock_table[i]);

  pthread_t timer;
  pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock* alloc_tcp_sock() {
  struct tcp_sock* tsk = malloc(sizeof(struct tcp_sock));

  memset(tsk, 0, sizeof(struct tcp_sock));

  tsk->state = TCP_CLOSED;
  tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

  init_list_head(&tsk->list);
  init_list_head(&tsk->listen_queue);
  init_list_head(&tsk->accept_queue);
  init_list_head(&tsk->send_buf);
  init_list_head(&tsk->rcv_ofo_buf);

  tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);
  tsk->wait_connect = alloc_wait_struct("connect");
  tsk->wait_accept = alloc_wait_struct("accept");
  tsk->wait_recv = alloc_wait_struct("recv");
  tsk->wait_send = alloc_wait_struct("send");
  tsk->retrans_timer.type = 1;
  tsk->cc.state = TCP_CC_SLOW_START;
  tsk->cc.cwnd = TCP_MSS;
  tsk->cc.ssthresh = 0xFFFF;
  report(tsk->cc.cwnd);
  tsk->snd_nxt = tcp_new_iss();
  tsk->no_allowed_to_send = false;
  return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g.
// hashed), the ref_cnt is increased by 1. each time free_tcp_sock is called,
// the ref_cnt is decreased by 1, and release the resources practically if
// ref_cnt is decreased to zero.
void free_tcp_sock(struct tcp_sock* tsk) {
  tsk->ref_cnt--;
  assert(tsk->ref_cnt >= 0);
  if (!tsk->ref_cnt) {
    free_ring_buffer(tsk->rcv_buf);
    free_wait_struct(tsk->wait_connect);
    free_wait_struct(tsk->wait_accept);
    free_wait_struct(tsk->wait_recv);
    free_wait_struct(tsk->wait_send);
    free(tsk);
  }
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock* tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport,
                                             u16 dport) {
  struct tcp_sock* tsk;
  // compute and store hash value so that we don't need to compute it again
  int hash_value = tcp_hash_function(saddr, daddr, sport, dport);
  list_for_each_entry(tsk, &tcp_established_sock_table[hash_value], hash_list) {
    if (tsk->sk_sip == saddr && tsk->sk_dip == daddr &&
        tsk->sk_sport == sport && tsk->sk_dport == dport)
      return tsk;
  }
  return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock* tcp_sock_lookup_listen(u32 saddr, u16 sport) {
  // lookup tcp sock in listen_table with key (sport)
  struct tcp_sock* tsk;
  int hash_value = tcp_hash_function(0, 0, sport, 0);
  list_for_each_entry(tsk, &tcp_listen_sock_table[hash_value], hash_list) {
    if (tsk->sk_sport == sport) return tsk;
  }
  return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock* tcp_sock_lookup(struct tcp_cb* cb) {
  u32 saddr = cb->daddr, daddr = cb->saddr;
  u16 sport = cb->dport, dport = cb->sport;
  struct tcp_sock* tsk =
      tcp_sock_lookup_established(saddr, daddr, sport, dport);
  if (!tsk) tsk = tcp_sock_lookup_listen(saddr, sport);

  return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock* tsk) {
  int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
  struct list_head* list = &tcp_bind_sock_table[bind_hash_value];
  list_add_head(&tsk->bind_hash_list, list);

  tsk->ref_cnt += 1;

  return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock* tsk) {
  if (!list_empty(&tsk->bind_hash_list)) {
    list_delete_entry(&tsk->bind_hash_list);
    free_tcp_sock(tsk);
  }
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport) {
  int value = tcp_hash_function(0, 0, sport, 0);
  struct list_head* list = &tcp_bind_sock_table[value];
  struct tcp_sock* tsk;
  list_for_each_entry(tsk, list, bind_hash_list) {
    if (tsk->sk_sport == sport) return 1;
  }

  return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port() {
  for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
    if (!tcp_port_in_use(port)) return port;
  }

  return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock* tsk, u16 port) {
  if ((port && tcp_port_in_use(port)) || (!port && !(port = tcp_get_port())))
    return -1;

  tsk->sk_sport = port;

  tcp_bind_hash(tsk);

  return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock* tsk) {
  struct list_head* list;
  int hash;

  if (tsk->state == TCP_LISTEN) {
    hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
    log(DEBUG, "hash tcp sock into listen_table, hash value: %d", hash);
    list = &tcp_listen_sock_table[hash];
  } else {
    hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, tsk->sk_sport,
                             tsk->sk_dport);
    list = &tcp_established_sock_table[hash];

    struct tcp_sock* tmp;
    list_for_each_entry(tmp, list, hash_list) {
      if (tsk->sk_sip == tmp->sk_sip && tsk->sk_dip == tmp->sk_dip &&
          tsk->sk_sport == tmp->sk_sport && tsk->sk_dport == tmp->sk_dport)
        return -1;
    }
  }

  list_add_head(&tsk->hash_list, list);
  tsk->ref_cnt += 1;

  return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock* tsk) {
  if (!list_empty(&tsk->hash_list)) {
    list_delete_entry(&tsk->hash_list);
    free_tcp_sock(tsk);
  }
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock* tsk, struct sock_addr* skaddr) {
  int err = 0;

  tcp_set_state(tsk, TCP_CLOSED);
  // omit the ip address, and only bind the port
  err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

  return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock* tsk, struct sock_addr* skaddr) {
  // initialize the four key tuple (sip, sport, dip, dport)
  tsk->sk_sip = ((iface_info_t*)(instance->iface_list.next))->ip;
  tsk->sk_sport = tcp_get_port();
  tsk->sk_dip = ntohl(skaddr->ip);
  tsk->sk_dport = ntohs(skaddr->port);
  // hash the tcp sock into bind_table
  tcp_bind_hash(tsk);
  // send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
  // SYN packet by sleep on wait_connect
  tcp_set_state(tsk, TCP_SYN_SENT);
  tcp_hash(tsk);
  tcp_send_control_packet(tsk, TCP_SYN);
  sleep_on(tsk->wait_connect);
  // if the SYN packet of the peer arrives, this function is notified, which
  // means the connection is established
  if (tsk->state == TCP_ESTABLISHED)
    return 0;
  return -1;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock* tsk, int backlog) {
  tsk->backlog = backlog;

  tcp_set_state(tsk, TCP_LISTEN);
  tcp_hash(tsk);
  return 0;
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock* tsk) {
  if (tsk->accept_backlog >= tsk->backlog) {
    log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
    return 1;
  }
  return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock* tsk) {
  if (!list_empty(&tsk->list)) list_delete_entry(&tsk->list);
  list_add_tail(&tsk->list, &tsk->parent->accept_queue);
  tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock* tcp_sock_accept_dequeue(struct tcp_sock* tsk) {
  struct tcp_sock* new_tsk =
      list_entry(tsk->accept_queue.next, struct tcp_sock, list);
  list_delete_entry(&new_tsk->list);
  init_list_head(&new_tsk->list);
  tsk->accept_backlog--;
  return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock* tcp_sock_accept(struct tcp_sock* tsk) {
  if (list_empty(&tsk->accept_queue)) {
    log(DEBUG, "tcp sock accept queue is empty, sleep on wait_accept.");
    sleep_on(tsk->wait_accept);
  }
  struct tcp_sock* socket = tcp_sock_accept_dequeue(tsk);
  return socket;
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock* tsk) {
  // send FIN packet
  log(DEBUG, "closing tcp sock.");
  switch (tsk->state) {
    case TCP_ESTABLISHED:
      tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
      tcp_set_state(tsk, TCP_FIN_WAIT_1);
      break;
    case TCP_CLOSE_WAIT:
      tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
      tcp_set_state(tsk, TCP_LAST_ACK);
      break;
    case TCP_SYN_RECV:
      tcp_send_control_packet(tsk, TCP_RST);
      tcp_set_state(tsk, TCP_CLOSED);
      wake_up(tsk->wait_connect);
      wake_up(tsk->wait_recv);
      wake_up(tsk->wait_send);
      wake_up(tsk->wait_accept);
      break;
    default:
      log(ERROR, "tcp sock state error.");
      exit(1);
  }
}

// read data from tcp buffer
// returns: 0 if reach the end of file, or the connection is closed
// -1 if error
// otherwise, return the number of bytes read
int tcp_sock_read(struct tcp_sock* tsk, char* buf, int len) {
  int read_len = 0;
  while (is_buffer_empty(tsk->rcv_buf) && tsk->state == TCP_ESTABLISHED) {
    sleep_on(tsk->wait_recv);
    if (tsk->state == TCP_CLOSED) return -1;
  }
  pthread_mutex_lock(&tsk->rcv_buf->lock);
  if (tsk->state == TCP_CLOSE_WAIT && ring_buffer_empty(tsk->rcv_buf)) {
    pthread_mutex_unlock(&tsk->rcv_buf->lock);
    return 0;
  }
  int newly_read_len = read_ring_buffer(tsk->rcv_buf, buf, len);
  log(DEBUG, "read %d bytes from ring buffer", newly_read_len);
  read_len += newly_read_len;
  tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
  tcp_send_control_packet(tsk, TCP_ACK);
  pthread_mutex_unlock(&tsk->rcv_buf->lock);
  return read_len;
}

// returns -1 if error
// otherwise, return the number of bytes written
int tcp_sock_write(struct tcp_sock* tsk, char* buf, int len) {
  int sent_len = 0;
  while (sent_len < len) {
    while ((tsk->snd_wnd == 0 || tsk->no_allowed_to_send) && tsk->state == TCP_ESTABLISHED) {
      sleep_on(tsk->wait_send);
      if (tsk->state == TCP_CLOSED) return -1;
    }
    int packets_allowed_to_send = tsk->snd_wnd / TCP_MSS - inflight(tsk);
    if (packets_allowed_to_send < 0) packets_allowed_to_send = 0;
    log(DEBUG, "sending window: %d, inflight: %d, packets allowed to send: %d",
        tsk->snd_wnd, inflight(tsk), packets_allowed_to_send);
    if (packets_allowed_to_send == 0) {
      tsk->no_allowed_to_send = true;
      continue;
    }
    int send_len = min(tsk->snd_una + tsk->snd_wnd - tsk->snd_nxt, len - sent_len);
	while (!send_len && tsk->state == TCP_ESTABLISHED) {
		sleep_on(tsk->wait_send);
		if (tsk->state == TCP_CLOSED) return -1;
		send_len = min(tsk->snd_una + tsk->snd_wnd - tsk->snd_nxt, len - sent_len);
		if (len == sent_len) return sent_len;
	}
    send_len = min(
        send_len, 1514 - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE);
    char* packet_buf = malloc(send_len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE +
                              TCP_BASE_HDR_SIZE);
    char* data =
        packet_buf + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
    memcpy(data, buf + sent_len, send_len);
    tcp_send_packet(
        tsk, packet_buf,
        send_len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE, true);
    sent_len += send_len;
  }
  return len;
}