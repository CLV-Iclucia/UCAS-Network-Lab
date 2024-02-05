#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "reporter.h"
#include "ring_buffer.h"
#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb) {
  u16 old_snd_wnd = tsk->snd_wnd;
  tsk->snd_wnd = min(cb->rwnd, tsk->cc.cwnd);
  if (less_than_32b(tsk->snd_una, cb->ack))
    tsk->snd_una = cb->ack;
  // if (tsk->snd_wnd > old_snd_wnd)
  //   tcp_reset_retrans_timer(tsk);
  if (old_snd_wnd == 0) {
    wake_up(tsk->wait_send);
  }
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk,
                                          struct tcp_cb *cb) {
  if (less_or_equal_32b(tsk->snd_una, cb->ack) &&
      less_or_equal_32b(cb->ack, tsk->snd_nxt))
    tcp_update_window(tsk, cb);
}

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb) {
  u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
  if (less_than_32b(cb->seq, rcv_end) &&
      less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
    return 1;
  }
  return 0;
}

static void free_ofo_packet(struct tcp_ofo_packet *ofo_packet) {
  free(ofo_packet->packet);
  free(ofo_packet);
}

static void insert_ofo_packet(struct tcp_ofo_packet *ofo_packet,
                              struct list_head *pending_queue) {
  // run through the pending queue and insert the ofo_packet in the right place
  // so that the seqs of ofo_packects in pending_queue are in increasing order
  struct tcp_ofo_packet *ofo_packet_iter;
  list_for_each_entry(ofo_packet_iter, pending_queue, list) {
    if (ofo_packet_iter->cb.seq <= ofo_packet->cb.seq)
      continue;
    list_add_tail(&ofo_packet->list, &ofo_packet_iter->list);
    return;
  }
  // ofo_packet->cb.seq is greater than any ofo packet in pending queue
  // insert it at the tail
  list_add_tail(&ofo_packet->list, pending_queue);
}

static void prepare_for_close(struct tcp_sock *tsk) {
  tcp_unset_retrans_timer(tsk);
  tcp_send_control_packet(tsk, TCP_ACK);
  tcp_set_state(tsk, TCP_CLOSE_WAIT);
  wake_up(tsk->wait_recv);
  wake_up(tsk->wait_send);
  wake_up(tsk->wait_accept);
}

static void tcp_fast_retransmit(struct tcp_sock *tsk) {
  tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
  tsk->cc.cwnd = tsk->cc.ssthresh;
}

void retrans_pending_packet(struct tcp_sock *tsk, struct pending_packet *pp) {
  int packet_len =
      pp->len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  assert(less_than_32b(tsk->snd_una, pp->seq_end));
  log(DEBUG, "retrans packet, seq: %d, seq_end: %d", pp->seq, pp->seq_end);
  log(DEBUG, "retrans timeout is now set to %d", tsk->retrans_timer.timeout);
  // note that we should not call ip_send_packet here because it will free the
  // packet
  char *packet = pp->packet;
  pp->packet = move_and_ip_send_packet(packet, packet_len);
}

void tcp_cc_handle_new_ack(struct tcp_sock *tsk) {
  pthread_mutex_lock(&tsk->cc.lock);
  tsk->cc.dup_cnt = 0;
  switch (tsk->cc.state) {
  case TCP_CC_SLOW_START:
    if (tsk->cc.cwnd <= tsk->cc.ssthresh) {
      tsk->cc.cwnd <<= 1;
      report(tsk->cc.cwnd);
    } else {
      tsk->cc.state = TCP_CC_CONGESTION_AVOIDANCE;
    }
    break;
  case TCP_CC_CONGESTION_AVOIDANCE:
    tsk->cc.cwnd += TCP_MSS;
    report(tsk->cc.cwnd);
    break;
  case TCP_CC_FAST_RECOVERY:
    // if is partial ack, retrans the following packet
    if (tsk->snd_una < tsk->cc.rp) {
      // it is partial ack
      // retrans packet from snd_una to rp
      struct pending_packet *pos, *q;
      list_for_each_entry_safe(pos, q, &tsk->send_buf, list) {
        if (less_or_equal_32b(tsk->snd_una, pos->seq_end) &&
            less_than_32b(pos->seq_end, tsk->cc.rp))
          retrans_pending_packet(tsk, pos);
      }
    } else {
      tsk->cc.cwnd = tsk->cc.ssthresh;
      tsk->cc.state = TCP_CC_CONGESTION_AVOIDANCE;
      report(tsk->cc.cwnd);
    }
    break;
  default:
    log(ERROR, "unknown cc state");
  }
  pthread_mutex_unlock(&tsk->cc.lock);
}

void tcp_cc_handle_dup_ack(struct tcp_sock *tsk) {
  pthread_mutex_lock(&tsk->cc.lock);
  tsk->cc.dup_cnt++;
  switch (tsk->cc.state) {
  case TCP_CC_SLOW_START:
    if (tsk->cc.dup_cnt >= 3) {
      tcp_fast_retransmit(tsk);
      tsk->cc.rp = tsk->snd_nxt;
      tsk->cc.state = TCP_CC_FAST_RECOVERY;
      tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
      tsk->cc.cwnd = tsk->cc.ssthresh + 3 * TCP_MSS;
    }
    report(tsk->cc.cwnd);
    break;
  case TCP_CC_CONGESTION_AVOIDANCE:
    if (tsk->cc.dup_cnt >= 3) {
      tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
      tsk->cc.cwnd = tsk->cc.ssthresh + 3 * TCP_MSS;
      tcp_fast_retransmit(tsk);
      tsk->cc.state = TCP_CC_FAST_RECOVERY;
    }
    report(tsk->cc.cwnd);
    break;
  case TCP_CC_FAST_RECOVERY:
    tsk->cc.cwnd += TCP_MSS;
    report(tsk->cc.cwnd);
    break;
  default:
    log(ERROR, "unknown cc state");
  }
  pthread_mutex_unlock(&tsk->cc.lock);
}
static void ack_packet(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
  char *data = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  log(DEBUG, "ack data packet, seq %d, ack: %d", cb->seq, cb->ack);
  int data_len = cb->pl_len;
  // handle the case of ack in different state
  switch (tsk->state) {
  case TCP_SYN_RECV:
    tsk->snd_una = cb->ack;
    tsk->rcv_nxt = cb->seq_end;
    tcp_set_state(tsk, TCP_ESTABLISHED);
    tcp_hash(tsk);
    // add to the accept queue of parent socket
    tcp_sock_accept_enqueue(tsk);
    wake_up(tsk->parent->wait_accept);
    break;
  case TCP_FIN_WAIT_1:
    tsk->rcv_nxt = cb->seq_end;
    tcp_set_state(tsk, TCP_FIN_WAIT_2);
    break;
  case TCP_SYN_SENT:
    tsk->rcv_nxt = cb->seq_end;
    break;
  case TCP_CLOSING:
    tcp_set_state(tsk, TCP_TIME_WAIT);
    tcp_set_timewait_timer(tsk);
    break;
  case TCP_LAST_ACK:
    tcp_set_state(tsk, TCP_CLOSED);
    break;
  default:
    break;
  }
  bool old_no_allowed = tsk->no_allowed_to_send;
  tcp_cc_handle_new_ack(tsk);
  tcp_update_window_safe(tsk, cb);
  int send_able = tsk->snd_wnd / TCP_MSS - inflight(tsk);
  int packet_allowed_to_send = max(send_able, 0);
  if (packet_allowed_to_send > 0 && old_no_allowed) {
    log(DEBUG, "allowed to send, wake up sending");
    tsk->no_allowed_to_send = false;
    wake_up(tsk->wait_send);
  }
  tcp_try_update_retrans_timer(tsk);
  if (tsk->snd_una == tsk->snd_nxt) {
    log(DEBUG, "all acked, unset retrans timer");
    tcp_unset_retrans_timer(tsk);
  }
  int offset = tsk->rcv_nxt - cb->seq;
  data_len -= offset;
  if (data_len > 0) {
    pthread_mutex_lock(&tsk->rcv_buf->lock);
    log(DEBUG, "write data to rcv_buf, offset: %d, data_len: %d", offset,
        data_len);
    bool old_empty = ring_buffer_empty(tsk->rcv_buf);
    write_ring_buffer(tsk->rcv_buf, data + offset, data_len);
    tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
    tsk->rcv_nxt = cb->seq_end;
    if (old_empty && !ring_buffer_empty(tsk->rcv_buf)) {
      log(DEBUG, "buffer is not empty, wake up receiving");
      wake_up(tsk->wait_recv);
    }
    log(DEBUG, "write data to rcv_buf succeeded, rcv_wnd: %d", tsk->rcv_wnd);
    pthread_mutex_unlock(&tsk->rcv_buf->lock);
  }
}

static void ack_ofo_packets(struct tcp_sock *tsk) {
  while (!list_empty(&tsk->rcv_ofo_buf)) {
    struct tcp_ofo_packet *ofo_packet_iter =
        list_entry(tsk->rcv_ofo_buf.next, struct tcp_ofo_packet, list);
    if (ofo_packet_iter->cb.seq > tsk->rcv_nxt)
      break;
    if (ofo_packet_iter->cb.seq_end >= tsk->rcv_nxt) {
      log(DEBUG, "ack ofo packet, seq: %d, ack: %d", ofo_packet_iter->cb.seq,
          ofo_packet_iter->cb.ack);
      ack_packet(tsk, &ofo_packet_iter->cb, ofo_packet_iter->packet);
    }
    struct tcp_ofo_packet *ofo_packet_iter_q = ofo_packet_iter;
    ofo_packet_iter =
        list_entry(ofo_packet_iter->list.next, struct tcp_ofo_packet, list);
    list_delete_entry(&ofo_packet_iter_q->list);
    free_ofo_packet(ofo_packet_iter_q);
  }
}

static void pend_ofo_packet(struct tcp_sock *tsk, struct tcp_cb *cb,
                            char *packet) {
  assert(cb->seq > tsk->rcv_nxt);
  log(DEBUG, "pend packet, seq: %d, ack: %d", cb->seq, cb->ack);
  struct tcp_ofo_packet *ofo_packet = malloc(sizeof(struct tcp_ofo_packet));
  int packet_len =
      cb->pl_len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  ofo_packet->packet = malloc(packet_len);
  memcpy(ofo_packet->packet, packet, packet_len);
  memcpy(&ofo_packet->cb, cb, sizeof(struct tcp_cb));
  insert_ofo_packet(ofo_packet, &tsk->rcv_ofo_buf);
}

// if seq_end <= ack, remove it from the send buffer
static void update_send_buffer(struct tcp_sock *tsk, struct tcp_cb *cb) {
  pthread_mutex_lock(&tsk->send_lock);
  struct pending_packet *pos, *q;
  list_for_each_entry_safe(pos, q, &tsk->send_buf, list) {
    if (less_than_32b(cb->ack, pos->seq_end))
      break;
    list_delete_entry(&pos->list);
    free(pos->packet);
    free(pos);
  }
  pthread_mutex_unlock(&tsk->send_lock);
}

static void tcp_handle_ack(struct tcp_sock *tsk, struct tcp_cb *cb,
                           char *packet) {
  assert(cb->flags & TCP_ACK);
  update_send_buffer(tsk, cb);
  if (!is_tcp_seq_valid(tsk, cb)) {
    log(DEBUG, "received packet with invalid seq, drop it.");
    return;
  }
  log(DEBUG, "receive seq: %d, current expected rcv_nxt: %d", cb->seq,
      tsk->rcv_nxt);
  if (less_than_32b(cb->seq, tsk->rcv_nxt) &&
      less_or_equal_32b(cb->seq_end, tsk->rcv_nxt)) {
    log(DEBUG, "receive outdated packet, send ack.");
    tcp_cc_handle_dup_ack(tsk);
    tcp_send_control_packet(tsk, TCP_ACK);
    return;
  }
  if (less_or_equal_32b(cb->seq, tsk->rcv_nxt)) {
    tsk->snd_una = cb->ack;
    ack_packet(tsk, cb, packet);
    ack_ofo_packets(tsk);
  } else
    pend_ofo_packet(tsk, cb, packet);
}

static void tcp_handle_syn(struct tcp_sock *tsk, struct tcp_cb *cb,
                           char *packet) {
  assert(cb->flags & TCP_SYN);
  if (tsk->state == TCP_LISTEN) {
    struct tcp_sock *csk = tcp_sock_lookup(cb);
    if (csk != tsk) {
      retrans_packet(csk);
      return;
    }
    csk = alloc_tcp_sock();
    csk->sk_sip = cb->daddr;
    csk->sk_sport = cb->dport;
    csk->sk_dip = cb->saddr;
    csk->sk_dport = cb->sport;
    csk->parent = tsk;
    csk->rcv_nxt = cb->seq_end;
    csk->iss = tcp_new_iss();
    csk->snd_nxt = csk->iss;
    csk->snd_una = csk->iss;
    csk->rcv_wnd = TCP_DEFAULT_WINDOW;
    csk->snd_wnd = cb->rwnd;
    csk->cc.state = TCP_CC_SLOW_START;
    csk->cc.cwnd = TCP_MSS;
    csk->cc.ssthresh = 65535;
    csk->cc.dup_cnt = 0;
    report(csk->cc.cwnd);
    tcp_set_state(csk, TCP_SYN_RECV);
    tcp_hash(csk);
    tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
    list_add_tail(&csk->list, &tsk->listen_queue);
    return;
  }
  if (tsk->state == TCP_SYN_SENT) {
    tcp_set_state(tsk, TCP_ESTABLISHED);
    tcp_hash(tsk);
    tcp_send_control_packet(tsk, TCP_ACK);
    wake_up(tsk->wait_connect);
  } else
    log(ERROR, "received unexpected packet, drop it.");
}

static void tcp_handle_fin(struct tcp_sock *tsk, struct tcp_cb *cb,
                           char *packet) {
  assert(cb->flags & TCP_FIN);
  if (less_than_32b(cb->seq, tsk->rcv_nxt) && !(cb->flags & TCP_ACK)) {
    retrans_packet(tsk);
    if (tsk->state == TCP_CLOSE_WAIT) {
      wake_up(tsk->wait_connect);
      wake_up(tsk->wait_recv);
      wake_up(tsk->wait_send);
      wake_up(tsk->wait_accept);
    }
    return;
  }
  if (tsk->state == TCP_ESTABLISHED) {
    if (!is_tcp_seq_valid(tsk, cb))
      return;
    if (less_than_32b(tsk->rcv_nxt, cb->seq))
      return;
    tsk->rcv_nxt = cb->seq_end;
    tcp_send_control_packet(tsk, TCP_ACK);
    tcp_set_state(tsk, TCP_CLOSE_WAIT);
    wake_up(tsk->wait_connect);
    wake_up(tsk->wait_recv);
    wake_up(tsk->wait_send);
    wake_up(tsk->wait_accept);
  } else if (tsk->state == TCP_FIN_WAIT_1) {
    tsk->rcv_nxt = cb->seq_end;
    tcp_send_control_packet(tsk, TCP_ACK);
    tcp_set_state(tsk, TCP_CLOSING);
  } else if (tsk->state == TCP_FIN_WAIT_2) {
    tsk->rcv_nxt = cb->seq_end;
    tcp_send_control_packet(tsk, TCP_ACK);
    tcp_set_state(tsk, TCP_TIME_WAIT);
    tcp_set_timewait_timer(tsk);
  } else if (tsk->state == TCP_LAST_ACK) {
    tsk->rcv_nxt = cb->seq_end;
    tcp_send_control_packet(tsk, TCP_ACK);
    tcp_set_state(tsk, TCP_CLOSED);
    tcp_unhash(tsk);
  } else
    log(ERROR, "received unexpected packet, drop it.");
}

const char *tcp_flags_str(u8 flags) {
  static char str[512];
  memset(str, 0, 512);
  tcp_copy_flags_to_str(flags, str);
  return str;
}

// Process the incoming packet according to TCP state machine.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
  assert(tsk);
  log(DEBUG,
      "handle tcp packet: flags = %s, socket state = %s, ack = %d, seq = %d, "
      "rwnd = %d",
      tcp_flags_str(cb->flags), tcp_state_str[tsk->state], cb->ack, cb->seq,
      cb->rwnd);
  if (cb->flags & TCP_RST) {
    tcp_sock_close(tsk);
    return;
  }

  if (cb->flags & TCP_ACK)
    tcp_handle_ack(tsk, cb, packet);
  if (cb->flags & TCP_SYN)
    tcp_handle_syn(tsk, cb, packet);
  if (cb->flags & TCP_FIN)
    tcp_handle_fin(tsk, cb, packet);
}
