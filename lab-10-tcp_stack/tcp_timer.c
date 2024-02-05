#include "tcp_timer.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "tcp.h"
#include "tcp_sock.h"

#include <reporter.h>

static struct list_head timer_list;
static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;

void tcp_cc_handle_rto(struct tcp_sock *tsk) {
  pthread_mutex_lock(&tsk->cc.lock);
  tsk->cc.dup_cnt = 0;
  switch(tsk->cc.state) {
    case TCP_CC_SLOW_START:
      tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
      tsk->cc.cwnd = TCP_MSS;
      report(tsk->cc.cwnd);
      break;
    case TCP_CC_CONGESTION_AVOIDANCE:
      tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
      tsk->cc.cwnd = TCP_MSS;
      tsk->cc.state = TCP_CC_SLOW_START;
      report(tsk->cc.cwnd);
      break;
    case TCP_CC_FAST_RECOVERY:
      tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
      tsk->cc.cwnd = TCP_MSS;
      tsk->cc.state = TCP_CC_SLOW_START;
      report(tsk->cc.cwnd);
      break;
    default:
      log(DEBUG, "Unknown cc state");
  }
  pthread_mutex_unlock(&tsk->cc.lock);
}

static void handle_timewait_timer(struct tcp_timer *timer) {
  // decrease the timeout value
  timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
  if (timer->timeout > 0)
    return;
  struct tcp_sock *tsk = timewait_to_tcp_sock(timer);
  if (tsk->state == TCP_TIME_WAIT) {
    tcp_set_state(tsk, TCP_CLOSED);
    tcp_unhash(tsk);
  }
  list_delete_entry(&timer->list);
}

static void tcp_terminate(struct tcp_sock *tsk) {
  struct tcp_cb cb;
  cb.saddr = tsk->sk_sip;
  cb.daddr = tsk->sk_dip;
  cb.sport = tsk->sk_sport;
  cb.dport = tsk->sk_dport;
  cb.seq_end = tsk->snd_nxt;
  tcp_send_reset(&cb);
}

// do not delete timer from the list here!
static bool handle_retrans_timeout(struct tcp_sock *tsk) {
  log(DEBUG, "retrans timeout");
  pthread_mutex_lock(&tsk->send_lock);
  // popping out the packets of which seq_end <= snd_una
  log(DEBUG, "current snd_una: %d", tsk->snd_una);
  while (!list_empty(&tsk->send_buf)) {
    struct pending_packet *pos =
        list_entry(tsk->send_buf.next, struct pending_packet, list);
    if (less_or_equal_32b(pos->seq_end, tsk->snd_una)) {
      list_delete_entry(&pos->list);
      free(pos->packet);
      free(pos);
    } else
      break;
  }
  if (list_empty(&tsk->send_buf)) {
    pthread_mutex_unlock(&tsk->send_lock);
    return true;
  }
  // run through the send buffer, and retransmit all the packets in it
  struct pending_packet *pos =
      list_entry(tsk->send_buf.next, struct pending_packet, list);
  char *packet = pos->packet;
  if (pos->retrans_times > TCP_MAX_RETRANS) {
    log(DEBUG, "max retrans times reached, terminate connection");
    tcp_terminate(tsk);
    pthread_mutex_unlock(&tsk->send_lock);
    return true;
  }
  pos->retrans_times++;
  tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL
                               << pos->retrans_times;
  tsk->cc.ssthresh = tsk->cc.cwnd >> 1;
  tsk->cc.cwnd = TCP_MSS;
  retrans_pending_packet(tsk, pos);
  pthread_mutex_unlock(&tsk->send_lock);
  return false;
}

static void handle_retrans_timer(struct tcp_timer *timer) {
  // decrease the timeout value
  timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
  assert(timer->type == 1 && timer->enable);
  log(DEBUG, "handle retrans timer, timeout: %d", timer->timeout);
  if (timer->timeout > 0)
    return;
  // if timeout is less or equal to zero, the timer has expired
  struct tcp_sock *tsk = retranstimer_to_tcp_sock(timer);
  bool needs_unset = handle_retrans_timeout(tsk);
  if (!needs_unset) return ;
  log(DEBUG, "unset retrans timer");
  timer->enable = 0;
  list_delete_entry(&timer->list);
}

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list() {
  struct tcp_timer *pos, *q;
  // iterate over the timer_list
  pthread_mutex_lock(&timer_lock);
  list_for_each_entry_safe(pos, q, &timer_list, list) {
    if (pos->type == 0)
      handle_timewait_timer(pos);
    else if (pos->type == 1) {
      assert(pos->enable == 1);
      handle_retrans_timer(pos);
    }
    else
      log(ERROR, "Unknown timer type %d", pos->type);
  }
  pthread_mutex_unlock(&timer_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *timewait_timer = &tsk->timewait;
  timewait_timer->type = 0;
  timewait_timer->timeout = TCP_TIMEWAIT_TIMEOUT;
  timewait_timer->enable = 1;
  list_add_tail(&timewait_timer->list, &timer_list);
  pthread_mutex_unlock(&timer_lock);
}

void tcp_set_retrans_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *retrans_timer = &tsk->retrans_timer;
  assert(retrans_timer->type == 1);
  if (retrans_timer->enable) {
    pthread_mutex_unlock(&timer_lock);
    return;
  }
  log(DEBUG, "set retrans timer");
  retrans_timer->enable = 1;
  retrans_timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
  list_add_tail(&retrans_timer->list, &timer_list);
  pthread_mutex_unlock(&timer_lock);
}

void tcp_try_update_retrans_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *retrans_timer = &tsk->retrans_timer;
  assert(retrans_timer->type == 1);
  if (retrans_timer->enable == 0) {
    pthread_mutex_unlock(&timer_lock);
    return;
  }
  log(DEBUG, "try update retrans timer");
  retrans_timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
  log(DEBUG, "retrans timeout is reset");
  pthread_mutex_unlock(&timer_lock);
}

void tcp_reset_retrans_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *retrans_timer = &tsk->retrans_timer;
  assert(retrans_timer->enable);
  assert(retrans_timer->type == 1);
  log(DEBUG, "reset retrans timer");
  retrans_timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
  pthread_mutex_unlock(&timer_lock);
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *retrans_timer = &tsk->retrans_timer;
  assert(retrans_timer->type == 1);
  if (retrans_timer->enable == 0) {
    pthread_mutex_unlock(&timer_lock);
    return;
  }
  log(DEBUG, "unset retrans timer");
  retrans_timer->enable = 0;
  list_delete_entry(&retrans_timer->list);
  pthread_mutex_unlock(&timer_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg) {
  init_list_head(&timer_list);
  pthread_mutex_init(&timer_lock, NULL);
  log(DEBUG, "timer thread start");
  while (1) {
    usleep(TCP_TIMER_SCAN_INTERVAL);
    tcp_scan_timer_list();
  }
  return NULL;
}
