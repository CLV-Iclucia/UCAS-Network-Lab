#include "tcp_timer.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "tcp.h"
#include "tcp_sock.h"

static struct list_head timer_list;
static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;

static void handle_timewait_timer(struct tcp_timer *timer) {
  // decrease the timeout value
  timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
  if (timer->timeout <= 0) {
    // if timeout is less or equal to zero, the timer has expired
    struct tcp_sock *tsk = timewait_to_tcp_sock(timer);
    if (tsk->state == TCP_TIME_WAIT) {
      // if the tcp_sock is in TIME_WAIT state for 2*MSL, release it
      tcp_set_state(tsk, TCP_CLOSED);
      tcp_unhash(tsk);
    }
    // remove the timer from the timer_list
    list_delete_entry(&timer->list);
  }
}

static void handle_retrans_timeout(struct tcp_sock *tsk) {
  log(DEBUG, "retrans timeout");
  pthread_mutex_lock(&tsk->send_lock);
  if (tsk->retrans_timer.enable == 0) {
    pthread_mutex_unlock(&tsk->send_lock);
    return;
  }
  // popping out the packets of which seq_end <= snd_una
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
    return;
  }
  // run through the send buffer, and retransmit all the packets in it
  struct pending_packet *pos =
      list_entry(tsk->send_buf.next, struct pending_packet, list);
  char *packet = pos->packet;
  if (pos->retrans_times > TCP_MAX_RETRANS) {
    tcp_sock_close(tsk);
    pthread_mutex_unlock(&tsk->send_lock);
    return;
  }
  pos->retrans_times++;
  tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL << pos->retrans_times;
  int packet_len = pos->len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  if (less_than_32b(tsk->snd_una, pos->seq_end)) ip_send_packet(packet, packet_len);
  pthread_mutex_unlock(&tsk->send_lock);
}

static void handle_retrans_timer(struct tcp_timer *timer) {
  // decrease the timeout value
  timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
  if (timer->timeout > 0) return;
  // if timeout is less or equal to zero, the timer has expired
  struct tcp_sock *tsk = retranstimer_to_tcp_sock(timer);
  handle_retrans_timeout(tsk);
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
    else if (pos->type == 1)
      handle_retrans_timer(pos);
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
  if (retrans_timer->enable) {
    pthread_mutex_unlock(&timer_lock);
    return;
  }
  retrans_timer->enable = 1;
  retrans_timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
  list_add_tail(&retrans_timer->list, &timer_list);
  pthread_mutex_unlock(&timer_lock);
}

void tcp_reset_retrans_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *retrans_timer = &tsk->retrans_timer;
  assert(retrans_timer->enable);
  retrans_timer->timeout = TCP_RETRANS_INTERVAL_INITIAL;
  pthread_mutex_unlock(&timer_lock);
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk) {
  pthread_mutex_lock(&timer_lock);
  struct tcp_timer *retrans_timer = &tsk->retrans_timer;
  if (retrans_timer->enable == 0) {
    pthread_mutex_unlock(&timer_lock);
    return;
  }
  retrans_timer->enable = 0;
  list_delete_entry(&retrans_timer->list);
  pthread_mutex_unlock(&timer_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg) {
  init_list_head(&timer_list);
  pthread_mutex_init(&timer_lock, NULL);
  while (1) {
    usleep(TCP_TIMER_SCAN_INTERVAL);
    tcp_scan_timer_list();
  }
  return NULL;
}
