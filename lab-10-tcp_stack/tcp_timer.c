#include "tcp_timer.h"

#include <stdio.h>
#include <unistd.h>

#include "tcp.h"
#include "tcp_sock.h"
#include <pthread.h>

static struct list_head timer_list;
static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list() {
  struct tcp_timer *pos, *q;
  // iterate over the timer_list
  pthread_mutex_lock(&timer_lock);
  list_for_each_entry_safe(pos, q, &timer_list, list) {
    // decrease the timeout value
    pos->timeout -= TCP_TIMER_SCAN_INTERVAL;
    if (pos->timeout <= 0) {
      // if timeout is less or equal to zero, the timer has expired
      struct tcp_sock *tsk = timewait_to_tcp_sock(pos);
      if (tsk->state == TCP_TIME_WAIT) {
        // if the tcp_sock is in TIME_WAIT state for 2*MSL, release it
        tcp_set_state(tsk, TCP_CLOSED);
        tcp_unhash(tsk);
      }
      // remove the timer from the timer_list
      list_delete_entry(&pos->list);
    }
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
