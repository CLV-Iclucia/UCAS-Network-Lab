#include <stdbool.h>
#include <unistd.h>

#include "log.h"
#include "tcp_sock.h"

// tcp server application, listens to port (specified by arg) and serves only
// one connection request

void *tcp_server(void *arg) {
  static char buffer[600000];
  u16 port = *(u16 *)arg;
  struct tcp_sock *tsk = alloc_tcp_sock();

  struct sock_addr addr;
  addr.ip = htonl(0);
  addr.port = port;
  if (tcp_sock_bind(tsk, &addr) < 0) {
    log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
    exit(1);
  }
  if (tcp_sock_listen(tsk, 3) < 0) {
    log(ERROR, "tcp_sock listen failed");
    exit(1);
  }

  log(DEBUG, "listen to port %hu.", ntohs(port));

  struct tcp_sock *csk = tcp_sock_accept(tsk);

  log(DEBUG, "accept a connection.");
  FILE* fp = fopen("server-output.dat", "w+");
  if (fp == NULL) {
    log(ERROR, "cannot open file.");
    return NULL;
  }
  while (true) {
    int valread;
    if ((valread = tcp_sock_read(csk, buffer, 600000)) == 0) {
      printf("Client disconnected\n");
      break;
    }
    if (valread < 0) {
      perror("read failed");
      exit(EXIT_FAILURE);
    }
    fwrite(buffer, sizeof(char), valread, fp);
  }
  fclose(fp);
  tcp_sock_close(csk);
  log(DEBUG, "Transimission finished.");
  return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data
void *tcp_client(void *arg) {
  static char buffer[600000];
  struct sock_addr *skaddr = arg;

  struct tcp_sock *tsk = alloc_tcp_sock();
  log(DEBUG, "try to connect to server (" IP_FMT ":%hu).",
      NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
  if (tcp_sock_connect(tsk, skaddr) < 0) {
    log(ERROR, "tcp_sock connect to server (" IP_FMT ":%hu)failed.",
        NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
    exit(1);
  }

  log(DEBUG, "connecting to server (" IP_FMT ":%hu).",
      NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
  FILE* fp = fopen("client-input.dat", "r");
  if (fp == NULL) {
    log(ERROR, "cannot open file.");
    return NULL;
  }
  int start_time, end_time;
  while (true) {
    int valread;
    if ((valread = fread(buffer, sizeof(char), 600000, fp)) == 0)
      break;
    if (valread < 0) {
      perror("read failed");
      exit(EXIT_FAILURE);
    }
    tcp_sock_write(tsk, buffer, valread);
    sleep(1);
  }
  fclose(fp);
  tcp_sock_close(tsk);
  printf("%d ns", end_time - start_time);
  log(DEBUG, "Transimission finished.");
  return NULL;
}
