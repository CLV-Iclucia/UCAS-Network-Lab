#include <stdlib.h>
#include <string.h>

#include "ether.h"
#include "ip.h"
#include "list.h"
#include "log.h"
#include "tcp.h"
#include "tcp_sock.h"

// send a tcp packet
//
// Given that the payload of the tcp packet has been filled, initialize the tcp
// header and ip header (remember to set the checksum in both header), and emit
// the packet by calling ip_send_packet.
// seq = snd_nxt, ack = rcv_nxt, rwnd = rcv_wnd
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len,
                     bool prep_for_retrans) {
  struct iphdr *ip = packet_to_ip_hdr(packet);
  struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

  int ip_tot_len = len - ETHER_HDR_SIZE;
  int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

  u32 saddr = tsk->sk_sip;
  u32 daddr = tsk->sk_dip;
  u16 sport = tsk->sk_sport;
  u16 dport = tsk->sk_dport;

  u32 seq = tsk->snd_nxt;
  u32 ack = tsk->rcv_nxt;
  u16 rwnd = tsk->rcv_wnd;
  tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH | TCP_ACK, rwnd);
  ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP);
  tcp->checksum = tcp_checksum(ip, tcp);

  ip->checksum = ip_checksum(ip);
  log(DEBUG,
      "send packet, flags: %s, seq: %d, ack: %d, len: %d, current sending "
      "window: %d",
      tcp_flags_str(tcp->flags), seq, ack, tcp_data_len, tsk->snd_wnd);
  if (prep_for_retrans) {
    insert_data_send_buffer(tsk, packet, tcp_data_len);
    tsk->snd_nxt += tcp_data_len;
    tcp_set_retrans_timer(tsk);
  }
  ip_send_packet(packet, len);
}

// send a tcp control packet
//
// The control packet is like TCP_ACK, TCP_SYN, TCP_FIN (excluding TCP_RST).
// All these packets do not have payload and the only difference among these is
// the flags.
// seq = snd_nxt, ack = rcv_nxt, rwnd = rcv_wnd
void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags) {
  assert(tsk->retrans_timer.type == 1);
  int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  char *packet = malloc(pkt_size);
  if (!packet) {
    log(ERROR, "malloc tcp control packet failed.");
    return;
  }

  struct iphdr *ip = packet_to_ip_hdr(packet);
  struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

  u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

  ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);
  tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, tsk->snd_nxt, tsk->rcv_nxt,
               flags, tsk->rcv_wnd);
  tcp->checksum = tcp_checksum(ip, tcp);
  log(DEBUG,
      "send control packet, flags: %s, seq: %d, ack: %d, rwnd: %d, current "
      "sending window: %d",
      tcp_flags_str(flags), tsk->snd_nxt, tsk->rcv_nxt, tsk->rcv_wnd,
      tsk->snd_wnd);
  if (flags & (TCP_SYN | TCP_FIN)) {
    insert_control_send_buffer(tsk, packet, pkt_size);
    tsk->snd_nxt += 1;
    tcp_set_retrans_timer(tsk);
  }
  ip_send_packet(packet, pkt_size);
}

// send tcp reset packet
// Different from tcp_send_control_packet, the fields of reset packet is
// from tcp_cb instead of tcp_sock.
void tcp_send_reset(struct tcp_cb *cb) {
  int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  char *packet = malloc(pkt_size);
  if (!packet) {
    log(ERROR, "malloc tcp control packet failed.");
    return;
  }

  struct iphdr *ip = packet_to_ip_hdr(packet);
  struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

  u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
  ip_init_hdr(ip, cb->daddr, cb->saddr, tot_len, IPPROTO_TCP);
  tcp_init_hdr(tcp, cb->dport, cb->sport, 0, cb->seq_end, TCP_RST | TCP_ACK, 0);
  tcp->checksum = tcp_checksum(ip, tcp);

  ip_send_packet(packet, pkt_size);
}
