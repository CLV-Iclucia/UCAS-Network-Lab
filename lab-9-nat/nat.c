#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"
#include "arp.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t* if_name_to_iface(const char* if_name) {
  iface_info_t* iface = NULL;
  list_for_each_entry(iface, &instance->iface_list, list) {
    if (strcmp(iface->name, if_name) == 0)
      return iface;
  }

  log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
  return NULL;
}

static bool is_internal_ip(u32 ip) {
  rt_entry_t* entry = longest_prefix_match(ip);
  if (entry == NULL)
    return false;
  if (entry->iface->index == nat.internal_iface->index)
    return true;
  return false;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char* packet) {
  struct iphdr* ip = packet_to_ip_hdr(packet);
  bool src_internal = is_internal_ip(ntohl(ip->saddr));
  bool dst_internal = is_internal_ip(ntohl(ip->daddr));
  if (src_internal && !dst_internal)
    return DIR_OUT;
  if (!src_internal && !dst_internal)
    return DIR_IN;
  return DIR_INVALID;
}

static int8_t hash_ip_and_port(u32 ip, u16 port) {
  int hash = hash8((char *)&ip, 4);
  return hash8((char *)&port, 2) ^ hash;
}

static struct nat_mapping* nat_lookup(u32 remote_ip, u16 remote_port) {
  int hash = hash_ip_and_port(remote_ip, remote_port);
  struct nat_mapping* mapping = NULL;
  list_for_each_entry(mapping, &nat.nat_mapping_list[hash], list) {
    if (mapping->remote_ip == remote_ip && mapping->remote_port == remote_port)
      return mapping;
  }
  return NULL;
}

u32 compute_seq_end(struct iphdr* ip, struct tcphdr* tcp, int len) {
  u32 seq = ntohl(tcp->seq);
  u32 seq_end = seq + len - TCP_HDR_SIZE(tcp) - ETHER_HDR_SIZE - IP_HDR_SIZE(ip);
  if (tcp->flags & TCP_FIN)
    seq_end++;
  if (tcp->flags & TCP_SYN)
    seq_end++;
  return seq_end;
}

static struct dnat_rule* look_up_dnat_rule(u32 ip, u16 port) {
  struct dnat_rule* rule = NULL;
  list_for_each_entry(rule, &nat.rules, list) {
    if (rule->external_ip == ip && rule->external_port == port)
      return rule;
  }
  return NULL;
}

static struct nat_mapping* create_mapping(u32 remote_ip,
                           u16 remote_port,
                           u32 internal_ip,
                           u16 internal_port,
                           u32 external_ip,
                           u16 external_port) {
  struct nat_mapping* mapping = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
  mapping->remote_ip = remote_ip;
  mapping->remote_port = remote_port;
  mapping->internal_ip = internal_ip;
  mapping->internal_port = internal_port;
  mapping->external_ip = external_ip;
  mapping->external_port = external_port;
  mapping->update_time = time(NULL);
  mapping->conn.internal_ack = mapping->conn.internal_seq_end = 0;
  mapping->conn.external_ack = mapping->conn.external_seq_end = 0;
  mapping->conn.internal_fin = mapping->conn.external_fin = 0;
  log(DEBUG, "mapping created with ("IP_FMT", %d) <--> ("IP_FMT", %d)",
      HOST_IP_FMT_STR(mapping->internal_ip),
      mapping->internal_port,
      HOST_IP_FMT_STR(mapping->external_ip),
      mapping->external_port);
  int hash = hash_ip_and_port(remote_ip, remote_port);
  list_add_tail(&mapping->list, &nat.nat_mapping_list[hash]);
  return mapping;
}

static void nat_translate_packet_in(iface_info_t* iface, char* packet, int len) {
  log(DEBUG, "handle incoming packet.");
  struct iphdr* ip = packet_to_ip_hdr(packet);
  struct tcphdr* tcp = packet_to_tcp_hdr(packet);
  struct nat_mapping* mapping = nat_lookup(ntohl(ip->saddr), ntohs(tcp->sport));
  if (!mapping) {
    struct dnat_rule* rule = look_up_dnat_rule(ntohl(ip->daddr), ntohs(tcp->dport));
    // do translation
    ip->daddr = htonl(rule->internal_ip);
    tcp->dport = htons(rule->internal_port);
    ip->checksum = ip_checksum(ip);
    tcp->checksum = tcp_checksum(ip, tcp);
    mapping = create_mapping(ntohl(ip->saddr),
                   ntohs(tcp->sport),
                   rule->internal_ip,
                   rule->internal_port,
                   rule->external_ip,
                   rule->external_port);
    mapping->conn.external_ack = ntohl(tcp->ack);
    mapping->conn.external_fin = (tcp->flags & TCP_FIN);
    mapping->conn.external_seq_end = compute_seq_end(ip, tcp, len);
    mapping->update_time = time(NULL);
    // send the packet
    iface_send_packet(nat.internal_iface, packet, len);
    return;
  }
  if (!(tcp->flags & TCP_SYN)) {
    log(DEBUG, "invalid packet, drop it.");
    free(packet);
    return;
  }
  // find the mapping entry, do translation
  ip->daddr = htonl(mapping->internal_ip);
  tcp->dport = htons(mapping->internal_port);
  ip->checksum = ip_checksum(ip);
  tcp->checksum = tcp_checksum(ip, tcp);
  // update statistics
  mapping->conn.external_ack = ntohl(tcp->ack);
  mapping->conn.external_seq_end = compute_seq_end(ip, tcp, len);
  mapping->conn.external_fin = (tcp->flags & TCP_FIN);
  mapping->update_time = time(NULL);
  // send the packet
  iface_send_packet_by_arp(nat.internal_iface, ntohl(ip->daddr), packet, len);
}

static void nat_translate_packet_out(iface_info_t* iface, char* packet, int len) {
  log(DEBUG, "handle outgoing packet.");
  struct iphdr* ip = packet_to_ip_hdr(packet);
  struct tcphdr* tcp = packet_to_tcp_hdr(packet);
  struct nat_mapping* mapping = nat_lookup(ntohl(ip->daddr), ntohs(tcp->dport));
  if (mapping) {
    // do translation
    log(DEBUG,
        "found mapping entry, do translation, translate source from "IP_FMT":%d to "IP_FMT":%d",
        NET_IP_FMT_STR(ip->saddr),
        ntohs(tcp->sport),
        HOST_IP_FMT_STR(mapping->internal_ip),
        mapping->internal_port);
    ip->saddr = htonl(mapping->internal_ip);
    tcp->sport = htons(mapping->internal_port);
    ip->checksum = ip_checksum(ip);
    tcp->checksum = tcp_checksum(ip, tcp);
    // update statistics
    mapping->conn.internal_ack = ntohl(tcp->ack);
    mapping->conn.internal_fin = (tcp->flags & TCP_FIN);
    mapping->conn.internal_seq_end = compute_seq_end(ip, tcp, len);
    mapping->update_time = time(NULL);
    // send the packet
    log(DEBUG, "send packet by iface %s", nat.internal_iface->name);
    iface_send_packet(nat.external_iface, packet, len);
    return;
  }
  log(DEBUG, "no mapping entry found.");
  // if it is not the first packet of the flow, drop it
  if (!(tcp->flags & TCP_SYN)) {
    log(DEBUG, "not the first packet, drop it.");
    free(packet);
    return;
  }
  // find a free port
  u16 port = 0;
  for (int i = NAT_PORT_MIN; i <= NAT_PORT_MAX; i++) {
    if (nat.assigned_ports[i] == 0) {
      port = i;
      log(DEBUG, "assign port %d", port);
      break;
    }
  }
  if (port == 0) {
    log(ERROR, "no free port, drop the packet.");
    return;
  }
  // create a new mapping entry
  mapping = create_mapping(ntohl(ip->daddr),
                 ntohs(tcp->dport),
                 ntohl(ip->saddr),
                 ntohs(tcp->sport),
                 nat.external_iface->ip,
                 port);
  mapping->conn.internal_ack = ntohl(tcp->ack);
  mapping->conn.internal_ack = compute_seq_end(ip, tcp, len);
  mapping->conn.internal_fin = (tcp->flags & TCP_FIN);
  mapping->update_time = time(NULL);
  // do translation
  ip->saddr = htonl(mapping->internal_ip);
  tcp->sport = htons(mapping->internal_port);
  ip->checksum = ip_checksum(ip);
  tcp->checksum = tcp_checksum(ip, tcp);
  // send the packet
  iface_send_packet_by_arp(nat.external_iface, ntohl(ip->daddr), packet, len);
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t* iface, char* packet, int len, int dir) {
  pthread_mutex_lock(&nat.lock);
  struct iphdr* ip = packet_to_ip_hdr(packet);
  struct tcphdr* tcp = packet_to_tcp_hdr(packet);
  log(DEBUG,
      "from "IP_FMT":%d to "IP_FMT":%d",
      NET_IP_FMT_STR(ip->saddr),
      ntohs(tcp->sport),
      NET_IP_FMT_STR(ip->daddr),
      ntohs(tcp->dport));
  int direction = get_packet_direction(packet);
  if (direction == DIR_INVALID) {
    log(ERROR, "invalid packet direction, drop it.");
    free(packet);
    return;
  }
  if (direction == DIR_IN)
    nat_translate_packet_in(iface, packet, len);
  if (direction == DIR_OUT)
    nat_translate_packet_out(iface, packet, len);
  pthread_mutex_lock(&nat.lock);
}

void nat_translate_packet(iface_info_t* iface, char* packet, int len) {
  log(DEBUG, "handle packet from interface %s", iface->name);
  int dir = get_packet_direction(packet);
  if (dir == DIR_INVALID) {
    log(ERROR, "invalid packet direction, drop it.");
    icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
    free(packet);
    return;
  }

  struct iphdr* ip = packet_to_ip_hdr(packet);
  if (ip->protocol != IPPROTO_TCP) {
    log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
    free(packet);
    return;
  }

  do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection* conn) {
  return (conn->internal_fin && conn->external_fin) &&
      (conn->internal_ack >= conn->external_seq_end) &&
      (conn->external_ack >= conn->internal_seq_end);
}

static void sweep_mappings() {
  for (int i = 0; i < HASH_8BITS; i++) {
    struct nat_mapping* mapping = NULL;
    struct nat_mapping* q = NULL;
    list_for_each_entry_safe(mapping, q, &nat.nat_mapping_list[i], list) {
      // if the flow is finished, remove it
      if (is_flow_finished(&mapping->conn)) {
        log(DEBUG, "flow finished, remove it.");
        list_delete_entry(&mapping->list);
        free(mapping);
      }
      // if the flow is not finished, but timeout, remove it
      else if (time(NULL) - mapping->update_time > TCP_ESTABLISHED_TIMEOUT) {
        log(DEBUG, "flow timeout, remove it.");
        list_delete_entry(&mapping->list);
        free(mapping);
      }
    }
  }
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void* nat_timeout() {
  while (1) {
    // run through all the mapping entries
    pthread_mutex_lock(&nat.lock);
    sweep_mappings();
    pthread_mutex_unlock(&nat.lock);
    sleep(1);
  }
  return NULL;
}

int parse_config(const char* filename) {
  FILE* fp = fopen(filename, "r");
  if (fp == NULL) {
    log(ERROR, "cannot open config file '%s'", filename);
    return -1;
  }
  // example for SNAT config file:
  // internal-iface: n1-eth0\n
  // external-iface: n1-eth1\n
  // implement the parse logic here, remember to ignore the '\n' in the end
  char buf[BUFSIZ];
  char* ptr = NULL;
  while (fgets(buf, BUFSIZ, fp) != NULL) {
    if (strncmp(buf, "internal-iface", strlen("internal-iface")) == 0) {
      ptr = strtok(buf, " ");
      ptr = strtok(NULL, " ");
      ptr[strlen(ptr) - 1] = '\0';
      nat.internal_iface = if_name_to_iface(ptr);
    }
    if (strncmp(buf, "external-iface", strlen("external-iface")) == 0) {
      ptr = strtok(buf, " ");
      ptr = strtok(NULL, " ");
      ptr[strlen(ptr) - 1] = '\0';
      nat.external_iface = if_name_to_iface(ptr);
    }
  }
  fclose(fp);
  // example for DNAT config file:
  // internal-iface: n1-eth0\n
  // external-iface: n1-eth1\n
  // dnat-rules: 159.226.39.43:8000 -> 10.21.0.1:8000\n
  // dnat-rules: 159.226.39.43:8001 -> 10.21.0.2:8000\n
  // implement the parse logic here, remember to ignore the '\n' in the end
  fp = fopen(filename, "r");
  if (fp == NULL) {
    log(ERROR, "cannot open config file '%s'", filename);
    return -1;
  }
  while (fgets(buf, BUFSIZ, fp) != NULL) {
    if (strncmp(buf, "internal-iface", strlen("internal-iface")) == 0) {
      ptr = strtok(buf, " ");
      ptr = strtok(NULL, " ");
      ptr[strlen(ptr) - 1] = '\0';
      nat.internal_iface = if_name_to_iface(ptr);
    }
    if (strncmp(buf, "external-iface", strlen("external-iface")) == 0) {
      ptr = strtok(buf, " ");
      ptr = strtok(NULL, " ");
      ptr[strlen(ptr) - 1] = '\0';
      nat.external_iface = if_name_to_iface(ptr);
    }
    if (strncmp(buf, "dnat-rules", strlen("dnat-rules")) == 0) {
      ptr = strtok(buf, " ");
      ptr = strtok(NULL, " ");
      ptr[strlen(ptr) - 1] = '\0';
      char* ptr1 = strtok(ptr, ":");
      char* ptr2 = strtok(NULL, ":");
      char* ptr3 = strtok(NULL, ":");
      char* ptr4 = strtok(NULL, ":");
      struct dnat_rule* rule = (struct dnat_rule *)malloc(sizeof(struct dnat_rule));
      rule->external_ip = ntohl(inet_addr(ptr1));
      rule->external_port = atoi(ptr2);
      rule->internal_ip = ntohl(inet_addr(ptr3));
      rule->internal_port = atoi(ptr4);
      list_add_tail(&rule->list, &nat.rules);
    }
  }
  return 0;
}

// initialize
void nat_init(const char* config_file) {
  memset(&nat, 0, sizeof(nat));

  for (int i = 0; i < HASH_8BITS; i++)
    init_list_head(&nat.nat_mapping_list[i]);

  init_list_head(&nat.rules);

  // seems unnecessary
  memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

  parse_config(config_file);

  pthread_mutex_init(&nat.lock, NULL);

  pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit() {
  pthread_kill(nat.thread, SIGTERM);
  pthread_mutex_destroy(&nat.lock);
}
