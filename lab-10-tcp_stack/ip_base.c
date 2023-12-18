#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "arpcache.h"
#include "base.h"
#include "icmp.h"
#include "include/base.h"
#include "include/ether.h"
#include "ip.h"
#include "log.h"
#include "rtable.h"

// initialize ip header
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto) {
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(len);
  ip->id = rand();
  ip->frag_off = htons(IP_DF);
  ip->ttl = DEFAULT_TTL;
  ip->protocol = proto;
  ip->saddr = htonl(saddr);
  ip->daddr = htonl(daddr);
  ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest
// prefix. the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst) {
  // lookup the routing table to find the entry with the same and longest prefix
  rt_entry_t *entry = NULL, *longest_entry = NULL;
  list_for_each_entry(entry, &rtable, list) {
    if ((dst & entry->mask) == (entry->dest & entry->mask)) {
      if (longest_entry == NULL || entry->mask > longest_entry->mask) {
        longest_entry = entry;
      }
    }
  }
  return longest_entry;
}

void ip_send_packet(char *packet, int len) {
  struct iphdr *ip = packet_to_ip_hdr(packet);
  struct ether_header *eh = (struct ether_header *)packet;
  eh->ether_type = htons(ETH_P_IP);
  rt_entry_t *entry = longest_prefix_match(ntohl(ip->daddr));
  assert(entry != NULL);
  iface_info_t *iface = entry->iface;
  assert(iface != NULL);
  memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
  ip->saddr = htonl(iface->ip);
  ip->checksum = ip_checksum(ip);
  iface_send_packet_by_arp(iface, ntohl(ip->daddr), packet, len);
}
