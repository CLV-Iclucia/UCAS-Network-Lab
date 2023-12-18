#include "base.h"
#include "include/base.h"
#include "include/ether.h"
#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
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

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
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

void ip_send_packet(char *packet, int len)
{
	struct iphdr* ip = packet_to_ip_hdr(packet);
	rt_entry_t* entry = longest_prefix_match(ntohl(ip->daddr));
	assert(entry != NULL);
	iface_info_t* iface = entry->iface;
	assert(iface != NULL);
	ip->saddr = htonl(iface->ip);
	ip->checksum = ip_checksum(ip);
	log(DEBUG, "send icmp packet to "IP_FMT" from " IP_FMT, NET_IP_FMT_STR(ip->daddr), NET_IP_FMT_STR(ip->saddr));
	iface_send_packet(iface, packet, len);
}
