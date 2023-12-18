#include "ip.h"
#include "base.h"
#include "include/base.h"
#include "include/ether.h"
#include "rtable.h"
#include "icmp.h"
#include "arp.h"
#include "arpcache.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len) {
	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ntohl(ip->daddr) == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)((char *)ip + IP_HDR_SIZE(ip));
			if (icmp->type == ICMP_ECHOREQUEST) {
				log(DEBUG, "receive ICMP_ECHOREQUEST, send ICMP_ECHOREPLY");
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
				free(packet);
				return;
			}
		} else {
			log(DEBUG, "not ICMP_ECHOREQUEST, drop packet");
			free(packet);
			return;
		}
	}
	if (ip->ttl <= 1) {
		log(DEBUG, "TTL <= 1, reply ICMP_TIME_EXCEEDED");
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return;
	}
	ip->ttl--;
	log(DEBUG, "Receive packet from "IP_FMT", to "IP_FMT", ttl = %d", NET_IP_FMT_STR(ip->saddr), NET_IP_FMT_STR(ip->daddr), ip->ttl);
	ip->checksum = ip_checksum(ip);
	rt_entry_t *entry = longest_prefix_match(ntohl(ip->daddr));
	if (entry == NULL) {
		log(DEBUG, "no matching entry, reply ICMP_DEST_UNREACH");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return;
	}
	// match, forward the packet
	iface_info_t *dest_iface = entry->iface;
	if (dest_iface == NULL) {
		log(DEBUG, "no matching iface, reply ICMP_DEST_UNREACH");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return;
	}
	// log the MAC address of the src
	ip_forward_packet(dest_iface, packet, len);	
}

// 1. dec ttl by 1, if ttl is already 0, drop it and send ICMP time exceeded
// 2. recalculate ip header checksum
// 3. change MAC and send
// since packet is in network byte order, we need to convert it to host byte order
void ip_forward_packet(iface_info_t *iface, char *packet, int len) {
	struct iphdr *ip = packet_to_ip_hdr(packet);
	rt_entry_t *entry = longest_prefix_match(ntohl(ip->daddr));
	if (entry->gw) {
		log(DEBUG, "found next hop for packet from "IP_FMT", send packet", NET_IP_FMT_STR(ip->saddr));
		iface_send_packet_by_arp(iface, entry->gw, packet, len);
	} else {
		log(DEBUG, "no next hop for packet from "IP_FMT", send packet", NET_IP_FMT_STR(ip->saddr));
		iface_send_packet_by_arp(iface, ntohl(ip->daddr), packet, len);
	}
}