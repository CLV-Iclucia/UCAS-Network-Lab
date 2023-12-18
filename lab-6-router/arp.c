#include "arp.h"
#include "base.h"
#include "include/icmp.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include "ip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	log(DEBUG, "send arp request to "IP_FMT , LE_IP_FMT_STR(dst_ip));
	char* packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eh = (struct ether_header *)packet;
	memset(eh->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = ETH_ALEN;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);
	memset(arp_hdr->arp_tha, 0, ETH_ALEN);
	arp_hdr->arp_spa = htonl(iface->ip);
	arp_hdr->arp_tpa = htonl(dst_ip);
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	log(DEBUG, "send arp reply to "IP_FMT" through %s", NET_IP_FMT_STR(req_hdr->arp_spa), iface->name);
	char* packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
	arp_hdr->arp_pro = htons(ETH_P_IP);
	arp_hdr->arp_hln = ETH_ALEN;
	arp_hdr->arp_pln = 4;
	arp_hdr->arp_op = htons(ARPOP_REPLY);
	memcpy(arp_hdr->arp_sha, iface->mac, ETH_ALEN);
	arp_hdr->arp_spa = htonl(iface->ip);
	memcpy(arp_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	arp_hdr->arp_tpa = req_hdr->arp_spa;
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	if (ntohs(arp_hdr->arp_op) == ARPOP_REQUEST) {
		if (ntohl(arp_hdr->arp_tpa) == iface->ip) {
			arp_send_reply(iface, arp_hdr);
			return ;
		}
		log(DEBUG, "received arp packet not for me");
	}
	else if (ntohs(arp_hdr->arp_op) == ARPOP_REPLY) {
		log(DEBUG, "received arp reply from"IP_FMT", caching it", NET_IP_FMT_STR(arp_hdr->arp_spa));
		arpcache_insert(ntohl(arp_hdr->arp_spa), arp_hdr->arp_sha);
	}
	else {
		log(DEBUG, "received arp packet not request or reply, arp fail");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
	}
	free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		log(DEBUG, "found mac for "IP_FMT" in arpcache, send packet", NET_IP_FMT_STR(dst_ip));
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	} else {
		log(DEBUG, "not found mac for "IP_FMT" in arpcache, pending packet", NET_IP_FMT_STR(dst_ip));
		arpcache_append_packet(iface, dst_ip, packet, len);
		arp_send_request(iface, dst_ip);	
	}
}
