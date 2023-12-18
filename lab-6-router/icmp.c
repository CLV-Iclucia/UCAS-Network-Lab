#include "icmp.h"
#include "include/ether.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code) {
 //   log(DEBUG, "malloc and send icmp packet.");
    struct ether_header *in_eh = (struct ether_header *)in_pkt;
    struct iphdr *ip = packet_to_ip_hdr(in_pkt);
    u32 src = ntohl(ip->daddr);
    u32 dst = ntohl(ip->saddr);
    u16 ip_len = IP_HDR_SIZE(ip);
    int icmp_len = (type == ICMP_ECHOREPLY ? len : ETHER_HDR_SIZE + ip_len + ICMP_HDR_SIZE + ip_len + 8);
    char *packet = (char *)malloc(icmp_len);
    struct ether_header *eh = (struct ether_header *)packet;
    memcpy(eh->ether_shost, in_eh->ether_dhost, ETH_ALEN);
    memcpy(eh->ether_dhost, in_eh->ether_shost, ETH_ALEN);
    eh->ether_type = htons(ETH_P_IP);
    struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + ETHER_HDR_SIZE + ip_len);
    icmp_hdr->type = type;
    icmp_hdr->code = code;
    ip_init_hdr(ip_hdr, src, dst, icmp_len - ETHER_HDR_SIZE, IPPROTO_ICMP);
    char* rest_pkt = packet + ETHER_HDR_SIZE + ip_len + ICMP_HDR_SIZE - 4;
    char* in_pkt_rest = (char *)ip + ip_len + ICMP_HDR_SIZE - 4;
    if (type == ICMP_ECHOREPLY) {
        memcpy(rest_pkt, in_pkt_rest, len - ETHER_HDR_SIZE - ip_len - ICMP_HDR_SIZE + 4);
        log(DEBUG, "this router got pinged");
    } else {
        rest_pkt[0] = rest_pkt[1] = rest_pkt[2] = rest_pkt[3] = 0;
        memcpy(rest_pkt + 4, in_pkt + ETHER_HDR_SIZE, ip_len + 8);
        log(DEBUG, "ICMP for other reasons");
    }
    icmp_hdr->checksum = icmp_checksum(icmp_hdr, icmp_len - ETHER_HDR_SIZE - ip_len);
    ip_send_packet(packet, icmp_len);
}
