#include "include/base.h"
#include "include/ether.h"
#include "include/mac.h"
#include "include/utils.h"

#include "include/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
bool is_broadcast(u8 mac[ETH_ALEN])
{
	for (int i = 0; i < ETH_ALEN; i++) {
		if (mac[i] != 0xff)
			return false;
	}
	return true;
}

void handle_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	log(DEBUG, "the dst mac address is " ETHER_STRING ".\n", ETHER_FMT(eh->ether_dhost));
	log(DEBUG, "the src mac address is " ETHER_STRING ".\n", ETHER_FMT(eh->ether_shost));
	// if the dest mac address is found in mac_port table, forward it; otherwise,
	// broadcast it.
	if (is_broadcast(eh->ether_dhost)) {
		log(DEBUG, "the dst mac address is broadcast address, broadcast it.");
		broadcast_packet(iface, packet, len);
		free(packet);
		return;
	}
	iface_info_t *dst_iface = lookup_port(eh->ether_dhost);
	if (dst_iface != NULL) {
		log(DEBUG, "found " ETHER_STRING " in mac_port table, forward it.", ETHER_FMT(eh->ether_dhost));
		iface_send_packet(dst_iface, packet, len);
	}
	else {
		log(DEBUG, "not found " ETHER_STRING " in mac_port table, broadcast it.", ETHER_FMT(eh->ether_dhost));
		broadcast_packet(iface, packet, len);
	}
	if (!lookup_port(eh->ether_shost))
		insert_mac_port(eh->ether_shost, iface);
	free(packet);
}

// run user stack, receive packet on each interface, and handle those packet
// like normal switch
void ustack_run()
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	char buf[ETH_FRAME_LEN];
	int len;
	// use another thread to sweep mac_port table
	pthread_t tid;
	pthread_create(&tid, NULL, sweeping_mac_port_thread, NULL);
	while (1) {
		int ready = poll(instance->fds, instance->nifs, -1);
		if (ready < 0) {
			perror("Poll failed!");
			break;
		}
		else if (ready == 0)
			continue;

		for (int i = 0; i < instance->nifs; i++) {
			if (instance->fds[i].revents & POLLIN) {
				len = recvfrom(instance->fds[i].fd, buf, ETH_FRAME_LEN, 0, \
						(struct sockaddr*)&addr, &addr_len);
				if (len <= 0) {
					log(ERROR, "receive packet error: %s", strerror(errno));
				}
				else if (addr.sll_pkttype == PACKET_OUTGOING) {
					// XXX: Linux raw socket will capture both incoming and
					// outgoing packets, while we only care about the incoming ones.

					// log(DEBUG, "received packet which is sent from the "
					// 		"interface itself, drop it.");
				}
				else {
					iface_info_t *iface = fd_to_iface(instance->fds[i].fd);
					if (!iface) 
						continue;

					char *packet = malloc(len);
					if (!packet) {
						log(ERROR, "malloc failed when receiving packet.");
						continue;
					}
					memcpy(packet, buf, len);
					handle_packet(iface, packet, len);
				}
			}
		}
	}
	// join the sweeping thread
	pthread_join(tid, NULL);
}

int main(int argc, const char **argv)
{
	if (getuid() && geteuid()) {
		printf("Permission denied, should be superuser!\n");
		exit(1);
	}

	init_ustack();

	init_mac_port_table();

	ustack_run();

	return 0;
}
