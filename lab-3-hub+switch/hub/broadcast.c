#include "include/base.h"
#include <stdio.h>
#include "include/log.h"
// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet
	//log(INFO, "Broadcast packet start.");
	iface_info_t *iface_info = NULL;
	list_for_each_entry(iface_info, &instance->iface_list, list) {
		if (iface_info != iface) {
			log(INFO, "Sending packet of length %d to iface %s", len, iface_info->name);
			iface_send_packet(iface_info, packet, len);
		}
	}
	//log(INFO, "Broadcast packet done.");
}
