#include "include/mac.h"
#include "include/list.h"
#include "include/log.h"

#include <bits/pthreadtypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;
// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// lookup the mac address in mac_port table
	// return NULL for non-existing records
	// first calc the hash value
	log(INFO, "lookup "ETHER_STRING, ETHER_FMT(mac));
	int hash = hash8((char *)mac, ETH_ALEN);	
	log(DEBUG, "hash value of "ETHER_STRING" is %d", ETHER_FMT(mac), hash);
	mac_port_entry_t *entry = NULL;
	// lock
	pthread_mutex_lock(&mac_port_map.lock);
	list_for_each_entry(entry, &mac_port_map.hash_table[hash], list) {
		if (memcmp(entry->mac, mac, ETH_ALEN) == 0) {
			log(DEBUG, "found "ETHER_STRING" in mac_port table", ETHER_FMT(mac));
			entry->visited = time(NULL);
			// unlock
			pthread_mutex_unlock(&mac_port_map.lock);
			return entry->iface;
		}
	}
	// unlock
	pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// insert mac -> iface pair into mac_port table
	// it is just a insertion to a hash table
	// first calc the hash value
	log(INFO, "insert "ETHER_STRING" -> %s into mac_port table", ETHER_FMT(mac), iface->name);
	int hash = hash8((char *)mac, ETH_ALEN);
	log(DEBUG, "hash value of "ETHER_STRING" is %d", ETHER_FMT(mac), hash);
	// lock
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
	memcpy(entry->mac, mac, ETH_ALEN);
	entry->iface = iface;
	entry->visited = time(NULL);
	list_add_tail(&entry->list, &mac_port_map.hash_table[hash]);
	pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// lock
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	time_t now = time(NULL);
	int n = 0;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			if (now - entry->visited > MAC_PORT_TIMEOUT) {
				list_delete_entry(&entry->list);
				free(entry);
				n++;
			}
		}
	}
	// unlock
	pthread_mutex_unlock(&mac_port_map.lock);
	return 0;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
