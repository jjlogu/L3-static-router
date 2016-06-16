#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
	struct sr_arpreq* req = sr->cache.requests;
	while(req) {
		sr_handle_arpreq(sr,req);
		req=req->next;
	}
}

void sr_handle_arpreq(struct sr_instance* sr /* borrowed */,
			struct sr_arpreq* req /* borrowed */) {
	time_t now = time(NULL);
	if( 1.0 <= difftime(now,req->sent) ) {
		if( 5 <= req->times_sent ) {
			unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
			uint8_t* buf = (uint8_t*)malloc(len);
			struct sr_rt* rt_match = 0;
			sr_ip_hdr_t* ip_hdr = 0;
			sr_ethernet_hdr_t* eth_hdr = 0;
			struct sr_if* if_to_send = 0;

			assert(buf);

			while(req->packets) {
				ip_hdr = (sr_ip_hdr_t*)(req->packets->buf+sizeof(sr_ethernet_hdr_t));
				eth_hdr = (sr_ethernet_hdr_t*)(req->packets->buf);
				rt_match = sr_get_longest_rt_table_match(sr->routing_table,ip_hdr->ip_src);

				if(rt_match) {
					if_to_send = sr_get_interface(sr,rt_match->interface);
					prepare_icmp_t3_hdr( (sr_icmp_t3_hdr_t*)( buf+(len-sizeof(sr_icmp_t3_hdr_t)) ), 0x03 /* type */, 0x01/* code */, ip_hdr );
					/* Note: Not looking at rt_table for mac, just reusing mac->IP from existing queued packet */
					prepare_ipv4_hdr((sr_ip_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t)),0x00 /* TOS */, len-sizeof(sr_ethernet_hdr_t), 0x0000 /* ID */, IP_DF /* offset */, ip_protocol_icmp /* protocol */, ntohl(if_to_send->ip) /* source */ ,ntohl(ip_hdr->ip_src) /* destination */);
					prepare_eth_hdr((sr_ethernet_hdr_t*)buf, eth_hdr->ether_shost /* destination */, if_to_send->addr /* sender */, ethertype_ip);
					
					print_hdrs(buf,len);
					sr_send_packet(sr,buf,len,rt_match->interface);
				}
				req->packets = req->packets->next;
			}
			free(buf);
			fprintf(stderr,"Sent ICMP host not reachable (type 3, code 1)\n");
			sr_arpreq_destroy(&sr->cache,req);
		}
		else {
			/* Send a ARP request */
			unsigned int len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
            uint8_t* buf = (uint8_t*)malloc(len);
			struct sr_if* if_to_send = sr_get_interface(sr,req->packets->iface);

			assert(buf);
            sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)buf;
            sr_arp_hdr_t* arp_req = (sr_arp_hdr_t*)(buf+sizeof(sr_ethernet_hdr_t));

            /* Prepare Ethernet Header */
            memset(eth_hdr->ether_dhost,0xff,ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost,if_to_send->addr,ETHER_ADDR_LEN);
            eth_hdr->ether_type = htons(ethertype_arp);

            /* Prepare ARP request */
            arp_req->ar_hrd = htons(arp_hrd_ethernet);
            arp_req->ar_pro = htons(ethertype_ip);
            arp_req->ar_hln = ETHER_ADDR_LEN;
            arp_req->ar_pln = 0x04;
            arp_req->ar_op = htons(arp_op_request);
            memcpy(arp_req->ar_sha,if_to_send->addr,ETHER_ADDR_LEN);
            arp_req->ar_sip = if_to_send->ip;
            memset(arp_req->ar_tha,0xff,ETHER_ADDR_LEN);
            arp_req->ar_tip = req->ip;
			fprintf(stderr, "Sending ARP request\n");
			sr_send_packet(sr,buf,len,if_to_send->name);
			free(buf);

			req->sent = time(NULL);
			req->times_sent++;
		}
	}
}
/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

