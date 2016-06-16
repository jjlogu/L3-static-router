/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    sr_ethernet_hdr_t* e_hdr = 0;
    struct sr_if* if_match = 0;
	unsigned int minlen = sizeof(sr_ethernet_hdr_t);
 
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
 
    if( len < minlen ){
        fprintf(stderr, "Invalid ethernet frame header length\n");
        return;
    }
#ifdef MYDEBUG
	fprintf(stderr,"++++++++++++++++++ Received a Packet ++++++++++++++++++\n");
    print_hdrs(packet,len);
	fprintf(stderr,"+++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
#endif
 
    e_hdr = (sr_ethernet_hdr_t*)packet;

	/* Handle IP */
    if ( e_hdr->ether_type == htons(ethertype_ip) ) {
		sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+minlen);
		uint16_t checksum = 0x0000;
		minlen += sizeof(sr_ip_hdr_t);

		if( len < minlen ) {
			fprintf(stderr,"Invalid IP packet length\n");
			return;
		}
		checksum = ip_hdr->ip_sum;
		ip_hdr->ip_sum = 0x0000; /* for recalculate checksum */
		ip_hdr->ip_sum = cksum(ip_hdr,ip_hdr->ip_hl*4); /* recalculate checksum */
		if(checksum != ip_hdr->ip_sum) {
			fprintf(stderr,"Invalid IP checksum: Expected:%04X  Calculated:%04X\n",checksum,ip_hdr->ip_sum);
			return;
		}
		if_match = is_ip_match_router_if(sr,ip_hdr->ip_dst);	
		if(if_match) { /* packet is for router */
			/* Handle ICMP */
			if(ip_hdr->ip_p == ip_protocol_icmp) {
				sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet+minlen);
				minlen += sizeof(sr_icmp_hdr_t);

				/*Make sure packet length for ICMP*/
				if( len < minlen ) {
         			fprintf(stderr,"Invalid ICMP packet length\n");
		            return;
        		}
				checksum = icmp_hdr->icmp_sum;
				icmp_hdr->icmp_sum = 0x0000; /* for recalculate checksum */
				icmp_hdr->icmp_sum = cksum(icmp_hdr,len-(sizeof(sr_ethernet_hdr_t)+(ip_hdr->ip_hl*4))); /* recalculate checksum */
				if(checksum != icmp_hdr->icmp_sum) {
            		fprintf(stderr,"Invalid ICMP checksum: Expected:%04X  Calculated:%04X\n",checksum,icmp_hdr->icmp_sum);
		            return;
        		}
				if(0x0008 == icmp_hdr->icmp_type){
 					unsigned char t_ether_addr[ETHER_ADDR_LEN];
					/* Prepare ICMP reply */
					icmp_hdr->icmp_sum = 0x0000; /* for recalculate checksum */
					icmp_hdr->icmp_type = 0x0000;
					icmp_hdr->icmp_code = 0x0000;
					icmp_hdr->icmp_sum = cksum(icmp_hdr,len-(sizeof(sr_ethernet_hdr_t)+(ip_hdr->ip_hl*4))); /* recalculate checksum */
					
					/* Prepare IP packet */
					ip_hdr->ip_dst = ip_hdr->ip_src;
					ip_hdr->ip_src = if_match->ip;
					ip_hdr->ip_sum = 0x0000; /* for recalculate checksum */
			        ip_hdr->ip_sum = cksum(ip_hdr,ip_hdr->ip_hl*4); /* recalculate checksum */

					/* Prepare Ethernet packet */
					memcpy(t_ether_addr,e_hdr->ether_dhost,ETHER_ADDR_LEN);
					memcpy(e_hdr->ether_dhost,e_hdr->ether_shost,ETHER_ADDR_LEN);
			    	memcpy(e_hdr->ether_shost,t_ether_addr,ETHER_ADDR_LEN);

					/* Send on wire */
                	sr_send_packet(sr,packet,len,interface);
					fprintf(stderr,"ICMP reply has been sent to ");
					print_addr_ip_int(ntohl(ip_hdr->ip_dst));

					return;
				} 
			}
			else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
				fprintf(stderr, "TODO: send ICMP Port unreachable (type 3, code 3)\n");
			}
			fprintf(stderr, "TODO: send ICMP destination not reachable(Protocol unreachable error.) Type-3 Code-2\n");
		} else { /* packet is not for router */
			struct sr_rt* rt_match = sr_get_longest_rt_table_match(sr->routing_table,ip_hdr->ip_dst);
			if(rt_match) {
				struct sr_arpentry* entry = 0;
				struct sr_if* if_to_send = sr_get_interface(sr,rt_match->interface);

				fprintf(stderr,"IP packet received for forward\n");	
				ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
				if(0 < ip_hdr->ip_ttl) {
					ip_hdr->ip_ttl = ip_hdr->ip_ttl;
					ip_hdr->ip_sum = 0x0000; /* for recalculate checksum */	
					ip_hdr->ip_sum = cksum(ip_hdr,ip_hdr->ip_hl*4); /* recalculate checksum */

					entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
					if(entry) {
						/* Update Ethernet header */
						memcpy(e_hdr->ether_shost,if_to_send->addr,ETHER_ADDR_LEN);
						memcpy(e_hdr->ether_dhost,entry->mac,ETHER_ADDR_LEN);

						sr_send_packet(sr, packet, len, rt_match->interface);
						/* sr_arpcache_dump(&sr->cache); */
						free(entry);
						return;
					}
					else {
						struct sr_arpreq* req = 0;
						fprintf(stderr,"Calling sr_arpcache_queuereq\n");
						req = sr_arpcache_queuereq(&sr->cache,ip_hdr->ip_dst,packet,len,rt_match->interface); 
						sr_handle_arpreq(sr,req);
					}
				} else {
					fprintf(stderr,"TODO: send ICMP Time exceeded (type 11, code 0)\n");
				}
			}
			else {
				fprintf(stderr,"TODO: send ICMP Destination net not reachable(Type-3, Code-0)\n");
			}
		}

		/* fprintf(stderr,"len = %d\n",len);
		print_hdrs(packet,len); */
	} /* end Handle IP */
	/* Handle ARP */
    else if ( e_hdr->ether_type == htons(ethertype_arp) ) {
    	sr_arp_hdr_t* a_hdr = 0;

		if( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) ) {
			fprintf(stderr, "Invalid ARP header length\n");
			return;
		}
		a_hdr=(sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
        /* Handle ARP request */
        if( a_hdr->ar_op == htons(arp_op_request) ) {
            /* if ARP request is for one of router's interface, send ARP reply */
            if_match = is_ip_match_router_if(sr, a_hdr->ar_tip);
            if(if_match) {
				/* Send ARP reply */
				uint8_t* buf;
                buf=(uint8_t *)malloc(len);
                assert(buf);
                memcpy(e_hdr->ether_dhost,e_hdr->ether_shost,ETHER_ADDR_LEN);
			    memcpy(e_hdr->ether_shost,if_match->addr,ETHER_ADDR_LEN);
                a_hdr->ar_op = htons(arp_op_reply);
                a_hdr->ar_tip = a_hdr->ar_sip;
                memcpy(a_hdr->ar_tha,a_hdr->ar_sha,ETHER_ADDR_LEN);
                memcpy(a_hdr->ar_sha,if_match->addr,ETHER_ADDR_LEN);
                a_hdr->ar_sip = if_match->ip;
                memcpy(buf,(uint8_t*)packet,len);
                sr_send_packet(sr,buf,len,interface);
                sr_arpcache_insert(&sr->cache,a_hdr->ar_tha,a_hdr->ar_tip); 

#ifdef MYDEBUG
				fprintf(stderr,"++++++++++++++++++ Sending ARP reply ++++++++++++++++++\n");
			    print_hdrs(buf,len);
				fprintf(stderr,"+++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
#endif

                free(buf);  
            }
            else {
                fprintf(stderr,"ARP request detail:\n");
                print_hdrs(packet,len);
            }
        }/* end Handle ARP request */
		else if( a_hdr->ar_op == htons(arp_op_reply) ) { /* Handle ARP reply */
			unsigned char broadcast_adr[ETHER_ADDR_LEN];
			struct sr_arpreq* req = 0; 
			memset(broadcast_adr,0xff,ETHER_ADDR_LEN);
			if(0 == memcmp(a_hdr->ar_tha,broadcast_adr,ETHER_ADDR_LEN)) {
				fprintf(stderr,"Hacky!! Source MAC is broadcast address on ARP reply (o_O)\n");
				return;
			}
			if(0 == a_hdr->ar_sip) {
				fprintf(stderr,"Invalid source IP in ARP reply (o_O)\n");
				return;
			}
			/* Not verifying the target IP */
			req = sr_arpcache_insert(&sr->cache,a_hdr->ar_sha,a_hdr->ar_sip);
			fprintf(stderr,"ARP cache updated for ");
			print_addr_eth(a_hdr->ar_sha);
			fprintf(stderr," <-> ");
			print_addr_ip_int(ntohl(a_hdr->ar_sip));
			fprintf(stderr,"\n");
			
			if(NULL != req) {
				/* Send all packets waiting in queue */
				while(req->packets) {
					fprintf(stderr,"SEND WAITING PACKETS\n");

					memcpy(((sr_ethernet_hdr_t*)req->packets->buf)->ether_dhost,a_hdr->ar_sha,ETHER_ADDR_LEN);
					memcpy(((sr_ethernet_hdr_t*)req->packets->buf)->ether_shost,a_hdr->ar_tha,ETHER_ADDR_LEN);
#ifdef MYDEBUG
					print_hdrs(req->packets->buf,req->packets->len);
#endif
					sr_send_packet(sr,req->packets->buf,req->packets->len,req->packets->iface);
					req->packets = req->packets->next;
				}
				sr_arpreq_destroy(&sr->cache, req);
			}
		}
    }/* end Handle ARP */
}/* end sr_ForwardPacket */

