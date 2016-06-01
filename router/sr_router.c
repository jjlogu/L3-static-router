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
	struct sr_ethernet_hdr* e_hdr = 0;
        struct sr_arp_hdr*      a_hdr = 0;
        struct sr_if* if_walker = 0;
 
        /* REQUIRES */
        assert(sr);
        assert(packet);
        assert(interface);
 
        if(len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr)) {
                fprintf(stderr, "Invalid packet header length\n");
                return;
        }
        printf("*** -> Received packet of length %d \n",len);
 
        e_hdr = (struct sr_ethernet_hdr*)packet;
        a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
 
	/* Handle ARP request */
        if ( (e_hdr->ether_type == htons(ethertype_arp)) && (a_hdr->ar_op == htons(arp_op_request)) ) {
		/* if ARP request is for one of router's interface, send ARP reply*/
                if_walker = sr->if_list;
                while(if_walker) {
                        if(if_walker->ip == a_hdr->ar_tip) {
				uint8_t* buf;
				buf=(uint8_t *)malloc(len);
				assert(buf);
				memcpy(e_hdr->ether_dhost,e_hdr->ether_shost,ETHER_ADDR_LEN);
				memcpy(e_hdr->ether_shost,if_walker->addr,ETHER_ADDR_LEN);
				a_hdr->ar_op = htons(arp_op_reply);
				a_hdr->ar_tip = a_hdr->ar_sip;
				memcpy(a_hdr->ar_tha,a_hdr->ar_sha,ETHER_ADDR_LEN);
				memcpy(a_hdr->ar_sha,if_walker->addr,ETHER_ADDR_LEN);
				a_hdr->ar_sip = if_walker->ip;
				memcpy(buf,(uint8_t*)packet,len);
				sr_send_packet(sr,buf,len,interface);
				sr_arpcache_insert(&sr->cache,a_hdr->ar_tha,a_hdr->ar_tip);
				print_hdrs(buf,len);
				free(buf);	
				
				/* Print ARP cache */
				/* sr_arpcache_dump(&sr->cache); */
				break;
                        }
                        if_walker = if_walker->next;
                }
        }
}/* end sr_ForwardPacket */

