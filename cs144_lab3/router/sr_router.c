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

void sr_init(struct sr_instance *sr)
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

/**
 * Handles incoming ARP packets
 * It will do the following:
 * 1. If it is an ARP request packet, then it will:
 *    a) Add the source IP address and the source MAC address to the ARP cache
 *    b) Look up the MAC address for the destination IP address and return a reply. But 
 *       if the destination IP address is not in the ARP cache, then we broadcast an ARP request
 *       in the other ports
 * 
 * 2. If it is an ARP reply packet, then it will:
 *        
 */
void sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) 
{
  /**
   * Get what type of ARP packet it is.
   * The ARP packet type is stored in the opcode as defined in http://www.networksorcery.com/enp/protocol/arp.html
   */

  /* Note that the ARP header is in the data section of the Ethernet packet */
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  printf("ARP packet request type: %u\n", (unsigned int) arp_header->ar_op);
  print_hdr_arp((uint8_t *) arp_header);

  /* Note that the number in arp_header->ar_op is in network format; we need it in the host's short format (little endian format)*/

  /* Checks if it is an ARP request */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    printf("Received ARP request packet!\n");
    print_addr_ip_int(ntohl(arp_header->ar_sip));
    print_addr_ip_int(ntohl(arp_header->ar_tip));

    /* Map the source's ip address and the source's MAC address to the ARP table */
    sr_arpcache_dump(&(sr->cache));
    struct sr_arpreq *arp_req = sr_arpcache_insert(&(sr->cache), (unsigned char *) arp_header->ar_sha, (uint32_t) arp_header->ar_sip);
    sr_arpcache_dump(&(sr->cache));
  }

  /* Checks if it is an ARP reply */
  else if (arp_header->ar_op == arp_op_reply) {
    printf("Received ARP reply packet!\n");
  }
  else {
    printf("ERROR! Unknown ARP packet!\n");
  }
}

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

void sr_handlepacket(struct sr_instance *sr,
        uint8_t *packet/* lent */,
        unsigned int len,
        char *interface/* lent */) 
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  /*
    So the specifications of an ARP packet is at: http://www.networksorcery.com/enp/protocol/arp.htm
    Note that an ARP packet is wrapped around the packet
   */
  struct sr_ethernet_hdr_t *ethernet_header = (struct sr_ethernet_hdr_t *) packet;
  uint16_t ethernet_type = ethertype((uint8_t *)ethernet_header);

  printf("Ethernet type: %u\n", (unsigned int) ethernet_type);

  /* Checks if it is an ARP packet */
  if (ethernet_type == ethertype_arp) {
    printf("Found ARP Packet!\n");
    sr_handle_arp_packet(sr, packet, len, interface);
  }
  
  /* Checks if it is an IP packet */
  else if (ethernet_type == ethertype_ip) {
    printf("Found IP packet!\n");
  }

  else {
    printf("ERROR! Cannot determine what ethernet type this is! Received ethernet type: %u\n", (unsigned int) ethernet_type);
  }
}/* end sr_ForwardPacket */


