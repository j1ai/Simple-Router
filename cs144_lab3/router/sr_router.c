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
#include <stdlib.h>
#include <assert.h>
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

/*---------------------------------------------------------------------
 * Method: sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when the router receives an ARP packet.
 * It will do the following things:
 * 1) If it is a ARP request packet:
 *    a) If it is for the router, then it will return an ARP reply with the router's MAC address
 *    b) If it is not for the router, then ...
 * 
 * 2) If it is an ARP reply packet:
 *    a)
 *    b)
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) 
{
  /* Note that the ARP header is in the data section of the Ethernet packet */
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Checks if it is an ARP request */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    printf("Received ARP request packet!\n");

    /* Check if it is targetted to the router */
    unsigned char *router_ether_add = sr_get_ether_addr(sr, arp_header->ar_tip);

    /* If the entry is not there */
    if (router_ether_add == NULL) {
      /* do something */
    }

    /* If the entry is there */
    else {
      /* Create a new ethernet packet */
      uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

      /* Add fields to the ethernet packet */
      sr_ethernet_hdr_t *new_packet_eth_headers = (sr_ethernet_hdr_t *) new_packet;
      memcpy(new_packet_eth_headers->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(new_packet_eth_headers->ether_shost, router_ether_add, sizeof(uint8_t) * ETHER_ADDR_LEN);
      new_packet_eth_headers->ether_type = htons(ethertype_arp);

      /* Set the ARP header */
      sr_arp_hdr_t *new_packet_arp_headers = (sr_arp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
      new_packet_arp_headers->ar_hrd = arp_header->ar_hrd;
      new_packet_arp_headers->ar_pro = arp_header->ar_pro;
      new_packet_arp_headers->ar_hln = arp_header->ar_hln;
      new_packet_arp_headers->ar_pln = arp_header->ar_pln;
      new_packet_arp_headers->ar_op = htons(arp_op_reply);

      memcpy(new_packet_arp_headers->ar_sha, router_ether_add, sizeof(unsigned char) * ETHER_ADDR_LEN);
      new_packet_arp_headers->ar_sip = arp_header->ar_tip;
      memcpy(new_packet_arp_headers->ar_tha, arp_header->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);
      new_packet_arp_headers->ar_tip = arp_header->ar_sip;

      printf("Built new ARP reply packet:\n");
      print_hdrs(new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

      /* Return a ARP reply */
      if (sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface) != 0) {
        printf("ERROR: Packet sent unsuccessfully\n");
      }

      free(router_ether_add);
      free(new_packet);
    }
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
 * Method: sr_handle_icmp_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when the router receives an IP ICMP packet.
 * It will do the following things:
 * 1) If it is a ICMP Echo Request:
 *    Then it will send out an ICMP Echo response
 * 
 * 2) 
 *
 *---------------------------------------------------------------------*/
void sr_handle_icmp_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  printf("Received ICMP IP Packet!\n");

  /* Check to see if it is a valid ICMP packet */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
    fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
    return;
  }

  /* Get the ethernet header */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Get the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get the ICMP header */
  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Check if it is a ECHO request. If so, send a ECHO reply */
  if (icmp_header->icmp_type == 0x8) {
    printf("Received ICMP IP Echo Request Packet!\n");

    /* Create a new ethernet packet */
    int new_packet_length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    uint8_t *new_packet = malloc(new_packet_length);

    /* Set up the ethernet packet */
    sr_ethernet_hdr_t *new_packet_eth_headers = (sr_ethernet_hdr_t *) new_packet;
    memcpy(new_packet_eth_headers->ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(new_packet_eth_headers->ether_shost, ethernet_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    new_packet_eth_headers->ether_type = htons(ethertype_ip);

    /* Set up the IP header */
    sr_ip_hdr_t *new_packet_ip_headers = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    new_packet_ip_headers->ip_v = ip_header->ip_v;
    new_packet_ip_headers->ip_hl = ip_header->ip_hl;
    new_packet_ip_headers->ip_tos = ip_header->ip_tos;  /* ?? */
    new_packet_ip_headers->ip_len = ip_header->ip_len;  /* ?? */
    new_packet_ip_headers->ip_id = ip_header->ip_id;   /* ?? */
    new_packet_ip_headers->ip_off = ip_header->ip_off;  /* ?? */
    new_packet_ip_headers->ip_ttl = ip_header->ip_ttl - 1;  /* ?? */
    new_packet_ip_headers->ip_p = htons(ip_protocol_icmp);    /* ?? */
    new_packet_ip_headers->ip_sum = ip_header->ip_sum;  /* ?? */
    new_packet_ip_headers->ip_src = ip_header->ip_dst;
    new_packet_ip_headers->ip_dst = ip_header->ip_src;

    /* Set up the ICMP header */
    sr_icmp_hdr_t *new_packet_icmp_headers = (sr_icmp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t));
    new_packet_icmp_headers->icmp_type = 0;
    new_packet_icmp_headers->icmp_code = 0;
    new_packet_icmp_headers->icmp_sum = 0; /* ?? */

    print_hdrs(packet, new_packet_length);
    print_hdrs(new_packet, new_packet_length);

    /* Send the packet */
    sr_send_packet(sr, new_packet, new_packet_length, interface);

    free(new_packet);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called to handle when an IP packet is received.
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_proto == ip_protocol_icmp) {
    sr_handle_icmp_ip_packet(sr, packet, len, interface);

  } else {
    /* Do something if it is not an ICMP IP Packet */
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
  print_hdrs(packet, len);

  /*
    So the specifications of an ARP packet is at: http://www.networksorcery.com/enp/protocol/arp.htm
    Note that an ARP packet is wrapped around the packet
   */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
  uint16_t ethernet_type = ethertype((uint8_t *) ethernet_header);
  
  /* Checks if it is an IP packet */
  if (ethernet_type == ethertype_ip) {
    printf("Found IP packet!\n");
    sr_handle_ip_packet(sr, packet, len, interface);
  }

  /* Checks if it is an ARP packet */
  else if (ethernet_type == ethertype_arp) {
    printf("Found ARP Packet!\n");
    sr_handle_arp_packet(sr, packet, len, interface);
  }

  else {
    printf("ERROR! Cannot determine what ethernet type this is! Received ethernet type: %u\n", (unsigned int) ethernet_type);
  }
}/* end sr_ForwardPacket */


