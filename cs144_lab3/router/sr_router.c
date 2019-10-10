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

/**
 * Verifies if an IP header's checksum is correct
 * Returns 1 if it is correct; else returns 0
*/
int verify_ip_header_checksum(sr_ip_hdr_t *ip_header) {
  uint16_t actual_checksum = ip_header->ip_sum;

  ip_header->ip_sum = 0;
  uint16_t expected_checksum = cksum((uint8_t *) ip_header, sizeof(sr_ip_hdr_t));
  ip_header->ip_sum = actual_checksum;

  printf("Actual checksum: %d Expected checksum: %d\n", actual_checksum, expected_checksum);
  if (actual_checksum == expected_checksum) {
    return 1;
  }
  return 0;
}

/** 
 * Verifies if the ICMP header's checksum is correct.
 * Note that it will need the total length of the packet.
 * Returns 1 if it is correct; else returns 0.
 */
int verify_icmp_packet_checksum(sr_icmp_hdr_t *icmp_header, int len) {
  uint16_t actual_checksum = icmp_header->icmp_sum;

  icmp_header->icmp_sum = 0;
  uint16_t expected_checksum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  icmp_header->icmp_sum = actual_checksum;

  printf("Actual checksum: %d Expected checksum: %d\n", actual_checksum, expected_checksum);
  if (actual_checksum == expected_checksum) {
    return 1;
  }
  return 0;
}

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
 * TODO: This function needs some testing
 * 
 *---------------------------------------------------------------------*/
void sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) 
{
  /** Check that the packet's length is valid */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "ERROR: ARP Packet does not meet min. length!\n");
  }

  /* Note that the ARP header is in the data section of the Ethernet packet */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Checks if it is an ARP request */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    printf("Received ARP request packet!\n");

    /* Check if it is targetted to the router */
    unsigned char *router_ether_add = sr_get_ether_addr(sr, arp_header->ar_tip);

    /* If the entry is not there */
    if (router_ether_add == NULL) {
      fprintf(stderr, "ERROR: Failed to handle ARP packet not for the router!\n");

    } else {
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
        fprintf(stderr, "ERROR: Packet sent unsuccessfully\n");
      }

      free(router_ether_add);
      free(new_packet);
    }

  } else if (arp_header->ar_op == arp_op_reply) {
    printf("Got ARP reply packet!\n");

    /**
     * If it is an incoming ARP reply packet for the router, that means that earlier in time, 
     * we have sent an ARP request from the router to the network.
     * This occurs when we receive an IP packet which has an IP address that we don't recognize
     * 
     * Thus, what we have to do is to insert the IP and the MAC address from the ARP reply packet
     * to our ARP cache, get the IP packets that we wanted to send (but has failed because we were
     * unable to get the MAC address of the destination), and resend the IP packets
     */

    /** unsigned char *dst_mac_address = arp_header->ar_tha; */

    unsigned char *src_mac_address = arp_header->ar_sha;
    uint32_t src_ip_address = arp_header->ar_sip;

    struct sr_arpreq *arp_request = sr_arpcache_insert(&sr->cache, src_mac_address, src_ip_address);

    /** Resend the packets in the ARP request */
    if (arp_request != NULL) {
      struct sr_packet *cur_packet = arp_request->packets;
      while (cur_packet != NULL) {

        /** Get details about the packet */
        int packet_len = cur_packet->len;
        uint8_t *packet = cur_packet->buf;
        char *iface = cur_packet->iface;

        /** Inject the ARP reply's src MAC address to the packet we want to send */
        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
        memcpy(ethernet_header->ether_dhost, src_mac_address, sizeof(uint8_t) * ETHER_ADDR_LEN);

        /** Send the packet */
        sr_send_packet(sr, packet, packet_len, iface);

        cur_packet = cur_packet->next;
      }

      sr_arpreq_destroy(&sr->cache, arp_request);
    }
  } else {
    fprintf(stderr, "ERROR! Unknown ARP packet!\n");
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
 * TODO: This function needs some testing
 *
 *---------------------------------------------------------------------*/
void sr_handle_icmp_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  printf("Received ICMP IP Packet!\n");

  /* Check to see if it is a valid ICMP packet */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
    fprintf(stderr, "ERROR: Packet did not meet ICMP IP Packet's min. length!\n");
    return;
  }

  /* Get the ethernet header */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Get the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get the ICMP header */
  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  if (verify_icmp_packet_checksum(icmp_header, len) != 1) {
    fprintf(stderr, "ERROR: ICMP IP packet's checksum is incorrect\n");
    return;
  }

  /* Check if it is a ECHO request. If so, send a ECHO reply */
  if (icmp_header->icmp_type == 0x8) {
    printf("Received ICMP IP Echo Request Packet!\n");

    /** 
     * According to http://www.networksorcery.com/enp/protocol/icmp/msg0.htm#targetText=All%20ICMP%20Echo%20Reply%20messages,in%20the%20resulting%20Echo%20Reply,
     * we need to send an exact copy of the packet, and only change a few things
    */

    /* Swap the source and destination MAC addresses */
    uint8_t new_ether_dhost[6];
    uint8_t new_ether_shost[6];
    memcpy(new_ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(new_ether_shost, ethernet_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_dhost, new_ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_shost, new_ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

    /* Swap the source and destination IP addresses */
    uint32_t new_ip_src = ip_header->ip_dst;
    uint32_t new_ip_dst = ip_header->ip_src;
    ip_header->ip_src = new_ip_src;
    ip_header->ip_dst = new_ip_dst;
    ip_header->ip_ttl = ip_header->ip_ttl - 1;

    /* Change the ICMP type and code */
    icmp_header->icmp_code = 0;
    icmp_header->icmp_type = 0;

    /* Recompute the checksum in the IP header */
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

    /* Recompute the checksum in the ICMP header */
    /* Note that the ICMP checksum only uses the ICMP header values not the packet data */
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    /* Send the packet */
    sr_send_packet(sr, packet, len, interface);
    printf("Sent ICMP Reply Packet!\n");

  } else {
    /* TODO: Do something if it is not a ECHO request*/
    fprintf(stderr, "TODO: Cannot handle non-ECHO request packets!\n");
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_net_unreachable_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when the router receives an Non-Existent route to destination IP
 * (no matching entry in routing table).
 *
 *---------------------------------------------------------------------*/
void sr_handle_net_unreachable_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  printf("Received Net Unreachable IP Packet!\n");

  /* Get the ethernet header */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Get the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get the ICMP header */
  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));


  /* Swap the source and destination MAC addresses */
  uint8_t new_ether_dhost[6];
  uint8_t new_ether_shost[6];
  memcpy(new_ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(new_ether_shost, ethernet_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_dhost, new_ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, new_ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

  /* Swap the source and destination IP addresses */
  uint32_t new_ip_src = ip_header->ip_dst;
  uint32_t new_ip_dst = ip_header->ip_src;
  ip_header->ip_src = new_ip_src;
  ip_header->ip_dst = new_ip_dst;

  ip_header->ip_p = 1;
  ip_header->ip_ttl = ip_header->ip_ttl - 1;

  /* Change the ICMP type and code */
  icmp_header->icmp_code = 0;
  icmp_header->icmp_type = 3;

  /* Recompute the checksum in the IP header */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Recompute the checksum in the ICMP header */
  /* Note that the ICMP checksum only uses the ICMP header values not the packet data */
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  printf("Sending ICMP Net Unreachable Reply Packet:\n");
  print_hdrs(packet, len);

  /* Send the packet */
  sr_send_packet(sr, packet, len, interface);
  printf("Sent ICMP Net Unreachable Reply Packet!\n");
}

/*---------------------------------------------------------------------
 * Method: sr_handle_host_unreachable_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when the router receives an IP TCP/ UDP packet.
 *
 *---------------------------------------------------------------------*/
void sr_handle_port_unreachable_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  printf("Received Port Unreachable IP Packet!\n");

  /* Get the ethernet header */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Get the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get the ICMP header */
  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Swap the source and destination MAC addresses */
  uint8_t new_ether_dhost[6];
  uint8_t new_ether_shost[6];
  memcpy(new_ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(new_ether_shost, ethernet_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_dhost, new_ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, new_ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

  /* Swap the source and destination IP addresses */
  uint32_t new_ip_src = ip_header->ip_dst;
  uint32_t new_ip_dst = ip_header->ip_src;
  ip_header->ip_src = new_ip_src;
  ip_header->ip_dst = new_ip_dst;

  ip_header->ip_p = 1;
  ip_header->ip_ttl = ip_header->ip_ttl - 1;

  /* Change the ICMP type and code */
  icmp_header->icmp_code = 3;
  icmp_header->icmp_type = 3;

  /* Recompute the checksum in the IP header */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Recompute the checksum in the ICMP header */
  /* Note that the ICMP checksum only uses the ICMP header values not the packet data */
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  /* Send the packet */
  sr_send_packet(sr, packet, len, interface);
  printf("Sent ICMP Port Unreachable Reply Packet!\n");
}

/*---------------------------------------------------------------------
 * Method: sr_handle_host_unreachable_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when five ARP requests were sent to next-hop IP without a response.
 *
 *---------------------------------------------------------------------*/
void sr_handle_host_unreachable_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  printf("Received Host Unreachable IP Packet!\n");

  /* Get the ethernet header */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Get the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get the ICMP header */
  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Swap the source and destination MAC addresses */
  uint8_t new_ether_dhost[6];
  uint8_t new_ether_shost[6];
  memcpy(new_ether_dhost, ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(new_ether_shost, ethernet_header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_dhost, new_ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, new_ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

  /* Swap the source and destination IP addresses */
  uint32_t new_ip_src = ip_header->ip_dst;
  uint32_t new_ip_dst = ip_header->ip_src;
  ip_header->ip_src = new_ip_src;
  ip_header->ip_dst = new_ip_dst;

  ip_header->ip_p = 1;
  ip_header->ip_ttl = ip_header->ip_ttl - 1;

  /* Change the ICMP type and code */
  icmp_header->icmp_code = htons(1);
  icmp_header->icmp_type = htons(3);

  /* Recompute the checksum in the IP header */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Recompute the checksum in the ICMP header */
  /* Note that the ICMP checksum only uses the ICMP header values not the packet data */
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  /* Send the packet */
  sr_send_packet(sr, packet, len, interface);
  printf("Sent ICMP Host Unreachable Reply Packet!\n");
}

/*---------------------------------------------------------------------
 * Method: sr_handle_time_exceeded_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when the router receives an IP packet that it's TTL is equal to 0
 *
 *---------------------------------------------------------------------*/
void sr_handle_time_exceeded_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
  /* TODO: Do something if the IP packet TTL is0 */
  printf("Received TTL execeeded IP Packet!\n");
}


/*---------------------------------------------------------------------
 * Method: sr_handle_foreign_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * Scope:  Local
 *
 * This method is called when the router receives an IP packet not destined for this router.
 *
 *---------------------------------------------------------------------*/
void sr_handle_foreign_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{

  /* TODO: Do something if the IP packet is not for this router */
  printf("Received Foreign IP Packet!\n");

  /* Get the ethernet header */
  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;

  /* Get the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_header->ip_ttl <= 1){
    sr_handle_time_exceeded_ip_packet(sr, packet, len, interface);
    return;
  }

  struct sr_rt *routing_entry = sr->routing_table;
  struct sr_if *outgoing_interface = NULL;

  while(routing_entry){
    uint32_t cur_route = ip_header->ip_dst & routing_entry->mask.s_addr;
    if (cur_route == routing_entry->dest.s_addr){
        outgoing_interface = sr_get_interface(sr,routing_entry->interface);
        break;
    }
    routing_entry = routing_entry->next;
  }

  /** If there is a matched outgoing interface from routing table */
  if(outgoing_interface){

    /* Swap the source MAC addresses */
    memcpy(ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);

    /** Search the ARP Cache */
    struct sr_arpentry *arp_cache_entry = sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst);

    /** If arp cache entry is hit */
    if(arp_cache_entry){
        /** Send frame to next hop */
    }
    else{
        /** Send ARP request */
    }

  }
  /** ICMP Net Unreachable */
  else{
    sr_handle_net_unreachable_ip_packet(sr,packet,len,interface);
  }
}

/**
 * Returns 1 if it is the packet for the router; else return 0
 */
int is_ip_packet_for_me(struct sr_instance *sr, uint32_t ip_dest){  
  print_addr_ip_int(ip_dest);
  struct sr_if *temp_if_list = sr->if_list;
  while(temp_if_list){
    print_addr_ip_int(temp_if_list->ip);
    if (temp_if_list->ip == ip_dest){
        return 1;
    }
    temp_if_list = temp_if_list->next;
  }
  return 0;
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
  /** Check that the packet meets min. length */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "ERROR: Packet did not meet min. IP header's length requirements!\n");
    return;
  }
  
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  if (verify_ip_header_checksum(ip_header) != 1) {
    fprintf(stderr, "ERROR: IP Header's checksum is incorrect!\n");
    return;
  } 

  if (is_ip_packet_for_me(sr, ip_header->ip_dst) == 1) {
    
    /** Get the protocol of the IP packet */
    uint8_t ip_proto = ip_protocol((uint8_t *) ip_header);

    if (ip_proto == ip_protocol_icmp) {
      sr_handle_icmp_ip_packet(sr, packet, len, interface);

    } else if (ip_proto == ip_protocol_tcp || ip_proto == ip_protocol_udp) {
      sr_handle_port_unreachable_ip_packet(sr, packet, len, interface);
    }

  } else {
    sr_handle_foreign_ip_packet(sr, packet, len, interface);
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
 * Note: if the packet is an ARP packet, it will always be destined for the
 * router. This is because if the packet is not for the router, it would
 * have already been handled in the sr_arp_req_not_for_us() in sr_vns_comm.c
 * file.
 * 
 * TODO: This function needs some testing
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

  /** Check if it meets the ethernet packet size */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "ERROR: Packet does not meet min. length requirements!\n");
    return;
  }

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
    fprintf(stderr, "TODO: Cannot determine what ethernet type this is! Received ethernet type: %u\n", (unsigned int) ethernet_type);
    /* TODO: Do something for unknown packet type */
  }
}/* end sr_ForwardPacket */


