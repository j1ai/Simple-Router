#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>

#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* This file defines an ARP cache, which is made of two structures: an ARP
   request queue, and ARP cache entries. The ARP request queue holds data about
   an outgoing ARP cache request and the packets that are waiting on a reply
   to that ARP cache request. The ARP cache entries hold IP->MAC mappings and
   are timed out every SR_ARPCACHE_TO seconds.

   Pseudocode for use of these structures follows.

   --

   # When sending packet to next_hop_ip
   entry = arpcache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)

   --

   The handle_arpreq() function is a function you should write, and it should
   handle sending ARP requests if necessary:

   function handle_arpreq(req):
       if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++

   --

   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpcache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)

   --

   To meet the guidelines in the assignment (ARP requests are sent every second
   until we send 5 ARP requests, then we send ICMP host unreachable back to
   all packets waiting on this ARP request), you must fill out the following
   function that is called every second and is defined in sr_arpcache.c:

   void sr_arpcache_sweepreqs(struct sr_instance *sr) {
       for each request on sr->cache.requests:
           handle_arpreq(request)
   }

   Since handle_arpreq as defined in the comments above could destroy your
   current request, make sure to save the next pointer before calling
   handle_arpreq when traversing through the ARP requests linked list.
 */

/**
 * This function handles whether to send the ARP packet or not based on certain conditions:
 *
 * 1. If the ARP packet is sent less than 5 times and the time between resending the
 *    ARP packet is greater than 1 second:
 *    - Then, we resend the ARP packet
 *
 * 2. If we already sent the ARP packet for 5 times;
 *    - Then we send an ICMP unreachable message
 *
 * 3. If the time between resending the ARP packet is less than 1 second:
 *    - We just ignore it
 *
 */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request) {
    /** Get the current system time */
    time_t cur_time;
    time (&cur_time);

    /** Check if the time sent before is greater than 1 second */
    if (difftime(cur_time, request->sent) > 1.0) {

        /** Check if the number of times sent is greater than 5*/
        if (request->times_sent >= 5) {
	     printf("ARP times_sent >= 5!\n");
           /**
            * Send ICMP host unreachable to the source address of all packets
            * waiting on this request
            */
           struct sr_packet *cur_packet = request->packets;
           while (cur_packet != NULL) {
                sr_handle_host_unreachable_ip_packet(sr, cur_packet->buf,  cur_packet->len, cur_packet->iface);
                cur_packet = cur_packet->next;
           }

           /** Destroy the request from the cache */
           sr_arpreq_destroy(&(sr->cache), request);

        } else {
	        printf("Sent arp request %d!\n", request->times_sent + 1);
            
            request->sent = cur_time;
            request->times_sent += 1;

            int arp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *arp_packet = malloc(arp_packet_len);

            /* Add fields to ethernet packet */
            struct sr_if *src_interface = sr_get_interface(sr, request->packets->iface);
            sr_ethernet_hdr_t *arp_packet_eth_headers = (sr_ethernet_hdr_t *) arp_packet;
            int i = 0;
            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                arp_packet_eth_headers->ether_dhost[i] = 255;          
            }
            memcpy(arp_packet_eth_headers->ether_shost, src_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            arp_packet_eth_headers->ether_type = htons(ethertype_arp);
    
            /* Set ARP header */
            sr_arp_hdr_t *arp_packet_arp_headers = (sr_arp_hdr_t *) (arp_packet + sizeof(sr_ethernet_hdr_t));
            arp_packet_arp_headers->ar_hrd = htons(arp_hrd_ethernet);
            arp_packet_arp_headers->ar_pro = htons(ethertype_ip);
            arp_packet_arp_headers->ar_hln = ETHER_ADDR_LEN;
            arp_packet_arp_headers->ar_pln = 4;
            arp_packet_arp_headers->ar_op  = htons(arp_op_request);

            memcpy(arp_packet_arp_headers->ar_sha, src_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            arp_packet_arp_headers->ar_sip = src_interface->ip;

            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                arp_packet_arp_headers->ar_tha[i] = 255;
            }
            arp_packet_arp_headers->ar_tip = request->ip;

            printf("ARP Packet below!! \n");
	        print_hdrs(arp_packet, arp_packet_len);

            if (sr_send_packet(sr, arp_packet, arp_packet_len, src_interface) != 0) {
                fprintf(stderr, "ERROR: Cannot send ARP Request packet\n");

            } else {
                printf("Sent ARP Request!!\n");
            }
            free(arp_packet);
        }
    }
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq *cur_request = sr->cache.requests;
    while (cur_request != NULL) {
        struct sr_arpreq *next_request = cur_request->next;
        handle_arpreq(sr, cur_request);
        cur_request = next_request;
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