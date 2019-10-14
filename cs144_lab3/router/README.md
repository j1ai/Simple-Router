CSC 458 Write-Up:

**Overview of the structure of your code**

- Router.c contains functions for:

1. Verifying checksums:
   1. verify\_ip\_header\_checksum() - verifies checksum of IP packet
   2. verify\_icmp\_packet\_checksum() - verifies checksum of ICMP packet
2. Setting up packet headers:
   1. sr\_setup\_new\_ethernet\_headers() - sets up header for a new ethernet packet
   2. sr\_setup\_new\_ip\_headers() - sets up header for a new IP packet
   3. sr\_setup\_new\_icmp3\_headers() - sets up header for a  new ICMP packet
3. Handling different types of packets:
   1. sr\_handlepacket() - determines whether to handle packet as an ARP or IP packet
   2. sr\_handle\_ip\_packet() - given an IP packet, determines which IP packet handler function should be called
   3. sr\_handle\_arp\_packet() - handles incoming ARP request packets to the router
   4. sr\_handle\_icmp\_ip\_packet() - handles incoming ICMP echo request packets to the router
   5. sr\_handle\_net\_unreachable\_ip\_packet() - sends a destination net unreachable ICMP response packet
   6. sr\_handle\_port\_unreachable\_ip\_packet() - sends a port unreachable ICMP response packet
   7. sr\_handle\_host\_unreachable\_ip\_packet() - sends a destination host unreachable ICMP response packet
   8. sr\_handle\_time\_exceeded\_ip\_packet() -  sends a time exceeded ICMP response packet
   9. sr\_handle\_foreign\_ip\_packet() - handles IP packets which are not for the router
4. Utility helper functions:
   1. sr\_get\_routing\_entry\_using\_lpm() - finds the routing entry using LPM
   2. is\_ip\_packet\_for\_me() - checks if an IP packet is for the router

- In arpcache.c:
  - handle\_arpreq() is responsible for resending ARP packets in case of a cache miss and sending  an ICMP host unreachable message if there is no response after an ARP packet is resent for over 5 times
  - sr\_arpcache\_sweepreqs() is responsible for checking whether we should resend a request or destroy the arp request by calling handle\_arpreq() for all packets in the queue every second

**Design decisions made**

Decision decisions were mostly made by the provided starter code. First, we realized that the file router.c contains a stubbed out function that is the entry point to all receiving packets. We knew that the stubbed out function needs to process packets like the first flowchart mentioned in the Tutorial 2 slides (the flowchart that determines what happens when the router receives an ARP packet)

Thus, out stubbed out function initially had code that will call one of the two helper functions (sr\_handle\_ip\_packet() or sr\_handle\_arp\_packet()) depending on whether it is an ARP packet or not.

Second, additional helper functions had to be made in the IP packet side of the flowchart, where the processing of the IP packet had to resemble the second flowchart mentioned in the Tutorial 2 slides.


Thus, additional helper functions had to be in the handling of the IP packet that will determine which path the IP packet should go.

In addition, helper functions were made to ease the development and sending of packets. For instance, the sr\_setup\_new\_ethernet\_headers(), sr\_setup\_new\_ip\_headers(), and sr\_setup\_new\_icmp3\_headers() helper functions are used to set up new IP packets.

In conclusion, the design of router.c was implemented based on the flow of a packet, and helper functions mark out each step of the flow.

**Ambiguities in the assignment itself, also list here how they were resolved in your implementation**

- The interfaces of the two different routers seem to be different every time we ran our solution locally. It was hard to debug whether our longest prefix match algorithm was correct, as the sr\_solution and our solution would generate different interfaces each time when we ran traceroute. We resolved it by testing it against the auto tester on markus.