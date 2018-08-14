# Monitor

This is a test of the README format.

## Protocols

### ARP

The fundamental concept behind ARP is that the network interface has a hardware
address (a 48 bit value for an Ethernet or token ring interface). Frames
exchanged at the hardware level must be addressed to the correct interface. But
TCP/IP work with its own addresses: 32 bit IPv4 or 128 bit IPv6 addresses.
Knowing a host's IP address doesn't let the kernel send a frame to that host.
The kernel (i.e., the Ethernet driver) must know the destination's hardware
address to send it data. The function of ARP is to provide a dynamic mapping
between IP addresses and the hardware addresses used by various network
technologies.

Gratuitous ARP occurs when a host sends an ARP request looking for its own IP
address. This is usually done when the interface is configured at bootstrap time.
This lets the host determine if another host is already configured with the same
IP address. The host is not expecting a reply to this request. But if a reply is
received, the error message "duplicate IP address sent from Ethernet address:
a:b:c:d:e:f" is logged on the console.
(cf. TCP/IP Illustrated)

#### ARP spoofing

Spoofing is the first step in sniffing packets on a switched network. When an
ARP reply comes in with an IP address that already exists in the ARP cache, the
receiving system will overwrite the prior MAC address information with the new
information found in the reply (unless the entry in the ARP cache was
explicitly marked permanent). Since no state information about ARP traffic is
kept, a system will accept an ARP reply even if it didn't send out a request.
cf. "Hacking: The art of exploitation"
https://en.wikipedia.org/wiki/ARP_spoofing

#### Links:

* https://tools.ietf.org/html/rfc826 (An Ethernet Address Resolution Protocol)
* https://wiki.wireshark.org/Gratuitous_ARP

### BGP (Border Gateway Protocol)

BGP4 is standard for Internet routing, required of most Internet service
providers (ISPs) to establish routing between one another. Very large private IP
networks use BGP internally. An example is the joining of a number of large Open
Shortest Path First (OSPF) networks, when OSPF by itself does not scale to the
size required. Another reason to use BGP is multihoming a network for better
redundancy, either to multiple access points of a single ISP or to multiple
ISPs.
 -- https://en.wikipedia.org/wiki/Border_Gateway_Protocol

Links:
* https://en.wikipedia.org/wiki/Border_Gateway_Protocol
* https://tools.ietf.org/html/rfc4271 (A Border Gateway Protocol 4 (BGP-4))
