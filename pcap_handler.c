#include "pcap_handler.h"
#include "misc.h"

void init_pcap(char *device)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char str_addr[INET_ADDRSTRLEN];
    bpf_u_int32 net, mask;
    int datalink;
    pcap_t *pcap_handle;
    struct sockaddr addr;
    //struct sockaddr_in *laddr;

    /* 
     * Get the default network device if no device is specified and not ona a 
     * Linux system (a device argument of "any" or NULL can be used to capture
     * packets from all interfaces on Linux). It issues the SIOCGIFCONF ioctl
     * and chooses the lowest numbered device that is up except for the loopback.
     */
#ifndef linux
    if (!device && (device = pcap_lookupdev(errbuf)) == NULL)
        err_quit(errbuf);
#endif

    // Get the IPv4 address for this device
    if (get_local_address(device, &addr) == -1)
        exit(1);
    
    local_addr = (struct sockaddr_in *) &addr;
    inet_ntop(AF_INET, &local_addr->sin_addr, str_addr, sizeof(str_addr));

    printf("Listening on interface: %s\n", device);
    if (verbose)
        printf("Local IPv4 address: %s\n", str_addr);

    // Create and activate a packet capture handle
    if (!(pcap_handle = pcap_open_live(device, SNAPLEN, promiscuous, TIME_TO_WAIT, 
                                       errbuf)))
        err_quit(errbuf);
    
    // get the link-layer header type
    datalink = pcap_datalink(pcap_handle);

    // datalink types are defined in net/bpf.h (MAC OS X)
    switch (datalink) {
    case DLT_EN10MB:
        if (verbose)
            printf("Datalink: Ethernet\n");
        if (pcap_loop(pcap_handle, 0, handle_packets, (u_char *) pcap_handle) < 0)
            pcap_perror(pcap_handle, NULL);
        break;
    case DLT_IEEE802:
        printf("Datalink: IEEE 802.X\n");
        break;
    default:
        printf("Datalink type not supported: %d\n", datalink);
        break;
    }
}

void handle_packets(u_char *arg, const struct pcap_pkthdr *phdr, const u_char *bytes)
{
    struct ether_header *eth_hdr = (struct ether_header *) bytes;
    pcap_t *pcap_handle = (pcap_t *) arg;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        if (check_ip(bytes + ETHER_HDR_LEN) != -1) {
            handle_ip(bytes + ETHER_HDR_LEN, phdr);
        }
    }
}

int handle_ip(const u_char *bytes, const struct pcap_pkthdr *phdr)
{
    char src_addr[INET_ADDRSTRLEN], dst_addr[INET_ADDRSTRLEN];
    struct ip *ip = (struct ip *) bytes;
    char str_addr[INET_ADDRSTRLEN];
    double kbps = 0.0;
    struct timeval tp;
    static unsigned long dbytes = 0;
    static double secs, psecs;

    inet_ntop(AF_INET, &ip->ip_src, src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->ip_dst, dst_addr, INET_ADDRSTRLEN);
    //printf("Protocol: %d\n", ip->ip_p);

    //inet_ntop(AF_INET, &local_addr->sin_addr, str_addr, sizeof(str_addr));
    //printf("local address: %s\n", str_addr);
    
    secs = phdr->ts.tv_usec;

    if (memcmp(&ip->ip_src, &local_addr->sin_addr, sizeof(ip->ip_src)) == 0) {
        num_packets_sent++;
        tot_bytes_sent += phdr->len;
    }
    if (memcmp(&ip->ip_dst, &local_addr->sin_addr, sizeof(ip->ip_dst)) == 0) {
        num_packets_rcvd++;
        tot_bytes_rcvd += phdr->len;
        dbytes += phdr->len;
 
        double dkb = (double) phdr->len / 1024;
        double dt = (secs / 100000) - (psecs / 100000);
        kbps = dkb / dt;
        printf("dkb = %f, dt = %f, ", dkb, dt);
        printf("KB/s : %f    \n", kbps);
 
        /*
        if (secs - psecs == 1) {
            kbps = (double) dbytes / 1024;
            printf("kB/s: %f  \r", kbps);
            //printf("secs: %lu\n", secs);
            fflush(stdout);
            dbytes = 0;
        }
        */
    }
    
    psecs = secs;
    //printf("src: %14s, dst: %14s\n", src_addr, dst_addr);
    //printf("size of packet: %lu\n", sizeof(bytes));
    //printf("Packets sent: %5u (%lu)   ", num_packets_sent, tot_bytes_sent);
    //printf("Packets rcvd: %5u (%lu) \t", num_packets_rcvd, tot_bytes_rcvd);
    //printf("secs = %5u, psecs = %5u \r", secs, psecs);
    //printf("Time: %5f    \r", time);

    return 0;
}
