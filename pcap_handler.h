//#include <pcap/pcap.h>

/* Initialize PCAP */
void init_pcap(char *dev);

/* Callback to be called when PCAP gets packets from the kernel */
void handle_packets(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *bytes);

/* Handle IP packets */
int handle_ip(const u_char *bytes, const struct pcap_pkthdr *phdr);
