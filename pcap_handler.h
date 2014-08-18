#include <pcap/pcap.h>

void init_pcap(char *dev);
void handle_packets(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *bytes);
int handle_ip(const u_char *bytes, const struct pcap_pkthdr *phdr);
