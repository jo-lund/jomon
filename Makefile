monitor : network_monitor.c pcap_handler.c
	gcc -lpcap -o monitor network_monitor.c pcap_handler.c
