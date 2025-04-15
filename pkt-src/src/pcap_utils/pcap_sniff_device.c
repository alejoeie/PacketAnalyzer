#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "../../include/pcap_utils/pcap_init.h"
#include "../../include/pkt_sniffing.h"

pcap_result_e pcap_sniff_device(char device_list[PCAP_MAX_DEVS][PCAP_MAX_NAME_LEN], const char* interface_to_sniff, const int size) {
    pcap_t *interface_handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promiscous_mode = 1;
    int sniff_timeout = 1000; // Miliseconds
    struct bpf_program fp;		/* The compiled filter expression */
    char *filter_exp = "ip";
    bpf_u_int32 mask;		/* Netmask */
    bpf_u_int32 ip_addr;		/* IPv4 IP address for sniffed device */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const uint8_t *packet;		/* The actual packet */
    int num_packets = 2; /* TBD: let the user decide how many packets are about to be sniffed */

    int ret;

    for (int i = 0; i < size; i++) {

        printf("Interface for sniffing :%s | %s\n", device_list[i], interface_to_sniff);
        
        if (strcmp(device_list[i], interface_to_sniff) == 0) {
            // Get netmask and ip address from packet
            ret = pcap_lookupnet(device_list[i], &ip_addr, &mask, errbuf);
            if (ret == -1) {
                fprintf(stderr, "Cannot get mask for device %s: %s\n", device_list[i], errbuf);
            }

            interface_handler = pcap_open_live(
                interface_to_sniff,
                2048,
                promiscous_mode,
                sniff_timeout,
                errbuf
            );

            if (interface_handler == NULL) {
                fprintf(stderr, "Could not open device %s\n", errbuf);
                return PCAP_RET_FAIL;
            }

            /* make sure we're capturing on an Ethernet device */
	        if (pcap_datalink(interface_handler) != DLT_EN10MB) {
	        	fprintf(stderr, "%s is not an Ethernet device\n", device_list[i]);
	        	exit(EXIT_FAILURE);
	        }

            ret = pcap_compile(interface_handler, &fp, filter_exp, 0, ip_addr);
            if (ret == -1) {
                fprintf(stderr, "Could not parse filter for compilation on device %s : %s\n", device_list[i], pcap_geterr(interface_handler));
                return PCAP_RET_FAIL;
            }

            ret = pcap_setfilter(interface_handler, &fp);
            if (ret == -1) {
                fprintf(stderr, "Could not install filter %s : %s\n", filter_exp, pcap_geterr(interface_handler));
                return PCAP_RET_FAIL;
            }

            packet = pcap_next(interface_handler, &header);
            if (packet == NULL) {
                fprintf(stderr, "Could not sniff packet\n");
            }
            printf("Total length of the packet captured: [%d]\n", header.len);

            /* now we can set our callback function */
	        ret = pcap_loop(interface_handler, num_packets, parse_ipv4, NULL);
            if (0 != ret) {
                fprintf(stderr, "Failed to sniff packets\n");
            }

            pcap_close(interface_handler);
             
        }
    }

    return PCAP_RET_OK;
}