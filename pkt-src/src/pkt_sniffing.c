#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h>
#include "../include/pkt_analyzer.h"
#include "../include/pkt_headers.h"

void parse_ipv4(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    static int count = 1;

    const struct sniff_ethernet_packet *ethernet; /* The ethernet header */
    const l3_ipv4_header_t *ipv4; /* IPv4 header */

    uint8_t size_ip, version;

    printf("Packet number: %d\n", count);
    count++;

    /* Define ethernet header */
    ethernet  = (struct sniff_ethernet_packet*)(packet);
    printf("Ether type: 0x%04x\n", ntohs(ethernet->ether_type));

    /* define ip header offset */
    ipv4 = (l3_ipv4_header_t*)(packet + ETHERNET_HEADER_LEN);

    size_ip = ((ipv4->version_ihl) & 0x0f);
    size_ip*4 < 20 ? fprintf(stderr, "Invalid IP header\n") : printf("Valid header\n");

    version = ((ipv4->version_ihl) >> 4);

    printf("=== IPv4 Header ===\n");
    printf("Version: %u\n", version);
    printf("IHL (Header Length): %u (%u bytes)\n", size_ip, size_ip * 4);
    printf("Type of Service: 0x%02X\n", ipv4->tos);
    printf("Total Length: %u bytes\n", ntohs(ipv4->ip_length));
    printf("Identification: 0x%04X (%u)\n", ntohs(ipv4->ip_id), ntohs(ipv4->ip_id));
    
    uint16_t frag_offset = ntohs(ipv4->offset);
    uint8_t flags = (frag_offset >> 13) & 0x7;
    uint16_t offset = frag_offset & 0x1FFF;

    printf("Flags: 0x%X\n", flags);
    printf("Fragment Offset: %u\n", offset);
    printf("TTL: %u\n", ipv4->ttl);
    printf("Protocol: %u\n", ipv4->protocol);
    printf("Header Checksum: 0x%04X\n", ntohs(ipv4->checksum));
    printf("Source IP: %s\n", inet_ntoa(ipv4->src_addr));
    printf("Destination IP: %s\n", inet_ntoa(ipv4->dst_addr));
    printf("===================\n");

}
