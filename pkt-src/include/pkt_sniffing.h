#ifndef PKT_LAYER_HEADERS_H
#define PKT_LAYER_HEADERS_H

void parse_ipv4(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif