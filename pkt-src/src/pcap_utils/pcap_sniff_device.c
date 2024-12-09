#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "../../include/pcap_utils/pcap_init.h"

pcap_result_e pcap_sniff_device(struct pcap_device_s *device, const char* interface_to_sniff) {
    
    struct pcap_if *pcap_device = device->capture;
    struct pcap_if *d;
    if (device == NULL) {
        fprintf(stderr, "No device available to sniff.\n");
        return PCAP_RET_FAIL;
    }
    fprintf(stderr, "Gragas: %s\n", device->errbuf);    
    for (d = pcap_device; d != NULL; d = d->next){
        printf("\tInterface to sniff: %s\n", d->name);
    //     if (interface_to_sniff == d->name) {
    //         printf("\t============\n");
    //         printf("\tInterface to sniff: %s\n", d->name);
    //         printf("\tDescription: %s\n", d->description);
    //         printf("\tNetMask Address: %s\n", d->description);

    //         if (d->addresses) {
    //             for (struct pcap_addr *p_addr = d->addresses; p_addr != NULL; p_addr = p_addr->next){
    //                 if (p_addr->addr->sa_family == AF_INET) { // IPv4 Address
    //                     struct sockaddr_in *ipv4 = (struct sockaddr_in *)p_addr->addr;
    //                     printf("\tIPv4 Address: %s\n", inet_ntoa(ipv4->sin_addr));

    //                     // Print the subnet mask
    //                     if (p_addr->netmask) {
    //                         struct sockaddr_in *netmask = (struct sockaddr_in *)p_addr->netmask;
    //                         printf("\tSubnet Mask: %s\n", inet_ntoa(netmask->sin_addr));
    //                     }
    //                 } else if(p_addr->addr->sa_family == AF_INET6) {
    //                     char buffer[INET6_ADDRSTRLEN];
    //                     struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p_addr->addr;
    //                     inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer, sizeof(buffer));
    //                     printf("\tIPv6 Address: %s\n", buffer);
    //                 }
    //             }
    //         } else {
    //             printf("\tAddresses: (No addresses available)\n");
    //         }
    //     }
        
    }



    return PCAP_RET_OK;
}