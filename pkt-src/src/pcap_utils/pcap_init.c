#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "../../include/pcap_utils/pcap_init.h"

struct pcap_device_s  *pkt_pcap_alloc_device(void){
    struct pcap_device_s *device = (struct pcap_device_s *)calloc(0, sizeof(struct pcap_device_s));
    if (device == NULL) {
        fprintf(stderr, "Failed to allocate new device\n");
    }

    return device;
}

int pkt_pcap_init_available_devices(struct pcap_device_s *device) {
    int ret;
    int all_devs;
    struct in_addr addr;
    struct pcap_if *pcap_device, *d;


    if(device == NULL) {
        fprintf(stderr, "Device does not exist\n");
        return -1;
    }

    if (-1 == (all_devs = pcap_findalldevs(&pcap_device, device->errbuf))) {
        fprintf(stderr, "ERROR %s", device->errbuf);
        return -1;
    }

    for (d = pcap_device; d != NULL; d = d->next){
        printf("\t============\n");
        printf("\tInterface: %s\n", d->name);
        printf("\tDescription: %s\n", d->description);
        printf("\tNetMask Address: %s\n", d->description);

        if (d->addresses) {
            for (struct pcap_addr *p_addr = d->addresses; p_addr != NULL; p_addr = p_addr->next){
                if (p_addr->addr->sa_family == AF_INET) { // IPv4 Address
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)p_addr->addr;
                    printf("\tIPv4 Address: %s\n", inet_ntoa(ipv4->sin_addr));
    
                    // Print the subnet mask
                    if (p_addr->netmask) {
                        struct sockaddr_in *netmask = (struct sockaddr_in *)p_addr->netmask;
                        printf("\tSubnet Mask: %s\n", inet_ntoa(netmask->sin_addr));
                    }
                } else if(p_addr->addr->sa_family == AF_INET6) {
                    char buffer[INET6_ADDRSTRLEN];
                    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p_addr->addr;
                    inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer, sizeof(buffer));
                    printf("\tIPv6 Address: %s\n", buffer);
                }
            }
        } else {
            printf("\tAddresses: (No addresses available)\n");
        }

    }

    printf("Device name: %s\n", device->dev);

    if(-1 == (ret = pcap_lookupnet(device->dev, &device->netp, &device->maskp, device->errbuf))){
        fprintf(stderr, "ERROR %s", device->errbuf);
        return -1;
    }


    addr.s_addr = device->maskp;
    device->mask = inet_ntoa(addr);

    if (NULL == (device->net = inet_ntoa(addr))) {
        perror("inet_ntoa");
        return -1;
    }


    return 0;
}

void pkt_pcap_destroy_device(struct pcap_device_s* device){
    free(device);
}


