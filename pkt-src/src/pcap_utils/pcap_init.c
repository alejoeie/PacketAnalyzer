#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "../../include/pcap_utils/pcap_init.h"

struct pcap_device_s  *pcap_alloc_device(void){
    struct pcap_device_s *device = (struct pcap_device_s *)calloc(0, sizeof(struct pcap_device_s));
    if (device == NULL) {
        fprintf(stderr, "Failed to allocate new device\n");
    }

    return device;
}

pcap_result_e pcap_init_available_devices(struct pcap_device_s *device) {
    // int ret;
    int all_devs;
    // struct in_addr addr;
    struct pcap_if *pcap_device;


    if(device == NULL) {
        fprintf(stderr, "Device does not exist\n");
        return PCAP_RET_FAIL;
    }

    if (-1 == (all_devs = pcap_findalldevs(&pcap_device, device->errbuf))) {
        fprintf(stderr, "ERROR %s", device->errbuf);
        return PCAP_RET_FAIL;
    }

    // for (d = pcap_device; d != NULL; d = d->next){
    //     printf("\t============\n");
    //     printf("\tInterface: %s\n", d->name);
        // printf("\tDescription: %s\n", d->description);
        // printf("\tNetMask Address: %s\n", d->description);

    //     if (d->addresses) {
    //         for (struct pcap_addr *p_addr = d->addresses; p_addr != NULL; p_addr = p_addr->next){
    //             if (p_addr->addr->sa_family == AF_INET) { // IPv4 Address
    //                 struct sockaddr_in *ipv4 = (struct sockaddr_in *)p_addr->addr;
    //                 printf("\tIPv4 Address: %s\n", inet_ntoa(ipv4->sin_addr));
    
    //                 // Print the subnet mask
    //                 if (p_addr->netmask) {
    //                     struct sockaddr_in *netmask = (struct sockaddr_in *)p_addr->netmask;
    //                     printf("\tSubnet Mask: %s\n", inet_ntoa(netmask->sin_addr));
    //                 }
    //             } else if(p_addr->addr->sa_family == AF_INET6) {
    //                 char buffer[INET6_ADDRSTRLEN];
    //                 struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p_addr->addr;
    //                 inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer, sizeof(buffer));
    //                 printf("\tIPv6 Address: %s\n", buffer);
    //             }
    //         }
    //     } else {
    //         printf("\tAddresses: (No addresses available)\n");
    //     }
    // }

    device->capture = pcap_device;

    return PCAP_RET_OK;
}


int pcap_register_pkt(struct pcap_device_s* device, char device_list[PCAP_MAX_DEVS][PCAP_MAX_NAME_LEN]) {
    int iter = 0;

    if (PCAP_RET_OK != pcap_init_available_devices(device)) {
        return PCAP_RET_FAIL;
    }
    struct pcap_if *tmp = device->capture;

    while(tmp) {
        printf("Capture name %s \n", tmp->name);
        strncpy(device_list[iter], tmp->name, PCAP_MAX_NAME_LEN - 1);
        device_list[iter][PCAP_MAX_NAME_LEN - 1] = '\0';
        iter++;

        if (iter >= PCAP_MAX_DEVS) {
            fprintf(stderr, "Warning: Maximum number of devices reached (%d).\n", PCAP_MAX_DEVS);
            break;
        }
        tmp = tmp->next;
    }

    // AQUI ESTA EL PROBLEMA
    /*
    for(struct pcap_device_s * temp = capture_pkt; temp->capture != NULL; temp->capture = temp->capture->next){
        printf("Capture name %s \n", temp->capture->name);
        strncpy(device_list[iter], temp->capture->name, PCAP_MAX_NAME_LEN - 1);
        device_list[iter][PCAP_MAX_NAME_LEN - 1] = '\0';
        iter++;

        if (iter >= PCAP_MAX_DEVS) {
            fprintf(stderr, "Warning: Maximum number of devices reached (%d).\n", PCAP_MAX_DEVS);
            break;
        }
    }
    */

    // pcap_destroy_device(device); 
    return iter;
}



void pcap_destroy_device(struct pcap_device_s* device){
    free(device);
}


