/*
 * File: packet_capture.c
 * Description: This file contains functions for capturing network packets using raw sockets.
 * Author: Alejandro Z
 * Date: 2024-11-24
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <pcap.h>
#include "../include/pkt_headers.h"
#include "../include/pkt_analyzer.h"
#include "../include/pcap_utils/pcap_init.h"

int main(int argc, char* argv[]) {

    struct pcap_device_s *dev_init = {0};

    dev_init = pkt_pcap_alloc_device();

    if (0 != pkt_pcap_init_available_devices(dev_init)) {
        return -1;
    }

    pkt_pcap_destroy_device(dev_init);    
    
    return 0;
}