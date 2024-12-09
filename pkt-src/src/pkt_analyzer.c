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
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <pcap.h>
#include "../include/pkt_headers.h"
#include "../include/pkt_analyzer.h"
#include "../include/pcap_utils/pcap_init.h"
#include "../include/pcap_utils/pcap_sniff_device.h"

int main(int argc, const char* argv[]) {
    struct pcap_device_s* device = pcap_alloc_device();
    char device_list[PCAP_MAX_DEVS][PCAP_MAX_NAME_LEN];
    
    fprintf(stdout, "Welcome to PacketAnalyzer | A command-line tool for packet capture\n");
    fprintf(stdout, "Available interfaces:\n");

    // Retrieve device list and count
    int device_count = pcap_register_pkt(device, device_list);
    if (device_count == 0) {
        fprintf(stderr, "No devices found or unable to retrieve device list.\n");
        return -1;
    }

    for (int i = 0; i < device_count; i++) {
        fprintf(stdout, "Device %d: %s\n", i + 1, device_list[i]);
    }

    if (argc < 2) {
        fprintf(stderr, "ERROR: Missing parameter\n"
                        "Usage: ./packet_analyzer <interface_name>\n"
                        "Where interface name is any interface from the list above.\n");
        return -1;
    }

    const char* user_interface = argv[1];
    fprintf(stdout, "Selected interface: %s\n", user_interface);

    fprintf(stdout, "Capturing packets on: %s\n", user_interface);

    pcap_sniff_device(device, user_interface);

    return 0;
}