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

int main(int argc, char* argv[]) {
    
    char device_list[PCAP_MAX_DEVS][PCAP_MAX_NAME_LEN];

    
    fprintf(stdout, "Welcome to PacketAnalyzer| A command-line tool for packet capture\n");
    fprintf(stdout, "Interface to capture:\n");
    if (PCAP_RET_OK != pcap_register_pkt(*device_list)){
        fprintf(stderr, "Not able to fill in packet capture\n");
        return -1;
    }

    if (argc < 2) {
        fprintf(stderr, "ERROR: Missing parameter\n"
                        "Usage: ./packet_analyzer <interface_name>\n"
                        "Where interface name is any interface from the list above.\n"
                        "\n");
        return -1;
    }
    

    return 0;
}