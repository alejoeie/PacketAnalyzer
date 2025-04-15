#ifndef PCAP_SNIFF_DEVICE_H
#define PCAP_SNIFF_DEVICE_H

pcap_result_e pcap_sniff_device(char device_list[PCAP_MAX_DEVS][PCAP_MAX_NAME_LEN], const char* interface_to_sniff, const int size);

#endif