#ifndef PCAP_SNIFF_DEVICE_H
#define PCAP_SNIFF_DEVICE_H

pcap_result_e pcap_sniff_device(struct pcap_device_s *device, const char* interface_to_sniff);

#endif