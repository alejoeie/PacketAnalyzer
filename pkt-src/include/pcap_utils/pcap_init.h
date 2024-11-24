#ifndef PCAP_INIT_H
#define PCAP_INIT_H

struct pcap_device_s {
    char *net;
    char *mask;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
};

int pkt_pcap_init_available_devices(struct pcap_device_s *device);

struct pcap_device_s *pkt_pcap_alloc_device(void);

void pkt_pcap_destroy_device(struct pcap_device_s *device);

#endif