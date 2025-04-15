#ifndef PCAP_INIT_H
#define PCAP_INIT_H

#define PCAP_MAX_DEVS 128
#define PCAP_MAX_NAME_LEN 512

typedef enum {
    PCAP_RET_OK,
    PCAP_RET_FAIL,
    PCAP_RET_NONE,
} pcap_result_e;

/*
struct pcap if {
    struct pcap if *next; // enlace a la siguiente definicion de interfaz 10
    char *name; // nombre de la interfaz (eth0,wlan0. . .)
    char *description; // descripcion de la interfaz o NULL
    struct pcap addr *addresses;// lista enlazada de direcciones asociadas a esta interfaz
    u_int flags; // PCAP IF interface flags
};
*/
// TODO: Redesign this structure, let's keep it modular, but it might change.
struct pcap_device_s {
    struct pcap_if *capture;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
};

pcap_result_e pcap_init_available_devices(struct pcap_device_s *device);

struct pcap_device_s *pcap_alloc_device(void);

void pcap_destroy_device(struct pcap_device_s *device);

int pcap_register_pkt(struct pcap_device_s **device, char device_list[PCAP_MAX_DEVS][PCAP_MAX_NAME_LEN]);

#endif