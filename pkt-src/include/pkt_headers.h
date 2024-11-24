#ifndef PKT_LAYER_HEADERS_H
#define PKT_LAYER_HEADERS_H

#define SUPPORTED_ETHERTYPE_PROTOCOL_IPV4 0x0800
#define SUPPORTED_ETHERTYPE_PROTOCOL_IPV6 0x86DD

#define IPV4_HEADER_FLAGS_PER_PKT(x) ((x) >> 2)
#define IPV4_HEADER_FRAG_OFFSET_PER_PKT(x) ((x) & 0x1FFF)
#define IPV4_HEADER_DSCP_PER_PKT(x) ((x) >> 2)
#define IPV4_HEADER_ECN_PER_PKT(x) ((x) & 0x03)

typedef struct l2_ethernet_header_s {
    uint8_t preamble[7];
    uint8_t SFD;
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} l2_ethernet_header_t;

typedef struct l3_ipv4_header_s {
    uint8_t version_ihl;     // Version: 4 for IPv4 and Internet Header Length: size of IPv4 Header (5 as min, 15 as max)
    uint8_t dscp_ecn; // Differentiated Services code point (ToS) and Explicit Congestion Notification
    uint16_t total_length; // Entire packet size (min 20 bytes, max 65535)
    uint16_t id; // Identification field
    uint16_t flags_and_frag_offset; // Fragmented packet handler and Fragmentation offset
    uint8_t ttl; // Time-to-live to prevent failure
    uint8_t protocol; // Transport Layer Protocol
    uint16_t checksum; // Error Checking of the header
    uint32_t src_addr; // IPv4 Address of sender
    uint32_t dst_addr; // IPv4 Address of receiver
} l3_ipv4_header_t;

#endif
