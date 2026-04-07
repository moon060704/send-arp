#ifndef ANS_HEADER_H
#define ANS_HEADER_H

#include <stdint.h>

#define MAC_ALEN 6
#define ETH_P_ARP 0x0806
#define ARP_P_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define ETHERTYPE_IPV4 0x0800
#define IPV4_PROTOCOL_TCP 6

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst_mac[MAC_ALEN];
    uint8_t  src_mac[MAC_ALEN];
    uint16_t eth_type;
} EthHdr;

typedef struct {
    uint8_t  vhl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  ip_src[4];
    uint8_t  ip_dst[4];
} Ipv4Hdr;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} TcpHdr;

typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_size;
    uint8_t  proto_size;
    uint16_t op_code;
    uint8_t  sender_mac[MAC_ALEN];
    uint32_t sender_ip;
    uint8_t  target_mac[MAC_ALEN];
    uint32_t target_ip;
} ArpHdr;

typedef struct {
    EthHdr eth;
    ArpHdr arp;
} EthArpPacket;

#pragma pack(pop)

typedef struct {
    uint32_t sender_ip;
    uint32_t target_ip;
    uint8_t  sender_mac[MAC_ALEN];
} Session;

#endif
