#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "send_arp.h"

unsigned char* request(unsigned char *smac, char *sip, char *dip) {
    struct eth_header eth;
    unsigned char* packet =(unsigned char *)calloc(42, sizeof(uint8_t));
    for(int i=0; i<6; i++) {
        eth.dmac[i] = 0xff;
        eth.smac[i] = smac[i];
    }
    eth.eth_type = ntohs(0x0806);
    memcpy(packet, &eth, sizeof(struct eth_header));

    struct arp_header arp;
    arp.hw_type = ntohs(0x0001);
    arp.protocol = ntohs(0x0800);
    arp.hw_add_len = 0x06;
    arp.proto_add_len = 0x04;
    arp.opcode = ntohs(0x0001);
    arp.sip = inet_addr(sip);
    for(int i=0; i<6; i++) {
        arp.smac[i] = smac[i];
        arp.dmac[i] = 0xff;
    }
    arp.dip = inet_addr(dip);
    memcpy(packet+14, &arp, sizeof(struct arp_header));

    return packet;
}
