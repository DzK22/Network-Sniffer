#include "../headers/liaison.h"

int threat_ethernet(const unsigned char *packet, int *protocol, int level) {
    struct ether_header *header;
    struct ether_addr *mac_src;
    struct ether_addr *mac_dst;
    header = (struct ether_header *) packet;
    mac_src = (struct ether_addr *) header->ether_shost;
    mac_dst = (struct ether_addr *) header->ether_dhost;
    *protocol = ntohs(header->ether_type);

    switch (level) {
        case V3:
            fprintf(stdout, "Ethernet:\n");
            fprintf(stdout, "\t@dest : %s\n", ether_ntoa(mac_dst));
            fprintf(stdout, "\t@src : %s\n", ether_ntoa(mac_src));
            char *type = NULL;
            if (*protocol == ETHERTYPE_IP)
                type = "IP";
            else if  (*protocol == ETHERTYPE_ARP)
                type = "ARP";
            else
                type = "?";
            fprintf(stdout, "\t type : %s\n", type);
            break;

        case V2:
            fprintf(stdout, "\t Ethernet:\n");
            fprintf(stdout, "\t@dest : %s\n", ether_ntoa(mac_dst));
            fprintf(stdout, "\t@src : %s\n", ether_ntoa(mac_src));
            break;

        case V1:
            if (*protocol == ETHERTYPE_ARP)
                fprintf(stdout, "[Ethernet] %s => %s\n", ether_ntoa(mac_src), ether_ntoa(mac_dst));
            break;
    }

    return sizeof(struct ether_header);
}
