#include "../headers/liaison.h"

int threat_ethernet(const unsigned char *packet, int level, unsigned *next) {
    const struct ether_header *header = (struct ether_header *) packet;
    const struct ether_addr *mac_src = (struct ether_addr *) header->ether_shost;
    const struct ether_addr *mac_dst = (struct ether_addr *) header->ether_dhost;
    int protocol = ntohs(header->ether_type);
    *next = ETHER_HDR_LEN;
    char *mac_source = ether_ntoa(mac_src);
    char *mac_dest = ether_ntoa(mac_dst);

    switch (level) {
        case V3:
            fprintf(stdout, GREEN"Ethernet:\n"COL_RESET);
            fprintf(stdout, PINK"\t@src : %s\n"COL_RESET, mac_source);
            fprintf(stdout, GREEN"\t@dest : %s\n"COL_RESET, mac_dest);
            break;

        case V2:
            fprintf(stdout, GREEN"\t Ethernet:\n"COL_RESET);
            fprintf(stdout, PINK"\t@src : %s\n"COL_RESET, mac_source);
            fprintf(stdout, GREEN"\t@dest : %s\n"COL_RESET, mac_dest);
            break;

        case V1:
            fprintf(stdout, "[Ethernet] %s => %s\n", mac_source, mac_dest);
            break;
    }

    return protocol;
}
