#include "../headers/liaison.h"

void treat_ethernet(const unsigned char *packet, int *protocol, int level) {
    const struct ether_header *header = (struct ether_header *) packet;
    const struct ether_addr *mac_src = (struct ether_addr *) header->ether_shost;
    const struct ether_addr *mac_dst = (struct ether_addr *) header->ether_dhost;
    *protocol = ntohs(header->ether_type);
    char mac_source[LEN];
    char mac_dest[LEN];
    snprintf(mac_source, LEN, "%s", ether_ntoa(mac_src));
    snprintf(mac_dest, LEN, "%s", ether_ntoa(mac_dst));

    switch (level) {
        case V3:
            fprintf(stdout, GREEN"Ethernet:\n"COL_RESET);
            fprintf(stdout, PINK"\t@mac src : %s\n"COL_RESET, mac_source);
            fprintf(stdout, GREEN"\t@mac dest : %s\n"COL_RESET, mac_dest);
            break;

        case V2:
            fprintf(stdout, GREEN"\t Ethernet:\n"COL_RESET);
            fprintf(stdout, PINK"\t@mac src : %s\n"COL_RESET, mac_source);
            fprintf(stdout, GREEN"\t@mac dest : %s\n"COL_RESET, mac_dest);
            break;

        case V1:
            fprintf(stdout, "[Ethernet] %s => %s\n", mac_source, mac_dest);
            break;
    }
}
