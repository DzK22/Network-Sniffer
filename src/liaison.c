#include "../headers/liaison.h"

int threat_ethernet(const unsigned char *packet, int *protocol, int level) {
    const struct ether_header *header = (struct ether_header *) packet;
    const struct ether_addr *mac_src = (struct ether_addr *) header->ether_shost;
    const struct ether_addr *mac_dst = (struct ether_addr *) header->ether_dhost;
    *protocol = ntohs(header->ether_type);
    char *mac_source = ether_ntoa(mac_src);
    char *mac_dest = ether_ntoa(mac_dst);

    switch (level) {
        case V3:
            fprintf(stdout, "Ethernet:\n");
            fprintf(stdout, PINK"\t@src : %s\n"COL_RESET, mac_source);
            fprintf(stdout, GREEN"\t@dest : %s\n"COL_RESET, mac_dest);
            char *type = NULL;
            switch (*protocol) {
                case ETHERTYPE_IP:
                    type = "IPv4";
                    break;

                case ETHERTYPE_IPV6:
                    type = "IPv6";
                    break;

                case ETHERTYPE_ARP:
                    type = "ARP";
                    break;

                case ETHERTYPE_REVARP:
                    type = "REVERSE ARP";
                    break;

                default:
                    type = "? Unknown ?";
                    break;
            }
            fprintf(stdout, YELLOW"\ttype : %s\n"COL_RESET, type);
            break;

        case V2:
            fprintf(stdout, "\t Ethernet:\n");
            fprintf(stdout, PINK"\t@src : %s\n"COL_RESET, mac_source);
            fprintf(stdout, GREEN"\t@dest : %s\n"COL_RESET, mac_dest);
            break;

        case V1:
            if (*protocol == ETHERTYPE_ARP)
                fprintf(stdout, "[Ethernet] %s => %s\n", mac_source, mac_dest);
            break;
    }

    return sizeof(struct ether_header);
}
