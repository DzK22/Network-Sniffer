#include "../headers/liaison.h"

//Fonction qui gère la couche liaison dans sa globalité
void treat_ethernet(const unsigned char *packet, int *protocol, int level) {
    const struct ether_header *header = (struct ether_header *) packet;
    const struct ether_addr *mac_src = (struct ether_addr *) header->ether_shost;
    const struct ether_addr *mac_dst = (struct ether_addr *) header->ether_dhost;
    *protocol = ntohs(header->ether_type);
    int res;
    char mac_source[LEN];
    char mac_dest[LEN];
    char *type = NULL;
    res = snprintf(mac_source, LEN, "%s", ether_ntoa(mac_src));
    if (test_snprintf(res, LEN) == EXIT_FAILURE) {
        fprintf(stderr, "error\n");
        exit(EXIT_FAILURE);
    }
    res = snprintf(mac_dest, LEN, "%s", ether_ntoa(mac_dst));
    if (test_snprintf(res, LEN) == EXIT_FAILURE) {
        fprintf(stderr, "error\n");
        exit(EXIT_FAILURE);
    }

    switch (level) {
        case V1:
            fprintf(stdout, "[Ethernet] %s => %s\t", mac_source, mac_dest);
            break;

        case V2:
            fprintf(stdout, "Ethernet: @mac src: %s, @mac dst: %s\n", mac_source, mac_dest);
            break;

        case V3:
            fprintf(stdout, GREEN"Ethernet:\n"COL_RESET);
            fprintf(stdout, GREEN"\t@mac dest: %s\n"COL_RESET, mac_dest);
            fprintf(stdout, PINK"\t@mac src: %s\n"COL_RESET, mac_source);
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
                default:
                    break;
            }
            if (type != NULL)
                fprintf(stdout, "\tType: %s (0x%04x)\n", type,  *protocol);
            else
                fprintf(stdout, "\tType: Unknown 0x%04x\n", *protocol);
            break;
    }
}
