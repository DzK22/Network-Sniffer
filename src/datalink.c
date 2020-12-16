#include "../headers/datalink.h"

/*
 * Function: treat_ethernet
 * ----------------------------
 *   Traite la couche liaison (Dans notre cas uniquement Ethernet)
 *
 *   packet: la partie du paquet correspondante à l'en-tête ethernet
 *   protocol: pointeur dans lequel on va mettre la valeur du protocole réseau utilisé
 *   level: niveau de verbosité
 *
 *   returns: void
 */
void treat_ethernet(const unsigned char *packet, int *protocol, int level) {
    const struct ether_header *header = (struct ether_header *) packet;
    const struct ether_addr *mac_src = (struct ether_addr *) header->ether_shost;
    const struct ether_addr *mac_dst = (struct ether_addr *) header->ether_dhost;
    *protocol = ntohs(header->ether_type);
    char str_mac_src[LEN];
    char str_mac_dst[LEN];
    ether_ntoa_r(mac_src, str_mac_src);
    ether_ntoa_r(mac_dst, str_mac_dst);
    switch (level) {
        case V1:
            fprintf(stdout, "[Ethernet] src: %s, dst: %s\t", str_mac_src, str_mac_dst);
            break;

        case V2:
            fprintf(stdout, GREEN"$> Ethernet:"COL_RESET" @mac src: %s, @mac dst: %s\n", str_mac_src, str_mac_dst);
            break;

        case V3:
            fprintf(stdout, GREEN" └─ Ethernet Frame: from %s to %s\n"COL_RESET, str_mac_src, str_mac_dst);
            break;
    }
}
