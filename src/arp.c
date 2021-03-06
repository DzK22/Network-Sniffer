#include "../headers/arp.h"

/*
 * Function: treat_arp
 * ----------------------------
 *   Fonction qui traîte le procole (R)ARP
 *
 *   packet: la partie du paquet correspondante à l'en-tête (R)ARP
 *   level: niveau de verbosité
 *   type: ARP ou RARP
 *
 *   returns: void
 */
void treat_arp(const unsigned char *packet, int level, int type) {
    struct arphdr *arp = (struct arphdr *)packet;
    struct ether_arp *ea = (struct ether_arp *)packet;
    ushort hardware = ntohs(arp->ar_hrd);
    ushort p_type = ntohs(arp->ar_pro);
    u_char h_size = arp->ar_hln;
    u_char protocol = arp->ar_pln;
    ushort op_code = ntohs(arp->ar_op);
    char str_ip_src[LEN];
    char str_ip_dst[LEN];
    char str_mac_src[LEN];
    char str_mac_dst[LEN];
    if (inet_ntop(AF_INET, (struct in_addr *)ea->arp_spa, str_ip_src, LEN) == NULL) {
        fprintf(stderr, "inet_ntop error\n");
        return;
    }
    if (inet_ntop(AF_INET, (struct in_addr *)ea->arp_tpa, str_ip_dst, LEN) == NULL) {
        fprintf(stderr, "inet_ntop error\n");
        return;
    }
    ether_ntoa_r((struct ether_addr *)&ea->arp_sha, str_mac_src);
    ether_ntoa_r((struct ether_addr *)&ea->arp_tha, str_mac_dst);
    switch (level) {
        case V1:
            fprintf(stdout, "|| [%s] ", type == ETHERTYPE_ARP ? "ARP" : "RARP");
            switch (type) {
                case ETHERTYPE_ARP:
                    if (op_code == ARPOP_REQUEST)
                        fprintf(stdout, "Who is %s ? Tell %s ", str_ip_dst, str_ip_src);
                    else if (op_code == ARPOP_REPLY)
                        fprintf(stdout, "%s is at %s ", str_ip_dst, str_mac_src);
                    break;

                case ETHERTYPE_REVARP:
                    if (op_code == ARPOP_RREQUEST)
                        fprintf(stdout, "Who is %s ? Tell %s ", str_mac_dst, str_mac_src);
                    else if (op_code == ARPOP_RREPLY)
                        fprintf(stdout, "%s is at %s ", str_mac_dst, str_ip_dst);
                    break;

                default:
                    break;
            }
            put_arp_opcode(op_code);
            break;

        case V2:
            fprintf(stdout, YELLOW"$> %s: "COL_RESET, type == ETHERTYPE_ARP ? "ARP" : "RARP");
            switch (type) {
                case ETHERTYPE_ARP:
                    if (op_code == ARPOP_REQUEST)
                        fprintf(stdout, "Who is %s ? Tell %s ", str_ip_dst, str_ip_src);
                    else if (op_code == ARPOP_REPLY)
                        fprintf(stdout, "%s is at %s ", str_ip_dst, str_mac_src);
                    break;

                case ETHERTYPE_REVARP:
                    if (op_code == ARPOP_RREQUEST)
                        fprintf(stdout, "Who is %s ? Tell %s ", str_mac_dst, str_mac_src);
                    else if (op_code == ARPOP_RREPLY)
                        fprintf(stdout, "%s is at %s ", str_mac_dst, str_ip_dst);
                    break;

                default:
                    break;
            }
            put_arp_opcode(op_code);
            break;

        case V3:
            fprintf(stdout, YELLOW"   └─ Type = ARP (0x0806)\n"COL_RESET);
            fprintf(stdout, YELLOW"     ├─"COL_RESET" Hardware Type : ");
            switch (hardware) {
                case ARPHRD_ETHER:
                    fprintf(stdout, "Ethernet\n");
                    break;

                case ARPHRD_EETHER:
                    fprintf(stdout, "Experimental Ethernet\n");
                    break;

                case ARPHRD_APPLETLK:
                    fprintf(stdout, "Apple Talk\n");
                    break;

                default:
                    fprintf(stdout, "Unknown Hardware (%d)\n", hardware);
                    break;
            }
            fprintf(stdout, YELLOW"     ├─"COL_RESET" Opcode : ");
            put_arp_opcode(op_code);
            fprintf(stdout, "\n");

            fprintf(stdout, YELLOW"     ├─"COL_RESET" Protocole Type : ");
            switch (p_type) {
                case ETHERTYPE_IP:
                    fprintf(stdout, "IPv4\n");
                    break;

                case ETHERTYPE_PUP:
                    fprintf(stdout, "PUP\n");
                    break;

                default:
                    fprintf(stdout, "Unknown protocol (%d)\n", p_type);
                    break;
            }

            fprintf(stdout, YELLOW"     ├─"COL_RESET" Hardware size : %d\n", h_size);
            fprintf(stdout, YELLOW"     ├─"COL_RESET" Protocol size: %d\n", protocol);

            if (hardware == ARPHRD_ETHER && p_type == ETHERTYPE_IP) {
                fprintf(stdout, YELLOW"     ├─"COL_RESET" Src Mac Address => %s\n", str_mac_src);
                fprintf(stdout, YELLOW"     ├─"COL_RESET" Src IP Address => %s\n", str_ip_src);
                fprintf(stdout, YELLOW"     ├─"COL_RESET" Dst Mac Address => %s\n", str_mac_dst);
                fprintf(stdout, YELLOW"     └─"COL_RESET" Dst IP Address => %s\n", str_ip_dst);
            }
            break;
    }
}

/*
 * Function: put_arp_opcode
 * ----------------------------
 *   Fonction qui affiche le type de l'opération (R)ARP en fonction de son code
 *
 *   opcode: code de l'opération
 *
 *   returns: void
 */
void put_arp_opcode (int opcode) {
    switch (opcode) {
        case ARPOP_REQUEST:
            fprintf(stdout, "ARP Request");
            break;

        case ARPOP_RREQUEST:
            fprintf(stdout, "RARP Request");
            break;

        case ARPOP_InREQUEST:
            fprintf(stdout, "InARP Request");
            break;

        case ARPOP_REPLY:
            fprintf(stdout, "ARP Reply");
            break;

        case ARPOP_RREPLY:
            fprintf(stdout, "RARP Reply");
            break;

        case ARPOP_InREPLY:
            fprintf(stdout, "InARP Reply");
            break;

        default:
            fprintf(stdout, "\t\tUnknown opcode (%d)", opcode);
            break;
    }
}
