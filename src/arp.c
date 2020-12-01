#include "../headers/arp.h"

//Fonction qui gère le protocole ARP
void treat_arp(const unsigned char *packet, int level) {
    struct arphdr *arp = (struct arphdr *)packet;
    struct ether_arp *ea = (struct ether_arp *)packet;
    ushort hardware = ntohs(arp->ar_hrd);
    ushort p_type = ntohs(arp->ar_pro);
    u_char h_size = arp->ar_hln;
    u_char protocol = arp->ar_pln;
    ushort op_code = ntohs(arp->ar_op);
    int arphdr_len = sizeof(struct arphdr);
    char str_ip_src[LEN];
    char str_ip_dst[LEN];
    switch (level) {
        case V1:
            fprintf(stdout, "|| [ARP] %s => %s\t", inet_ntoa(*(struct in_addr *)&ea->arp_spa), inet_ntoa(*(struct in_addr *)&ea->arp_tpa));
            break;

        case V2:
            fprintf(stdout, "$> ARP: ");
            if (inet_ntop(AF_INET, (struct in_addr *)ea->arp_spa, str_ip_src, LEN) == NULL) {
                fprintf(stderr, "inet_ntop error\n");
                return;
            }
            if (inet_ntop(AF_INET, (struct in_addr *)ea->arp_tpa, str_ip_dst, LEN) == NULL) {
                fprintf(stderr, "inet_ntop error\n");
                return;
            }
            fprintf(stdout, "From %s to %s ", str_ip_src, str_ip_dst);
            put_arp_opcode(op_code);
            break;

        case V3:
            fprintf(stdout, "\tHardware Type : ");
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
            fprintf(stdout, "\tOpcode : ");
            put_arp_opcode(op_code);

            fprintf(stdout, "\tProtocole Type : ");
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

            fprintf(stdout, "\tHardware size : %d\n", h_size);
            fprintf(stdout, "\tProtocol size: %d\n", protocol);
            //J'ai dû affiché les IP en brute en parcourant le paquet car les fonctions inet_ntoa et inet_ntop renvoyer des résultats faux
            if (hardware == ARPHRD_ETHER && p_type == ETHERTYPE_IP) {
                if (inet_ntop(AF_INET, (struct in_addr *)ea->arp_spa, str_ip_src, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop error\n");
                    return;
                }
                if (inet_ntop(AF_INET, (struct in_addr *)ea->arp_tpa, str_ip_dst, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop error\n");
                    return;
                }
                fprintf(stdout, "\tSrc Mac Address => %s\n", ether_ntoa((struct ether_addr *)&ea->arp_sha));
                fprintf(stdout, "\tSrc IP Address => %s\n", str_ip_src);
                fprintf(stdout, "\tDst Mac Address => %s\n", ether_ntoa((struct ether_addr *)&ea->arp_tha));
                fprintf(stdout, "\tDst IP Address => %s\n", str_ip_dst);
            }
            data_print(packet + arphdr_len);
            break;
    }
}

//Converti l'opcode ARP en string pour l'affichage
void put_arp_opcode (int opcode) {
    switch (opcode) {
        case ARPOP_REQUEST:
            fprintf(stdout, "ARP Request\n");
            break;

        case ARPOP_RREQUEST:
            fprintf(stdout, "RARP Request\n");
            break;

        case ARPOP_InREQUEST:
            fprintf(stdout, "InARP Request\n");
            break;

        case ARPOP_REPLY:
            fprintf(stdout, "ARP Reply\n");
            break;

        case ARPOP_RREPLY:
            fprintf(stdout, "RARP Reply\n");
            break;

        case ARPOP_InREPLY:
            fprintf(stdout, "InARP Reply\n");
            break;

        default:
            fprintf(stdout, "\t\tUnknown opcode (%d)\n", opcode);
            break;
    }
}
