#include "../headers/arp.h"

//Fonction qui gère le protocole ARP
void treat_arp(const unsigned char *packet, int level) {
    struct arphdr *arp = (struct arphdr *)packet;
    ushort hardware = ntohs(arp->ar_hrd);
    ushort p_type = ntohs(arp->ar_pro);
    u_char h_size = arp->ar_hln;
    u_char protocol = arp->ar_pln;
    ushort op_code = ntohs(arp->ar_op);
    int i, cpt;
    int arphdr_len = sizeof(struct arphdr);
    switch (level) {
        case V1:
            fprintf(stdout, "|| [ARP]\t");
            break;

        case V2:
            fprintf(stdout, "$> ARP: ");
            //J'ai dû affiché les IP en brute en parcourant le paquet car les fonctions inet_ntoa et inet_ntop renvoyer des résultats faux
            if (hardware == ARPHRD_ETHER && p_type == ETHERTYPE_IP) {
                fprintf(stdout, "@mac src: ");
                for (i = 0; i < 6; i++) {
                    printf("%02x", packet[arphdr_len + i]);
                    if (i != 5)
                        printf(":");
                    else
                        printf(", ");
                }

                fprintf(stdout, "@ip src: ");
                for (cpt = 0; cpt < 4; cpt++) {
                    printf("%d", packet[arphdr_len + i + cpt]);
                    if (cpt != 3)
                        printf(".");
                    else
                        printf(", ");
                }

                i += cpt;
                fprintf(stdout, "@mac dst: ");
                for (cpt = 0; cpt < 6; cpt++) {
                    printf("%02x", packet[arphdr_len + i + cpt]);
                    if (cpt != 5)
                        printf(":");
                    else
                        printf(", ");
                }

                i += cpt;
                fprintf(stdout, "@ip dst: ");
                for (cpt = 0; cpt < 4; cpt++) {
                    printf("%d", packet[arphdr_len + i + cpt]);
                    if (cpt != 3)
                        printf(".");
                }
            }
            fprintf(stdout, "\n");
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
                fprintf(stdout, "\tSrc @MAC => ");
                for (i = 0; i < 6; i++) {
                    printf("%02x", packet[arphdr_len + i]);
                    if (i != 5)
                        printf(":");
                    else
                        printf("\n");
                }

                fprintf(stdout, "\tSrc @IP => ");
                for (cpt = 0; cpt < 4; cpt++) {
                    printf("%d", packet[arphdr_len + i + cpt]);
                    if (cpt != 3)
                        printf(".");
                    else
                        printf("\n");
                }

                i += cpt;
                fprintf(stdout, "\tDst @MAC => ");
                for (cpt = 0; cpt < 6; cpt++) {
                    printf("%02x", packet[arphdr_len + i + cpt]);
                    if (cpt != 5)
                        printf(":");
                    else
                        printf("\n");
                }

                i += cpt;
                fprintf(stdout, "\tDst @IP => ");
                for (cpt = 0; cpt < 4; cpt++) {
                    printf("%d", packet[arphdr_len + i + cpt]);
                    if (cpt != 3)
                        printf(".");
                    else
                        printf("\n");
                }
            }
            data_print(packet + i);
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
