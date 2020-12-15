#include "../headers/transport.h"

/*
 * Function: treat_transport
 * ----------------------------
 *   Traite la couche transport
 *
 *   packet: la partie du paquet correspondante à l'en-tête du protocole de transport à traîter
 *   t_protocol: port correspondant au protocole de transport à traîter
 *   sport: port source
 *   dport: port de destination
 *   to_add: taille de l'en-tête traîtée (utile pour pouvoir la rajouter au paquet traîté pour trouver le prochain protocole à traîter)
 *   level: niveau de verbosité
 *
 *   returns: void
 */
void treat_transport(const unsigned char *packet, int t_protocol, int *sport, int *dport, int *to_add, int level) {
    switch (t_protocol) {
        case UDP:
            treat_udp(packet, sport, dport, level);
            *to_add = sizeof(struct udphdr);
            break;

        case TCP:
            treat_tcp(packet, to_add, sport, dport, level);
            break;

        // OSPF n'est pas un protocole de transport mais je l'ai mis ici pour me faciliter l'implémentation par rapport au reste du code
        case OSPF:
            treat_ospf(packet, level);
            *to_add = sizeof(struct ospfhdr);
            break;
        // ICMP n'est pas un protocole de transport mais je l'ai mis ici pour me faciliter l'implémentation par rapport au reste du code
        case ICMP:
            treat_icmp(packet, level);
            *to_add = sizeof(struct icmphdr) + 8;

        default:
            break;
    }
}

/*
 * Function: treat_udp
 * ----------------------------
 *   Traite l'en-tête UDP
 *
 *   packet: la partie du paquet correspondante à l'en-tête UDP
 *   sport: port source
 *   dport: port de destination
 *   level: niveau de verbosité
 *
 *   returns: void
 */
void treat_udp(const unsigned char *packet, int *sport, int *dport, int level) {
    struct udphdr *udp = (struct udphdr *)packet;
    int checksum, dataLength;
    *sport = ntohs(udp->uh_sport);
    *dport = ntohs(udp->uh_dport);
    checksum = ntohs(udp->uh_sum);
    dataLength = ntohs(udp->uh_ulen);

    switch (level) {
        case V1:
            fprintf(stdout, "|| UDP\t");
            break;
        case V2:
            fprintf(stdout, PINK"$> UDP:"COL_RESET" sport: %d, dport: %d\n", *sport, *dport);
            break;

        case V3:
            fprintf(stdout, PINK"       └─ UDP Segment: from port %d to port %d\n"COL_RESET, *sport, *dport);
            fprintf(stdout, PINK"         ├─"COL_RESET" Checksum = 0x%04x\n", checksum);
            fprintf(stdout, PINK"         └─"COL_RESET" Length = %d\n", dataLength);
            break;
    }
}

/*
 * Function: treat_tcp
 * ----------------------------
 *   Traite l'en-tête TCP
 *
 *   packet: la partie du paquet correspondante à l'en-tête TCP
 *   packet: taille de l'en-tête TCP (variable)
 *   sport: port source
 *   dport: port de destination
 *   level: niveau de verbosité
 *
 *   returns: void
 */
void treat_tcp(const unsigned char *packet, int *to_add, int *sport, int *dport, int level) {
    struct tcphdr *tcp = (struct tcphdr *)packet;
    int fin, syn, reset, push, ack, urg, window, checksum, seq, ack_seq, dataOff, urgPointer;
    *to_add = tcp->th_off * 4;
    *sport = ntohs(tcp->th_sport);
    *dport = ntohs(tcp->th_dport);
    fin = (tcp->th_flags & TH_FIN) ? 1 : 0;
    syn = (tcp->th_flags & TH_SYN) ? 1 : 0;
    reset = (tcp->th_flags & TH_RST) ? 1 : 0;
    push = (tcp->th_flags & TH_PUSH) ? 1 : 0;
    ack = (tcp->th_flags & TH_ACK) ? 1 : 0;
    urg = (tcp->th_flags & TH_URG) ? 1 : 0;
    window = ntohs(tcp->th_win);
    checksum = ntohs(tcp->th_sum);
    seq = ntohl(tcp->th_seq);
    ack_seq = ntohl(tcp->ack_seq);
    dataOff = tcp->th_off;
    urgPointer = ntohs(tcp->th_urp);
    switch (level) {
        case V1:
            fprintf(stdout, "|| [TCP] ");
            fprintf(stdout, "{ ");
            if (fin)
                fprintf(stdout, "FIN ");
            if (syn)
                fprintf(stdout, "SYN ");
            if (reset)
                fprintf(stdout, "RST ");
            if (push)
                fprintf(stdout, "PSH ");
            if (ack)
                fprintf(stdout, "ACK ");
            if (urg)
                fprintf(stdout, "URG ");
            fprintf(stdout, "}, Window: %d\t", window);
            break;

        case V2:
            fprintf(stdout, PINK"$> TCP:"COL_RESET" sport: %d, dport: %d ", *sport, *dport);
            fprintf(stdout, "{ ");
            if (fin)
                fprintf(stdout, "FIN ");
            if (syn)
                fprintf(stdout, "SYN ");
            if (reset)
                fprintf(stdout, "RST ");
            if (push)
                fprintf(stdout, "PSH ");
            if (ack)
                fprintf(stdout, "ACK ");
            if (urg)
                fprintf(stdout, "URG ");
            fprintf(stdout, "}, Window: %d\n", window);
            break;

        case V3:
            fprintf(stdout, PINK"       └─ TCP Segment: from port %d to port %d\n"COL_RESET, *sport, *dport);
            fprintf(stdout, PINK"         ├─"COL_RESET" Sequence Num = %02x\n", seq);
            fprintf(stdout, PINK"         ├─"COL_RESET" Acknowledgment Num = %02x\n", ack_seq);
            fprintf(stdout, PINK"         ├─"COL_RESET" Date Offset = %d\n", dataOff);
            fprintf(stdout, PINK"         ├─"COL_RESET" Flags : 0x%x\n", tcp->th_flags);
            fprintf(stdout, PINK"         ├"COL_RESET"\t\t- FIN : %d\n", fin);
            fprintf(stdout, PINK"         ├"COL_RESET"\t\t- SYN : %d\n", syn);
            fprintf(stdout, PINK"         ├"COL_RESET"\t\t- RST : %d\n", reset);
            fprintf(stdout, PINK"         ├"COL_RESET"\t\t- PSH : %d\n", push);
            fprintf(stdout, PINK"         ├"COL_RESET"\t\t- ACK : %d\n", ack);
            fprintf(stdout, PINK"         ├"COL_RESET"\t\t- URG : %d\n", urg);
            fprintf(stdout, PINK"         ├─"COL_RESET" Window = %d\n", window);
            fprintf(stdout, PINK"         ├─"COL_RESET" Checksum = 0x%04x\n", checksum);
            if (*to_add <= 20)
                fprintf(stdout, PINK"         └─"COL_RESET" Urgent Pointer = %d\n", urgPointer);
            //Si la taille de l'entete tcp est supérieure à 20 octets alors il y a des options tcp et on les affiche uniquement si le niveau de détails est au plus haut
            if (*to_add > 20) {
                fprintf(stdout, PINK"         ├─"COL_RESET" Urgent Pointer = %d\n", urgPointer);
                int i = sizeof(struct tcphdr), value, len;
                fprintf(stdout, PINK"         ├─"COL_RESET" Options:\n");
                do {
                    if (i + (int)packet[i + 1] >= *to_add || i + 1 >= *to_add)
                        fprintf(stdout, PINK"         └─"COL_RESET"\t\tTCP Option - ");
                    else
                        fprintf(stdout, PINK"         ├"COL_RESET"\t\tTCP Option - ");
                    switch (packet[i]) {
                        case NOP:
                            fprintf(stdout, "\tNo Operation (NOP)\n");
                            i++;
                            break;

                        case MSS:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tMaximum Segment Size (%d): [Length: %d, ", packet[i], len);
                            value = packet[i + 2] << 8 | packet[i + 3];
                            fprintf(stdout, "MSS Value: %d bytes]\n", value);
                            i += len;
                            break;

                        case WS:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tWindow Scale (%d): [Length: %d, Shift count: %d]\n", packet[i], len, packet[i + 2]);
                            i += len;
                            break;

                        case SACKP:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tSack Permitted (%d): [Length: %d]\n", packet[i], len);
                            i += len;
                            break;

                        case SACK:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tSack\n");
                            i += len;
                            break;

                        case TS:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tTimestamp (%d): ", packet[i]);
                            fprintf(stdout, "[Length: %d, ", len);
                            value = get_timestamp(packet, i);
                            fprintf(stdout, "Timestamp value: %d secs, ", value);
                            value = get_timestamp(packet, i + 4);
                            fprintf(stdout, "Timestamp echo reply: %d secs]\n", value);
                            i += len;
                            break;

                        default:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tUnknown (%d): [Length: %d]\n", packet[i], len);
                            i += len;
                            break;
                    }
                } while (i < *to_add && packet[i] != 0x00);
            }
            break;
    }
}

/*
 * Function: get_timestamp
 * ----------------------------
 *   recupère la valeur d'un timestamp dans les options TCP
 *
 *   packet: la partie du paquet correspondante à l'en-tête TCP
 *   i: indice où l'on se trouve dans le paquet (au niveau des options)
 *
 *   returns: la valeur du timestamp
 */
u_int32_t get_timestamp (const unsigned char *packet, int i) {
    return packet[i + 2] << 24 | packet[i + 3] << 16 | packet[i + 4] << 8 | packet[i + 5];
}
