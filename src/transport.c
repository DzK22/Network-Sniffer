#include "../headers/transport.h"

void treat_transport(const unsigned char *packet, int t_protocol, int *sport, int *dport, int *to_add, int level) {
    switch (t_protocol) {
        case UDP:
            //fprintf(stdout, "\tT_PROTOCOL : UDP\n");
            treat_udp(packet, sport, dport, level);
            *to_add = sizeof(struct udphdr);
            break;

        case TCP:
            //fprintf(stdout, "\tT_PROTOCOL : TCP\n");
            treat_tcp(packet, to_add, sport, dport, level);
            break;

        case OSPF:
            treat_ospf(packet, to_add, level);
            break;

        default:
            if (level == V3)
                fprintf(stdout, "\tUnknown (%d)\n", t_protocol);
            break;
    }
}

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
            fprintf(stdout, "$> UDP: sport: %d, dport: %d\n", *sport, *dport);
            break;

        case V3:
            fprintf(stdout, "\tSource port = %d\n", *sport);
            fprintf(stdout, "\tDestination port = %d\n", *dport);
            fprintf(stdout, "\tChecksum = 0x%04x\n", checksum);
            fprintf(stdout, "\tLength = %d\n", dataLength);
            break;
    }
}

//Fonction qui traite l'en-tête TCP
void treat_tcp(const unsigned char *packet, int *to_add, int *sport, int *dport, int level) {
    (void)level;
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
            fprintf(stdout, "}\t");
            break;

        case V2:
            fprintf(stdout, "$> TCP: sport: %d, dport: %d ", *sport, *dport);
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
            fprintf(stdout, "}\n");
            break;
        case V3:
            fprintf(stdout, "\tSource Port = %d\n", *sport);
            fprintf(stdout, "\tDestination Port = %d\n", *dport);
            fprintf(stdout, "\tSequence Num = %02x\n", seq);
            fprintf(stdout, "\tAcknowledgment Num = %02x\n", ack_seq);
            fprintf(stdout, "\tDate Offset = %d\n", dataOff);
            fprintf(stdout, "\tFlags : \n");
            fprintf(stdout, "\t\t- FIN : %d\n", fin);
            fprintf(stdout, "\t\t- SYN : %d\n", syn);
            fprintf(stdout, "\t\t- RST : %d\n", reset);
            fprintf(stdout, "\t\t- PSH : %d\n", push);
            fprintf(stdout, "\t\t- ACK : %d\n", ack);
            fprintf(stdout, "\t\t- URG : %d\n", urg);
            fprintf(stdout, "\tWindow = %d\n", window);
            fprintf(stdout, "\tChecksum = 0x%04x\n", checksum);
            fprintf(stdout, "\tUrgent Pointer = %d\n", urgPointer);
            //Si la taille de l'entete tcp est supérieure à 20 octets alors il y a des options tcp et on les affiche uniquement si le niveau de détails est au plus haut
            if (*to_add > 20 && level == V3) {
                int i = sizeof(struct tcphdr), value, len;
                fprintf(stdout, "\tOptions:\n");
                do {
                    fprintf(stdout, "\t\tTCP Option - ");
                    switch (packet[i]) {
                        case NOP:
                            fprintf(stdout, "\tNo Operation (NOP)\n");
                            i++;
                            break;

                        case MSS:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tMaximum Segment Size (%d)\n", packet[i]);
                            fprintf(stdout, "\t\t\t\tLength: %d\n", len);
                            value = packet[i + 2] << 8 | packet[i + 3];
                            fprintf(stdout, "\t\t\t\tMSS Value: %d bytes\n", value);
                            i += len;
                            break;

                        case WS:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tWindow Scale (%d)\n", packet[i]);
                            fprintf(stdout, "\t\t\t\tLength: %d\n", len);
                            fprintf(stdout, "\t\t\t\tShift count: %d\n", packet[i + 2]);
                            i += len;
                            break;

                        case SACKP:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tSack Permitted (%d)\n", packet[i]);
                            fprintf(stdout, "\t\t\t\tLength: %d\n", len);
                            i += len;
                            break;

                        case SACK:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tSack\n");
                            i += len;
                            break;

                        case TS:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tTimestamp (%d)\n", packet[i]);
                            fprintf(stdout, "\t\t\t\tLength: %d\n", len);
                            value = get_timestamp(packet, i);
                            fprintf(stdout, "\t\t\t\tTimestamp value: %d secs\n", value);
                            value = get_timestamp(packet, i + 4);
                            fprintf(stdout, "\t\t\t\tTimestamp echo reply: %d secs\n", value);
                            i += len;
                            break;

                        default:
                            len = (int)packet[i + 1];
                            fprintf(stdout, "\tUnknown \n");
                            fprintf(stdout, "\t\t\tLength: %d\n", len);
                            int cpt;
                            if (len > 2) {
                                fprintf(stdout, "\t\t\tValue: 0x");
                                for (cpt = 2; cpt < len; cpt++)
                                fprintf(stdout, "%02x", packet[i + cpt]);
                            }
                            fprintf(stdout, "\n");
                            i += len;
                            break;
                    }
                    fprintf(stdout, "\n");
                } while (i < *to_add);
            }
            break;
    }
}

//Récupère la valeur du timestamp
u_int32_t get_timestamp (const unsigned char *packet, int i) {
    return packet[i + 2] << 24 | packet[i + 3] << 16 | packet[i + 4] << 8 | packet[i + 5];
}
