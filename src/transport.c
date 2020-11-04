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

        case -1:
            break;

        default:
            fprintf(stdout, "\tUnknown (%d)\n", t_protocol);
            break;
    }
}

void treat_udp(const unsigned char *packet, int *sport, int *dport, int level) {
    (void)level;
    struct udphdr *udp = (struct udphdr *)packet;
    int checksum, dataLength;
    *sport = ntohs(udp->uh_sport);
    *dport = ntohs(udp->uh_dport);
    checksum = ntohs(udp->uh_sum);
    dataLength = ntohs(udp->uh_ulen);

    fprintf(stdout, "\tSource port = %d\n", *sport);
    fprintf(stdout, "\tDestination port = %d\n", *dport);
    fprintf(stdout, "\tChecksum = 0x%04x\n", checksum);
    fprintf(stdout, "\tLength = %d\n", dataLength);
}

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
    if (*to_add > 20) {
        const unsigned char *options = packet + 20;
        int size = *to_add - 20, i;
        unsigned char t, l;
        fprintf(stdout, "\tOptions:\n");
        for (; size > 0;) {
            t = options[0];
            //Signe la fin des options tcp, la suite est du padding
            if (t == '\0')
                break;
            fprintf(stdout, "\t\tT: %d", t);
            put_tcp_options(t);
            if (t == NOP) {
                options++;
                size--;
            }
            else {
                l = options[1];
                fprintf(stdout, "\t\tL: %d\n", l);
                if (l - 2 > 0) {
                    fprintf(stdout, "\t\tV: ");
                    for (i = 0; i < l - 2; i++)
                        fprintf(stdout, "%01x", options[i + 2]);
                    fprintf(stdout, "\n");
                }
                options += l;
                size -= l;
            }
            fprintf(stdout, "\n");
        }
    }
}

/*Type du T-L-V vers String*/
void put_tcp_options (int option) {
    switch (option) {
        case NOP:
            fprintf(stdout, "\t\tNo Operation (%d)\n", option);
            break;
        case MSS:
            fprintf(stdout, "\t\tMaximum Segment Size (%d)\n", option);
            break;
        case WS:
            fprintf(stdout, "\t\tWindow Scale (%d)\n", option);
            break;
        case SACKP:
            fprintf(stdout, "\t\tSack Permitted (%d)\n", option);
            break;
        case SACK:
            fprintf(stdout, "\t\tSack (%d)\n", option);
            break;
        case TS:
            fprintf(stdout, "\t\tTimestamp (%d)\n", option);
            break;
        default:
            fprintf(stdout, "\t\tUnknown (%d)\n", option);
            break;
    }
}
