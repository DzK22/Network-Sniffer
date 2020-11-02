#include "../headers/application.h"

bool get_app (const unsigned char *packet, int port, int type, int level, int len) {
    (void)level;
    (void)packet;
    switch (port) {
        case DHCP:
            break;

        case DNS:
            treat_dns(packet, level);
            break;

        case TELNET:
            break;

        case HTTPS:
            fprintf(stdout, "\n\tHTTPS [%d] =>", port);
            treat_https(packet, type, len, level);
            break;

        case HTTP:
            fprintf(stdout, "\n\tHTTP [%d] =>", port);
            treat_https(packet, type, len, level);
            break;

        case SMTP:
            break;

        case SMTPS:
            break;

        default:
            return false;
    }
    return true;
}
void treat_app (const unsigned char *packet, int sport, int dport, int *to_add, int level, int len) {
    (void)to_add;
    (void)level;
    if (!get_app(packet, sport, REQUEST, level, len) && !get_app(packet, dport, RESPONSE, level, len))
        fprintf(stderr, "\n\tTHERE IS NO APP MATCHING\n");
}

void treat_https (const unsigned char *packet, int type, int len, int level) {
    if (type == REQUEST)
        fprintf(stdout, " REQUEST\n");
    else
        fprintf(stdout, " RESPONSE\n");
    if (len <= 0)
        return;
    (void)level;
    print(packet, len);
}

void treat_dns (const unsigned char *packet, int level) {
    (void)level;
    HEADER *dns = (HEADER *)packet;
    if (dns->qr)
        fprintf(stdout, "\n\tRESPONSE");
    else
        fprintf(stdout, "\n\tREQUEST");
    switch (dns->opcode) {
        case DNSQUERY:
            fprintf(stdout, " Query (%d)\n", dns->opcode);
            break;
        case DNSIQUERY:
            fprintf(stdout, " Inverse Query (%d)\n", dns->opcode);
            break;
        case DNSSSR:
            fprintf(stdout, " Server Status Request (%d)\n", dns->opcode);
            break;
        case DNSNOTIFY:
            fprintf(stdout, " Notify (%d)\n", dns->opcode);
            break;
        case DNSUPDATE:
            fprintf(stdout, " Update (%d)\n", dns->opcode);
            break;
        default:
            fprintf(stdout, " Unknows (%d)\n", dns->opcode);
    }
    uint16_t nQuestions = ntohs(dns->qdcount);
    uint16_t nAnswers = ntohs(dns->ancount);
    uint16_t nAuth = ntohs(dns->nscount);
    uint16_t nAdd = ntohs(dns->arcount);
    fprintf(stdout, "\tQuestions : %d\n", nQuestions);
    fprintf(stdout, "\tAnswers RRs: %d\n", nAnswers);
    fprintf(stdout, "\tAuthority RRs : %d\n", nAuth);
    fprintf(stdout, "\tAdditionnal RRs : %d\n", nAdd);
}
