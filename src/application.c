#include "../headers/application.h"

bool get_app (const unsigned char *packet, int port, int type, int level, int len) {
    (void)level;
    (void)packet;
    switch (port) {
        case DHCP:
            break;

        case DNS:
            fprintf(stdout, "\tDNS [%d]\n", port);
            treat_dns(packet, level);
            break;

        case TELNET:
            break;

        case HTTPS:
            fprintf(stdout, "\tHTTPS [%d] =>", port);
            treat_https(packet, type, len, level);
            break;

        case HTTP:
            fprintf(stdout, "\tHTTP [%d] =>", port);
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
    uint16_t tID, nQuestions, nAnswers, nAuth, nAdd;
    tID = ntohs(dns->id);
    nQuestions = ntohs(dns->qdcount);
    nAnswers = ntohs(dns->ancount);
    nAuth = ntohs(dns->nscount);
    nAdd = ntohs(dns->arcount);
    fprintf(stdout, "\tTransaction ID : 0x%04x\n", tID);
    if (dns->qr)
        fprintf(stdout, "\tResponse: Message is a response\n");
    else
        fprintf(stdout, "\tResponse: Message is a query\n");
    put_opcode(dns->opcode);
    //Answers only in responses
    if (dns->qr) {
        if (dns->aa)
            fprintf(stdout, "\tAuthoritative: Server is an authority for domain\n");
        else
            fprintf(stdout, "\tAuthoritative: Server is not an authority for domain\n");
        if (dns->ra)
            fprintf(stdout, "\tRecursion available: Server can do recursive queries\n");
        if (!dns->ad)
            fprintf(stdout, "\tAnswer authenticated: Answer/authority portion was not authenticated by the server\n");
        put_rcode(dns->rcode);
    }
    if (dns->tc)
        fprintf(stdout, "\tTruncated: Message is truncated\n");
    else
        fprintf(stdout, "\tTruncated: Message is not truncated\n");
    if (dns->rd)
        fprintf(stdout, "\tRecursion desired: Do query recursively\n");
    else
        fprintf(stdout, "\tRecursion desired: Do not query recursively\n");
    if (dns->cd)
        fprintf(stdout, "\tNon-authenticated data: Acceptable\n");
    else
        fprintf(stdout, "\tNon-authenticated data: Unacceptable\n");

    fprintf(stdout, "\tQuestions : %d\n", nQuestions);
    fprintf(stdout, "\tAnswers RRs: %d\n", nAnswers);
    fprintf(stdout, "\tAuthority RRs : %d\n", nAuth);
    fprintf(stdout, "\tAdditionnal RRs : %d\n", nAdd);

    const unsigned char *datas = packet + sizeof(HEADER);
    unsigned i;
    //Questions treatment
    if (nQuestions) {
        fprintf(stdout, "\tQuestions:\n");
        for (i = 0; i < nQuestions; i++) {
            fprintf(stdout, "\t\t- Name: ");
            datas = datas + get_name(packet, datas);
            struct q_datas *q_data = (struct q_datas *)datas;
            fprintf(stdout, "\n");
            fprintf(stdout, "\t\t- Type: %d\n", ntohs(q_data->type));
            fprintf(stdout, "\t\t- Class: %d\n", ntohs(q_data->clss));
            datas += 4;
            fprintf(stdout, "\n\n");
        }
    }
    (void)datas;
}

unsigned get_name (const unsigned char *packet, const unsigned char *rest) {
    bool ptr;
    unsigned len = 0;
    for (;rest[len] != '\0';) {
        if (((u_int8_t)rest[len] & PTRMASK) == PTRVALUE) {
            u_int16_t off = rest[len] << 8;
            off |= rest[len + 1];
            off &= PTRINDEXMASK;
            ptr = true;
            get_name(packet, packet + off);
            return 2;
        }
        else {
            if (isprint(rest[len + 1]) && rest[len + 1] != '\n')
                fprintf(stdout, "%c", rest[len + 1]);
            else
                fprintf(stdout, ".");
            len++;
            ptr = false;
        }
    }
    if (!ptr)
        len++;
    return len;
}

void put_opcode(unsigned opcode) {
    fprintf(stdout, "\tOpcode: ");
    switch (opcode) {
        case DNSQUERY:
            fprintf(stdout, "Query (%d)\n", opcode);
            break;
        case DNSIQUERY:
            fprintf(stdout, "Inverse Query (%d)\n", opcode);
            break;
        case DNSSSR:
            fprintf(stdout, "Server Status Request (%d)\n", opcode);
            break;
        case DNSNOTIFY:
            fprintf(stdout, "Notify (%d)\n", opcode);
            break;
        case DNSUPDATE:
            fprintf(stdout, "Update (%d)\n", opcode);
            break;
        default:
            fprintf(stdout, "Unknows (%d)\n", opcode);
            break;
    }
}

void put_rcode (unsigned rcode) {
    fprintf(stdout, "\tReply Code: ");
    switch (rcode) {
        case DNOERROR:
            fprintf(stdout, "DNS Query completed successfully (%d)\n", rcode);
            break;
        case DFORMERR:
            fprintf(stdout, "DNS Query Format Error (%d)\n", rcode);
            break;
        case DSERVFAIL:
            fprintf(stdout, "Server failed to complete the DNS request (%d)\n", rcode);
            break;
        case DNXDOMAIN:
            fprintf(stdout, "Domain name does not exist (%d)\n", rcode);
            break;
        case DNOTIMP:
            fprintf(stdout, "Function not implemented (%d)\n", rcode);
            break;
        case DREFUSED:
            fprintf(stdout, "The server refused to answer for the query (%d)\n", rcode);
            break;
        case DYXDOMAIN:
            fprintf(stdout, "Name that should not exist, does exist (%d)\n", rcode);
            break;
        case DXRRSET:
            fprintf(stdout, "RRset that should not exist, does exist (%d)\n", rcode);
            break;
        case DNOTAUTH:
            fprintf(stdout, "Server not authoritative for the zone (%d)\n", rcode);
            break;
        case DNOTZONE:
            fprintf(stdout, "Name not in zone (%d)\n", rcode);
            break;
        default:
            fprintf(stdout, "Unknown reply code (%d)\n", rcode);
            break;
    }
}
