#include "../headers/dns.h"

//Appelée que si Verbose = 2 ou 3
void treat_dns (const unsigned char *packet, int level) {
    HEADER *dns = (HEADER *)packet;
    uint16_t tID, nQuestions, nAnswers, nAuth, nAdd;
    tID = ntohs(dns->id);
    nQuestions = ntohs(dns->qdcount);
    nAnswers = ntohs(dns->ancount);
    nAuth = ntohs(dns->nscount);
    nAdd = ntohs(dns->arcount);
    switch (level) {
        case V1:
            fprintf(stdout, "|| DNS\n");
            break;

        case V2:
            fprintf(stdout, "$> DNS: Questions: %d, Answers: %d, Auths: %d, Adds: %d\n", nQuestions, nAnswers, nAuth, nAdd);
            break;

        case V3:
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
                    datas += resolve(packet, datas);
                    struct q_datas *q_data = (struct q_datas *)datas;
                    fprintf(stdout, "\n");
                    char *class = get_class(ntohs(q_data->clss));
                    char *type = get_type(ntohs(q_data->type));
                    fprintf(stdout, "\t\t- Type: %s\n", type);
                    fprintf(stdout, "\t\t- Class: %s\n\n", class);
                    datas += 4;
                }
            }
            //Answers treatment
            if (nAnswers)
                dns_print("Answers", packet, datas, nAnswers);
            //Authorities treatment
            if (nAuth)
                dns_print("Authorities", packet, datas, nAuth);
            //Additionnals treatment
            if (nAdd)
                dns_print("Additionnals", packet, datas, nAdd);
            break;
    }
}

void dns_print(const char *type, const unsigned char *packet, const unsigned char *datas, u_int16_t n) {
    unsigned i;
    fprintf(stdout, "\t%s:\n", type);
    for (i = 0; i < n; i++) {
        fprintf(stdout, "\t\t- Name: ");
        datas += resolve(packet, datas);
        struct r_datas *data = (struct r_datas *)datas;
        u_int16_t len = ntohs(data->len);
        fprintf(stdout, "\n");
        char *class = get_class(ntohs(data->clss));
        char *type = get_type(ntohs(data->type));
        fprintf(stdout, "\t\t- Type: %s\n", type);
        fprintf(stdout, "\t\t- Class: %s\n", class);
        fprintf(stdout, "\t\t- Ttl: %d\n", ntohl(data->ttl));
        fprintf(stdout, "\t\t- Length: %d\n", ntohs(data->len));
        datas += 10;
        if (ntohs(data->clss) == IN) {
            struct in_addr *ip = (struct in_addr *)datas;
            char str[LEN];
            if (ntohs(data->type) == A) {
                if (inet_ntop(AF_INET, ip, str, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop error\n");
                    return;
                }
                fprintf(stdout, "\t\t- Address: %s\n", str);
            }
            else if (ntohs(data->type) == AAAA) {
                if (inet_ntop(AF_INET6, ip, str, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop error\n");
                    return;
                }
                fprintf(stdout, "\t\t- Address: %s\n", str);
            }
        }
        fprintf(stdout, "\n");
        datas += len;
    }
}

unsigned resolve (const unsigned char *packet, const unsigned char *rest) {
    int total = 0, len, i = 0;
    //On lit le nom tant qu'il n'est pas terminé
    while ((len = *(rest++)) != '\0') {
        //ON vérifie si le premier octet indique que c'est un pointeur
        if (len & PTRMASK) {
            //Si le premier octet est un pointeur on récupère l'offset (sur 14 bits)
            int off = (len & PTRINDEXMASK) << 8 | *(rest++);
            //On recherche le nom récursivement à l'offset indiqué
            resolve(packet, packet + off);
            total++;
            break;
        }
        //Si le premier octet n'est pas un pointeur on affiche le nom
        else {
            total += (1 + len);
            for (i = 0; i < len; i++) {
                if (isprint(*rest))
                    fprintf(stdout, "%c", *(rest++));
            }
            fprintf(stdout, ".");
        }
    }

    return ++total;
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

char *get_class (u_int16_t class) {
    switch (class) {
        case IN:
            return "IN";
        case CS:
            return "CS";
        case CH:
            return "CH";
        case HS:
            return "HS";
        default:
            return "Unknown";
    }
}

char *get_type (u_int16_t type) {
    switch (type) {
        case SOA:
            return "SOA";
        case A:
            return "A";
        case AAAA:
            return "AAAA";
        case NS:
            return "NS";
        case PTR:
            return "PTR";
        case MX:
            return "MX";
        case CNAME:
            return "CNAME";
        case TXT:
            return "TXT";
        case HINFO:
            return "HINFO";
        default:
            return "Unknown";
    }
}
