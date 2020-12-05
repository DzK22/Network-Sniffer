#include "../headers/dns.h"

//Appelée que si Verbose = 2 ou 3
void treat_dns (const unsigned char *packet, int level, int type) {
    HEADER *dns = (HEADER *)packet;
    uint16_t tID, nQuestions, nAnswers, nAuth, nAdd;
    tID = ntohs(dns->id);
    nQuestions = ntohs(dns->qdcount);
    nAnswers = ntohs(dns->ancount);
    nAuth = ntohs(dns->nscount);
    nAdd = ntohs(dns->arcount);
    switch (level) {
        case V1:
            fprintf(stdout, "|| %s\n", type == DNS ? "DNS" : "MDNS");
            break;

        case V2:
            fprintf(stdout, CYAN"$> %s:"COL_RESET" Questions: %d, Answers: %d, Auths: %d, Adds: %d\n", type == DNS ? "DNS" : "MDNS", nQuestions, nAnswers, nAuth, nAdd);
            break;

        case V3:
            fprintf(stdout , "          └─ %s ", type == DNS ? "DNS" : "MDNS");
            if (dns->qr)
                fprintf(stdout, "Response with %d Questions, %d Answers, %d Auths, %d Adds\n", nQuestions, nAnswers, nAuth, nAdd);
            else
                fprintf(stdout, "Query with %d Questions, %d Answers, %d Auths, %d Adds\n", nQuestions, nAnswers, nAuth, nAdd);
            fprintf(stdout, "            ├─ Transaction ID : 0x%04x\n", tID);
            put_opcode(dns->opcode);
            //Answers only in responses
            if (dns->qr) {
                if (dns->aa)
                    fprintf(stdout, "            ├─ Authoritative: Server is an authority for domain\n");
                else
                    fprintf(stdout, "            ├─ Authoritative: Server is not an authority for domain\n");
                if (dns->ra)
                    fprintf(stdout, "            ├─ Recursion available: Server can do recursive queries\n");
                if (!dns->ad)
                    fprintf(stdout, "            ├─ Answer authenticated: Answer/authority portion was not authenticated by the server\n");
                put_rcode(dns->rcode);
            }
            if (dns->tc)
                fprintf(stdout, "            ├─ Truncated: Message is truncated\n");
            else
                fprintf(stdout, "            ├─ Truncated: Message is not truncated\n");
            if (dns->rd)
                fprintf(stdout, "            ├─ Recursion desired: Do query recursively\n");
            else
                fprintf(stdout, "            ├─ Recursion desired: Do not query recursively\n");
            if (dns->cd)
                fprintf(stdout, "            ├─ Non-authenticated data: Acceptable\n");
            else
                fprintf(stdout, "            ├─ Non-authenticated data: Unacceptable\n");

            const unsigned char *datas = packet + sizeof(HEADER);
            unsigned i;
            //Questions treatment
            if (nQuestions) {
                fprintf(stdout, "            ├─ Questions:\n");
                for (i = 0; i < nQuestions; i++) {
                    fprintf(stdout, "            ├ \t\t- Name: ");
                    datas += resolve(packet, datas);
                    struct q_datas *q_data = (struct q_datas *)datas;
                    fprintf(stdout, "\n");
                    char *class = get_class(ntohs(q_data->clss));
                    char *type = get_type(ntohs(q_data->type));
                    fprintf(stdout, "            ├ \t\t- Type: %s\n", type);
                    if (nAnswers || nAuth || nAdd)
                        fprintf(stdout, "            ├ \t\t- Class: %s\n            ├ \n", class);
                    else
                        fprintf(stdout, "            └─ \t\t- Class: %s\n", class);
                    datas += 4;
                }
            }
            //Answers treatment
            if (nAnswers)
                dns_print("Answers", packet, datas, nAnswers, nAuth || nAdd ? true : false);
            //Authorities treatment
            if (nAuth)
                dns_print("Authorities", packet, datas, nAuth, nAdd ? true : false);
            //Additionnals treatment
            if (nAdd)
                dns_print("Additionnals", packet, datas, nAdd, false);
            break;
    }
}

void dns_print(const char *type, const unsigned char *packet, const unsigned char *datas, u_int16_t n, bool is_following) {
    unsigned i;
    fprintf(stdout, "            ├─ \t%s:\n", type);
    for (i = 0; i < n; i++) {
        fprintf(stdout, "            ├ \t\t- Name: ");
        datas += resolve(packet, datas);
        struct r_datas *data = (struct r_datas *)datas;
        u_int16_t len = ntohs(data->len), num_class = ntohs(data->clss), num_type = ntohs(data->type);
        fprintf(stdout, "\n");
        char *class = get_class(num_class);
        char *type = get_type(num_type);
        fprintf(stdout, "            ├ \t\t- Type: %s\n", type);
        fprintf(stdout, "            ├ \t\t- Class: %s\n", class);
        fprintf(stdout, "            ├ \t\t- Ttl: %d\n", ntohl(data->ttl));
        fprintf(stdout, "            ├ \t\t- Length: %d\n", len);
        datas += 10;
        if (num_class == IN) {
            struct in_addr *ip = (struct in_addr *)datas;
            char str[LEN];
            if (num_type == A) {
                if (inet_ntop(AF_INET, ip, str, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop error\n");
                    return;
                }
                fprintf(stdout, "            ├ \t\t- Address: %s\n", str);
            }
            else if (num_type == AAAA) {
                if (inet_ntop(AF_INET6, ip, str, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop error\n");
                    return;
                }
                fprintf(stdout, "            ├ \t\t- Address: %s\n", str);
            }
        }
        if (i != ((unsigned)n - 1) || is_following)
            fprintf(stdout, "            ├ \n");
        else
            fprintf(stdout, "            └─ \n");
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
    fprintf(stdout, "            ├─ Operation: ");
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
    fprintf(stdout, "            ├─ Reply Code: ");
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
