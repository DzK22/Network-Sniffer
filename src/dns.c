#include "../headers/dns.h"

//Appelée que si Verbose = 2 ou 3
void treat_dns (const unsigned char *packet, int level, int type) {
    HEADER *dns = (HEADER *)packet;
    u_int16_t tID, nQuestions, nAnswers, nAuth, nAdd;
    tID = ntohs(dns->id);
    nQuestions = ntohs(dns->qdcount);
    nAnswers = ntohs(dns->ancount);
    nAuth = ntohs(dns->nscount);
    nAdd = ntohs(dns->arcount);
    unsigned char *datas = (unsigned char *)packet + sizeof(HEADER);
    switch (level) {
        case V1:
            fprintf(stdout, "|| %s: Questions: %d, Answers: %d, Auths: %d, Adds: %d\n", type == DNS ? "DNS" : "MDNS", nQuestions, nAnswers, nAuth, nAdd);
            break;

        case V2:
            fprintf(stdout, CYAN"$> %s:"COL_RESET" Questions: %d, Answers: %d, Auths: %d, Adds: %d => ", type == DNS ? "DNS" : "MDNS", nQuestions, nAnswers, nAuth, nAdd);
            fprintf(stdout, "Query: ");
            resolve(packet, datas);
            fprintf(stdout, "\n");
            break;

        case V3:
            fprintf(stdout , CYAN"          └─ %s ", type == DNS ? "DNS" : "MDNS");
            if (dns->qr)
                fprintf(stdout, "Response with %d Questions, %d Answers, %d Auths, %d Adds\n"COL_RESET, nQuestions, nAnswers, nAuth, nAdd);
            else
                fprintf(stdout, "Query with %d Questions, %d Answers, %d Auths, %d Adds\n"COL_RESET, nQuestions, nAnswers, nAuth, nAdd);
            fprintf(stdout, CYAN"            ├─"COL_RESET" Transaction ID : 0x%04x\n", tID);
            put_opcode(dns->opcode);
            //Answers only in responses
            if (dns->qr) {
                if (dns->aa)
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Authoritative: Server is an authority for domain\n");
                else
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Authoritative: Server is not an authority for domain\n");
                if (dns->ra)
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Recursion available: Server can do recursive queries\n");
                if (!dns->ad)
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Answer authenticated: Answer/authority portion was not authenticated by the server\n");
                put_rcode(dns->rcode);
            }
            if (dns->tc)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Truncated: Message is truncated\n");
            else
                fprintf(stdout, CYAN"            ├─"COL_RESET" Truncated: Message is not truncated\n");
            if (dns->rd)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Recursion desired: Do query recursively\n");
            else
                fprintf(stdout, CYAN"            ├─"COL_RESET" Recursion desired: Do not query recursively\n");
            if (dns->cd)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Non-authenticated data: Acceptable\n");
            else
                fprintf(stdout, CYAN"            ├─"COL_RESET" Non-authenticated data: Unacceptable\n");
            //Questions treatment
            if (nQuestions)
                dns_print("Questions", packet, &datas, nQuestions, nAnswers || nAuth || nAdd ? true : false);
            //Answers treatment
            if (nAnswers)
                dns_print("Answers", packet, &datas, nAnswers, nAuth || nAdd ? true : false);
            //Authorities treatment
            if (nAuth)
                dns_print("Authorities", packet, &datas, nAuth, nAdd ? true : false);
            //Additionnals treatment
            if (nAdd)
                dns_print("Additionnals", packet, &datas, nAdd, false);
            break;
    }
}

void dns_print(const char *type, const unsigned char *packet, unsigned char **datas, u_int16_t n, bool is_following) {
    unsigned i;
    int test = strncmp(type, "Questions", 9);
    fprintf(stdout, CYAN"            ├─"COL_RESET" \t%s:\n", type);
    for (i = 0; i < n; i++) {
        fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Name: ");
        (*datas) += resolve(packet, *datas);
        struct r_datas *rdata = NULL;
        struct q_datas *qdata = NULL;
        if (test)
            rdata = (struct r_datas *)(*datas);
        else
            qdata = (struct q_datas *)(*datas);

        u_int16_t num_class, num_type;
        if (rdata != NULL) {
            num_class = ntohs(rdata->clss);
            num_type = ntohs(rdata->type);
        }
        else if (qdata != NULL) {
            num_class = ntohs(qdata->clss);
            num_type = ntohs(qdata->type);
        }
        fprintf(stdout, "\n");
        char *class = get_class(num_class);
        char *str_type = get_type(num_type);

        //2 + 2 octets pour les champs class et type
        (*datas) += 4;

        if (test) {
            fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Class: %s\n", class);
            fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Type: %s\n", str_type);
            //fprintf(stdout, CYAN"            ├"COL_RESET"\n");
        }
        else {
            if (is_following) {
                fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Class: %s\n", class);
                fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Type: %s\n", str_type);
                fprintf(stdout, CYAN"            ├"COL_RESET"\n");
            }
            else {
                fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Class: %s\n", class);
                fprintf(stdout, CYAN"            └─"COL_RESET" \t\t- Type: %s\n", str_type);
            }
            continue;
        }
        u_int16_t len = ntohs(rdata->len);
        u_int32_t ttl = ntohl(rdata->ttl);
        fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Ttl: %d\n", ttl);
        fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Length: %d\n", len);

        //2 + 4 octets pour les champs len et ttl (resp.)
        (*datas) += 6;
        if (!len) {
            if (i == (unsigned)n - 1)
                fprintf(stdout, CYAN"            └─"COL_RESET" \n");
            continue;
        }
        if (num_class == IN) {
            struct in_addr *ip = (struct in_addr *)(*datas);
            char str[LEN];
            switch (num_type) {
                case T_A:
                    if (inet_ntop(AF_INET, ip, str, LEN) == NULL) {
                        fprintf(stderr, "inet_ntop error\n");
                        return;
                    }
                    fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Address: %s\n", str);
                    break;

                case T_AAAA:
                    if (inet_ntop(AF_INET6, ip, str, LEN) == NULL) {
                        fprintf(stderr, "inet_ntop error\n");
                        return;
                    }
                    fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- Address: %s\n", str);
                    break;

                case T_PTR:
                case T_CNAME:
                case T_NS:
                    fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- %s: ", str_type);
                    resolve(packet, *datas);
                    fprintf(stdout, "\n");
                    break;

                case T_MX:
                    fprintf(stdout, CYAN"            ├"COL_RESET" \t\t- %s: ", str_type);
                    resolve(packet, *datas + 2);
                    fprintf(stdout, "\n");
                    break;
            }
        }
        if (i != ((unsigned)n - 1) || is_following)
            fprintf(stdout, CYAN"            ├"COL_RESET" \n");
        else
            fprintf(stdout, CYAN"            └─"COL_RESET" \n");
        (*datas) += len;
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
    fprintf(stdout, CYAN"            ├─"COL_RESET" Operation: ");
    switch (opcode) {
        case QUERY:
            fprintf(stdout, "Query (%d)\n", opcode);
            break;
        case IQUERY:
            fprintf(stdout, "Inverse Query (%d)\n", opcode);
            break;
        case STATUS:
            fprintf(stdout, "Server Status Request (%d)\n", opcode);
            break;
        case NS_NOTIFY_OP:
            fprintf(stdout, "Notify (%d)\n", opcode);
            break;
        case NS_UPDATE_OP:
            fprintf(stdout, "Update (%d)\n", opcode);
            break;
        default:
            fprintf(stdout, "Unknows (%d)\n", opcode);
            break;
    }
}

void put_rcode (unsigned rcode) {
    fprintf(stdout, CYAN"            ├─"COL_RESET" Reply Code: ");
    switch (rcode) {
        case NOERROR:
            fprintf(stdout, "DNS Query completed successfully (%d)\n", rcode);
            break;
        case FORMERR:
            fprintf(stdout, "DNS Query Format Error (%d)\n", rcode);
            break;
        case SERVFAIL:
            fprintf(stdout, "Server failed to complete the DNS request (%d)\n", rcode);
            break;
        case NXDOMAIN:
            fprintf(stdout, "Domain name does not exist (%d)\n", rcode);
            break;
        case NOTIMP:
            fprintf(stdout, "Function not implemented (%d)\n", rcode);
            break;
        case REFUSED:
            fprintf(stdout, "The server refused to answer for the query (%d)\n", rcode);
            break;
        case YXDOMAIN:
            fprintf(stdout, "Name that should not exist, does exist (%d)\n", rcode);
            break;
        case YXRRSET:
            fprintf(stdout, "RRset that should not exist, does exist (%d)\n", rcode);
            break;
        case NOTAUTH:
            fprintf(stdout, "Server not authoritative for the zone (%d)\n", rcode);
            break;
        case NOTZONE:
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
        case T_SOA:
            return "SOA";
        case T_A:
            return "A";
        case T_AAAA:
            return "AAAA";
        case T_NS:
            return "NS";
        case T_PTR:
            return "PTR";
        case T_MX:
            return "MX";
        case T_CNAME:
            return "CNAME";
        case T_TXT:
            return "TXT";
        case T_HINFO:
            return "HINFO";
        default:
            return "Unknown";
    }
}
