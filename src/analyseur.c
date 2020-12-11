#include "../headers/analyseur.h"
unsigned long packetID = 0;
extern unsigned long packetID;
pcap_t *packet;

volatile sig_atomic_t interrupt = 0;

void sigint_handler(int signum) {
    (void)signum;
    interrupt = 1;
    pcap_breakloop(packet);
}

int main (int argc, char **argv) {
    usage(argc);
    char interface[LEN];
    char fichier[LEN];
    char filtre[LEN];
    char errbuff[PCAP_ERRBUF_SIZE];
    int level = V2, res;
    char arg;
    unsigned char args[3];
    bool o = false, f = false, v = false, i = false;
    struct sigaction sig_int;
    sig_int.sa_handler = sigint_handler;
    if (sigemptyset(&sig_int.sa_mask) == -1) {
        fprintf(stderr, "sigemptyset error\n");
        return EXIT_FAILURE;
    }
    if (sigaction(SIGINT, &sig_int, NULL) == -1) {
        fprintf(stderr, "sigaction error\n");
        return EXIT_FAILURE;
    }
    while ((arg = getopt(argc, argv, "v:o:i:f:")) != -1) {
        switch (arg) {
            case 'i':
                res = snprintf(interface, LEN, "%s", optarg);
                if (test_snprintf(res, LEN) == EXIT_FAILURE)
                    return EXIT_FAILURE;
                i = true;
                break;

            case 'v':
                level = atoi(optarg);
                if (level != V3 && level != V2 && level != V1) {
                    fprintf(stderr, "[1..3]\n");
                    return EXIT_FAILURE;
                }
                v = true;
                break;

            case 'f':
                f = true;
                res = snprintf(filtre, LEN, "%s", optarg);
                if (test_snprintf(res, LEN) == EXIT_FAILURE)
                    return EXIT_FAILURE;
                break;

            case 'o':
                res = snprintf(fichier, LEN, "%s", optarg);
                if (test_snprintf(res, LEN) == EXIT_FAILURE)
                    return EXIT_FAILURE;
                o = true;
                break;

            default:
                usage(argc);
        }
    }

    if (!v)
        fprintf(stderr, "Vous devez utilisez l'option -v [1..3] | v = 2 par défaut\n");

    if (i && o) {
        fprintf(stderr, "Vous ne pouvez pas utiliser -i et -o pendant la mm execution\n");
        return EXIT_FAILURE;
    }

    if (f && o) {
        fprintf(stderr, "Vous ne pouvez pas utiliser -f et -o pendant la mm execution\n");
        return EXIT_FAILURE;
    }

    if (o) {
        if ((packet = pcap_open_offline(fichier, errbuff)) == NULL) {
            fprintf(stderr, "pcap_open_offline error\n");
            return EXIT_FAILURE;
        }
    }
    else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuff) == -1) {
            fprintf(stderr, "Impossible de capturer les devices\n");
            return EXIT_FAILURE;
        }

        bool exist = false;
        pcap_if_t *ptr = alldevs;
        if (!i) {
            res = snprintf(interface, LEN, "%s", alldevs[0].name);
            if (test_snprintf(res, LEN) == EXIT_FAILURE)
                return EXIT_FAILURE;
        }
        else {
            while (ptr != NULL) {
                if (strcmp(ptr->name, interface) == 0)
                    exist = true;
                ptr = ptr->next;
            }

            if (!exist) {
                fprintf(stderr, "%s n\'existe pas\nVoici la liste des interfaces disponibles :\n", interface);
                ptr = alldevs;
                while (ptr != NULL) {
                    fprintf(stdout, "%s\n", ptr->name);
                    ptr = ptr->next;
                }
                return EXIT_FAILURE;
            }
        }
        fprintf(stdout, "Capture sur l'interface [%s]\n", interface);
        if ((packet = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuff)) == NULL) {
            fprintf(stderr, "pcap_open_live\n");
            return EXIT_FAILURE;
        }
        pcap_freealldevs(alldevs);
        if (f) {
            struct bpf_program bfp_f;
            bpf_u_int32 maskp = 0;
            if (pcap_compile(packet, &bfp_f, filtre, 0, maskp) == -1) {
                fprintf(stderr, "Error filter compiling\n");
                return EXIT_FAILURE;
            }
            if (pcap_setfilter(packet, &bfp_f) == PCAP_ERROR) {
                fprintf(stderr, "Error filter setting\n");
                return EXIT_FAILURE;
            }
            fprintf(stdout, "le filtre %s a été appliqué sur l'interface %s\n", filtre, interface);
        }
    }

    args[0] = (unsigned char) level;
    if (pcap_loop(packet, -1, callback, args) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop error\n");
        return EXIT_FAILURE;
    }
    if (interrupt)
        fprintf(stdout, SUPPR"%ld packets captured\n", packetID);
    else
        fprintf(stdout, "%ld packets captured\n", packetID);
    pcap_close(packet);
    return EXIT_SUCCESS;
}

void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    packetID++;
    struct tm res;
    if (localtime_r(&header->ts.tv_sec, &res) == NULL) {
        fprintf(stderr, "localtime error\n");
        exit(EXIT_FAILURE);
    }
    char str_time[LEN];
    int e_protocol, t_protocol, sport, dport, len = header->len, level = args[0], previewHeaderLength, to_add, dataLen;
    switch (level) {
        case V1:
            fprintf(stdout, "%ld) ", packetID);
            break;

        case V2:
            fprintf(stdout, "** Packet ID = %ld **\n", packetID);
            break;

        case V3:
            if (strftime(str_time, LEN, "%a %Y-%m-%d %H:%M:%S %Z", &res)  == 0) {
                fprintf(stderr, "strftime error\n");
                exit(EXIT_FAILURE);
            }
            fprintf(stdout, "Packet ID = %ld arrived at %s with Length : %d bytes\n", packetID, str_time, len);
            break;
    }
    //Couche liaison
    treat_ethernet(packet, &e_protocol, level);
    previewHeaderLength = sizeof(struct ether_header);

    //Couche réseau
    treat_network(packet + previewHeaderLength, e_protocol, &t_protocol, &to_add, level, &dataLen);
    previewHeaderLength += to_add;

    //Couche transport
    treat_transport(packet + previewHeaderLength, t_protocol, &sport, &dport, &to_add, level);
    previewHeaderLength += to_add;

    //Couche applicative
    if (t_protocol == UDP)
        treat_app(packet + previewHeaderLength, sport, dport, level, len - dataLen);
    else if (t_protocol == TCP)
        treat_app(packet + previewHeaderLength, sport, dport, level, len - previewHeaderLength);

    if (fflush(stdout) == EOF) {
        fprintf(stderr, "fflush error\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stdout, "\n\n");
}

void usage (int argc) {
    if ((argc - 1) % 2) {
        fprintf(stderr, "Nombre d'arguments invalide %d\n", argc - 1);
        exit(EXIT_FAILURE);
    }
}

int test_snprintf(int res, int bytes) {
    if (res < 0 || res >= bytes) {
        fprintf(stderr, "snprintf error\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
