#include "../headers/analyseur.h"
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
                    printf("%s\n", ptr->name);
                    if (interface != NULL && strcmp(ptr->name, interface) == 0)
                    exist = true;
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
        /*if (f) {
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
        }*/
    }

    args[0] = (unsigned char) level;
    args[1] = (int)0;
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
