#include "../headers/analyseur.h"
void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    unsigned i;
    for (i = 0; i < header->caplen; i++) {
        printf("%x ", packet[i]);
    }
    printf("time = %ld\n", header->ts.tv_sec);
}

int main (int argc, char **argv) {
    printf("Bonjour Danyl\n");
    if ((argc-1)%2!=0) {
        printf("wrong number of arguments %d\n",argc-1);
        return EXIT_FAILURE;
    }
    char *interface = NULL;
    char *fichier = NULL;
    char *filtre = NULL;
    int level = -1;
    int i;
    for(i = 1; i < argc; i += 2) {
        switch (argv[i][0]) {
              case '-':
                if (strcmp(argv[i], "-i") == 0) {
                    if ((interface != NULL)||(fichier != NULL)) {
                        printf("Can't define interface -i\n");
                        return EXIT_FAILURE;
                    }
                    interface = argv[i+1];
                    printf("Interface %s\n",interface);
                }
                if(strcmp(argv[i], "-o") == 0) {
                    if((interface != NULL) || (fichier != NULL) || (filtre != NULL)) {
                        printf("Can't define offline file -o\n");
                        return EXIT_FAILURE;
                    }
                    fichier = argv[i+1];
                    printf("Fichier %s\n",fichier);
                }
                if (strcmp(argv[i], "-f")==0) {
                    if ((filtre != NULL) || (fichier != NULL)) {
                        printf("Can't define filter -f\n");
                        return EXIT_FAILURE;
                    }
                    filtre = argv[i+1];
                    printf("Filtre %s\n", filtre);
                }
                if (strcmp(argv[i], "-v") == 0) {
                    if (level != -1) {
                        printf("Can't define level -f\n");
                        return EXIT_FAILURE;
                    }
                    level = atoi(argv[i+1]);
                    printf("level %d\n", level);
                }
                break;
              default:
                printf("Invalid arguments\n");
            }
    }

    pcap_if_t *alldevs;
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuff) == -1) {
        fprintf(stderr, "Impossible de capturer les devices\n");
        return EXIT_FAILURE;
    }
    bool exist = false;
    while (alldevs != NULL) {
        printf("%s\n", alldevs->name);
        if (strcmp(alldevs->name, interface) == 0)
            exist = true;
        alldevs = alldevs->next;
    }
    if (!exist) {
        fprintf(stderr, "%s doens\'t exist\nVoici la liste des interfaces disponibles :\n", interface);
        return EXIT_FAILURE;
    }
    bpf_u_int32 netp, maskp;
    if (pcap_lookupnet(interface != NULL ? interface : alldevs[0].name, &netp, &maskp, errbuff) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet error\n");
        return EXIT_FAILURE;
    }

    pcap_t *packet;
    if ((packet = pcap_open_live(interface != NULL ? interface : alldevs[0].name, BUFSIZ, 0, 1000, errbuff)) == NULL) {
        fprintf(stderr, "pcap_open_live error\n");
        return EXIT_FAILURE;
    }
    int loop_res;
    if ((loop_res = pcap_loop(packet, 1, callback, NULL)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop error\n");
        return EXIT_FAILURE;
    }
    printf("%d\n", loop_res);
    pcap_close(packet);
    return EXIT_SUCCESS;
}
