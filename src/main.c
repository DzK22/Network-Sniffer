#include "../headers/analyseur.h"
int threat_ethernet(const unsigned char *packet, int *protocol, int level) {
    struct ether_header *header;
    struct ether_addr *mac_src;
    struct ether_addr *mac_dst;
    header = (struct ether_header *) packet;
    mac_src = (struct ether_addr *) header->ether_shost;
    mac_dst = (struct ether_addr *) header->ether_dhost;
    *protocol = ntohs(header->ether_type);

    switch (level) {
        case V3:
            fprintf(stdout, "Ethernet:\n");
            fprintf(stdout, "\t@dest : %s\n", ether_ntoa(mac_dst));
            fprintf(stdout, "\t@src : %s\n", ether_ntoa(mac_src));
            char *type = NULL;
            if (*protocol == ETHERTYPE_IP)
                type = "IP";
            else if  (*protocol == ETHERTYPE_ARP)
                type = "ARP";
            else
                type = "?";
            fprintf(stdout, "\t type : %s\n", type);
            break;

        case V2:
            fprintf(stdout, "\t Ethernet:\n");
            fprintf(stdout, "\t@dest : %s\n", ether_ntoa(mac_dst));
            fprintf(stdout, "\t@src : %s\n", ether_ntoa(mac_src));
            break;

        case V1:
            if (*protocol == ETHERTYPE_ARP)
                fprintf(stdout, "[Ethernet] %s => %s\n", ether_ntoa(mac_src), ether_ntoa(mac_dst));
            break;
    }

    return sizeof(struct ether_header);
}

void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)args;
    (void)header;
    static unsigned long packetID = 0;
    packetID++;
    fprintf(stdout, "packet number = %ld\n", packetID);
    int protocol, level = args[0];
    int test = threat_ethernet(packet, &protocol, level);
    fprintf(stdout,"READ = %d\n", test);
}

int main (int argc, char **argv) {
    if ((argc - 1) % 2 != 0) {
        printf("wrong number of arguments %d\n",argc - 1);
        return EXIT_FAILURE;
    }
    char interface[512];
    char fichier[512];
    char filtre[512];
    int level = V2;
    char arg;
    unsigned char args[1];
    bool o = false, f = false, v = false, i = false;
    while ((arg = getopt(argc, argv, "n:v:o:i:f:")) != -1) {
        switch (arg) {
            case 'i':
                snprintf(interface, 512, "%s", optarg);
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
                snprintf(filtre, 512, "%s", optarg);
                break;

            case 'o':
                snprintf(fichier, 512, "%s", optarg);
                o = true;
                break;

            default:
                break;
        }
    }

    if (!v)
        fprintf(stderr, "Vous devez utilisez l'option -v [1..3]\n");

    if (i && o) {
        fprintf(stderr, "Vous ne pouvez pas utiliser -i et -o pendant la mm execution\n");
        return EXIT_FAILURE;
    }
    (void)f;
    args[0] = (unsigned char) level;
    pcap_if_t *alldevs;
    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuff) == -1) {
        fprintf(stderr, "Impossible de capturer les devices\n");
        return EXIT_FAILURE;
    }
    bool exist = false;
    pcap_if_t *ptr = alldevs;

    while (ptr != NULL) {
        if (interface != NULL && strcmp(ptr->name, interface) == 0)
            exist = true;
        ptr = ptr->next;
    }

    if (!exist && interface != NULL) {
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
    if ((loop_res = pcap_loop(packet, -1, callback, args)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop error\n");
        return EXIT_FAILURE;
    }
    printf("%d\n", loop_res);
    pcap_close(packet);
    return EXIT_SUCCESS;
}
