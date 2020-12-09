#include "../headers/ospf_v2.h"

//Traite OSPv2 (Seulement IPv4 et non la version 3 pour certains champs tels que les options de hello packet)
void treat_ospf(const unsigned char *packet, int *to_add, int level) {
    struct ospfhdr *ospf = (struct ospfhdr *)packet;
    *to_add = sizeof(struct ospfhdr);
    u_int16_t len = ntohs(ospf->len);
    u_int16_t checksum = ntohs(ospf->checksum);
    switch (level) {
        case V1:
            fprintf(stdout, "|| OSPF\t");
            break;

        case V2:
            fprintf(stdout, PINK"$> OSPF:"COL_RESET" version: %d, msg type: %s (%d)\n", ospf->version, get_ptype(ospf->type), ospf->type);
            break;

        case V3:
            fprintf(stdout, PINK"       └─ OSPFv2 Messsage\n"COL_RESET);
            fprintf(stdout, "         ├─ Version: %d\n", ospf->version);
            fprintf(stdout, "         ├─ Message Type: %s (%d)\n", get_ptype(ospf->type), ospf->type);
            fprintf(stdout, "         ├─ Packet Length: %d\n", len);
            fprintf(stdout, "         ├─ Source OSPF Router: %s\n", inet_ntoa(ospf->rid));
            fprintf(stdout, "         ├─ Area ID: %s\n", inet_ntoa(ospf->aid));
            if (!(ospf->type == HELLO && ospf->version == 2))
                fprintf(stdout, "         └─ Checksum: 0x%4x\n", checksum);
            if (ospf->type == HELLO && ospf->version == 2) {
                fprintf(stdout, "         ├─ Checksum: 0x%4x\n", checksum);
                int opts[8];
                u_int8_t opt = ospf->ospf_hello.options;
                opts[0] = (opt & OPT_DN) ? 1 : 0;
                opts[1] = (opt & OPT_O) ? 1 : 0;
                opts[2] = (opt & OPT_DC) ? 1 : 0;
                opts[3] = (opt & OPT_L) ? 1 : 0;
                opts[4] = (opt & OPT_N) ? 1 : 0;
                opts[5] = (opt & OPT_MC) ? 1 : 0;
                opts[6] = (opt & OPT_E) ? 1 : 0;
                opts[7] = (opt & OPT_MT) ? 1 : 0;
                u_int16_t h_int = ntohs(ospf->ospf_hello.interval);
                u_int32_t deadint = ntohl(ospf->ospf_hello.dead_interval);
                fprintf(stdout, "         ├─ Network Mask: %s\n", inet_ntoa(ospf->ospf_hello.nmask));
                fprintf(stdout, "         ├─ Hello Interval [sec]: %d\n", h_int);
                fprintf(stdout, "         ├─ Router Priority: %d\n", ospf->ospf_hello.priority);
                fprintf(stdout, "         ├─ Router Dead Interval: %d\n", deadint);
                fprintf(stdout, "         ├─ Options: 0x%2x\n", opt);
                print_hopt(opts, 8);
                fprintf(stdout, "         ├─ Designated Router: %s\n", inet_ntoa(ospf->ospf_hello.dr));
                fprintf(stdout, "         ├─ Backup Designated Router: %s\n", inet_ntoa(ospf->ospf_hello.bdr));
                fprintf(stdout, "         └─ Active Neighbor: %s\n", inet_ntoa(*ospf->ospf_hello.neighbor));
            }
            break;
    }
}

//Transforme le type d'un message OSPF en string pour l'affichage
char *get_ptype (int type) {
    char *str_type = NULL;
    switch (type) {
        case HELLO:
            str_type = "Hello Packet";
            break;
        case DBD:
            str_type = "DB Description";
            break;
        case LSR:
            str_type = "LS Request";
            break;
        case LSU:
            str_type = "LS Update";
            break;
        case LSA:
            str_type = "LSA";
            break;
        default:
            str_type = "Unknown";
            break;
    }
    return str_type;
}

//Affiche les options OSPFv2
void print_hopt (int *list, int n) {
    int i;
    for (i = 0; i < n; i++) {
        fprintf(stdout, "         ├\t\t");
        switch (i) {
            case 0:
                fprintf(stdout, "DN: ");
                if (!list[i])
                    fprintf(stdout, "Not set\n");
                else
                    fprintf(stdout, "Set\n");
                break;
            case 1:
                fprintf(stdout, "O: ");
                if (!list[i])
                    fprintf(stdout, "Not set\n");
                else
                    fprintf(stdout, "Set\n");
                break;
            case 2:
                fprintf(stdout, "(DC) Demand Circuits: ");
                if (!list[i])
                    fprintf(stdout, "Not supported\n");
                else
                    fprintf(stdout, "Supported\n");
                break;
            case 3:
                fprintf(stdout, "(L) LLS Data block: ");
                if (!list[i])
                    fprintf(stdout, "Not present\n");
                else
                    fprintf(stdout, "Present\n");
                break;
            case 4:
                fprintf(stdout, "(N) NSSA: ");
                if (!list[i])
                    fprintf(stdout, "Not supported\n");
                else
                    fprintf(stdout, "Supported\n");
                break;
            case 5:
                fprintf(stdout, "(MC) Multicast: ");
                if (!list[i])
                    fprintf(stdout, "Not capable\n");
                else
                    fprintf(stdout, "Capable\n");
                break;
            case 6:
                fprintf(stdout, "(E) External Routing: ");
                if (!list[i])
                    fprintf(stdout, "Not capable\n");
                else
                    fprintf(stdout, "Capable\n");
                break;
            case 7:
                fprintf(stdout, "(MT) Multi-Topology Routing: ");
                if (!list[i])
                    fprintf(stdout, "No\n");
                else
                    fprintf(stdout, "Yes\n");
                break;
        }
    }
}
