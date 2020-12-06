#include "../headers/icmp.h"

void treat_icmp (const unsigned char *packet, int level) {
    struct icmphdr *icmp = (struct icmphdr *)packet;
    switch (level) {
        case V1:
            fprintf(stdout, "|| ICMP ");
            put_type(icmp->type);
            break;

        case V2:
            fprintf(stdout, PINK"$> ICMP: "COL_RESET);
            put_type(icmp->type);
            break;

        case V3:
            fprintf(stdout, PINK"       └─ ICMP Message ");
            put_type(icmp->type);
            fprintf(stdout, COL_RESET);
            fprintf(stdout, PINK"        ├─"COL_RESET" Checksum: %d\n", ntohs(icmp->checksum));
            fprintf(stdout, PINK"        ├─"COL_RESET" ID: %d\n", ntohs(icmp->un.echo.id));
            fprintf(stdout, PINK"        └─"COL_RESET" Sequence: %d\n", ntohs(icmp->un.echo.sequence));
            break;

    }
}

void put_type(u_int8_t type) {
    switch (type) {
        case ICMP_ECHO:
        fprintf(stdout, "Echo Request ");
            break;

        case ICMP_ECHOREPLY:
        fprintf(stdout, "Echo Reply ");
            break;

        case ICMP_DEST_UNREACH:
        fprintf(stdout, "Destination Unreachable");
            break;

        case ICMP_SOURCE_QUENCH:
        fprintf(stdout, "Source Quench");
            break;

        case ICMP_INFO_REPLY:
        fprintf(stdout, "Info Reply");
            break;

        case ICMP_INFO_REQUEST:
        fprintf(stdout, "Info Request");
            break;

        case ICMP_TIME_EXCEEDED:
        fprintf(stdout, "Time Exceeded");
            break;

        case ICMP_ADDRESS:
        fprintf(stdout, "Adress Mask Request");
            break;

        case ICMP_ADDRESSREPLY:
        fprintf(stdout, "Adress Mask Reply");
            break;

        default:
            fprintf(stdout, "Unknown");
            break;
    }
    fprintf(stdout, " (%d)\n", type);
}
