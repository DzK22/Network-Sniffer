#include "../headers/telnet.h"

void treat_telnet (const unsigned char *packet, int len, int level) {
    int i;
    switch (level) {
        case V1:
            fprintf(stdout, "|| TELNET\n");
            break;

        case V2:
            fprintf(stdout, "$> TELNET\n");
            break;

        case V3:
            i = 0;
            do {
                if (packet[i] == IAC)
                    put_cmd(packet[++i]);

                if (packet[i] == SBEGIN) {
                    put_opt(packet[++i]);
                    do {
                        fprintf(stdout, " %d", packet[i++]);
                    } while (!(packet[i] == IAC) && packet[i + 1] == SEND);
                    fprintf(stdout, "\n");
                }
                else
                    put_opt(packet[++i]);
                i++;
            } while (i < len);
            break;
    }
}

void put_cmd (int cmd) {
    fprintf(stdout, "\t");
    switch (cmd) {
        case SBEGIN:
            fprintf(stdout, "Start of subgnegociation ");
            break;

        default:
            fprintf(stdout, "Unsupported cmd");
    }
    fprintf(stdout, " (%d) ", cmd);
}

void put_opt (int opt) {
    fprintf(stdout, "\t");
    switch (opt) {
        case ECHO:
            fprintf(stdout, "Echo");
            break;
        default:
            fprintf(stdout, "Unsupported option");
            break;
    }
    fprintf(stdout, " (%d)\n", opt);
}
