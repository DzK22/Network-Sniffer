#include "../headers/telnet.h"

void treat_telnet (const unsigned char *packet, int len, int level) {
    switch (level) {
        case V1:
            fprintf(stdout, "|| TELNET\n");
            break;

        case V2:
            fprintf(stdout, CYAN"$> TELNET\n"COL_RESET);
            break;

        case V3:
            if (packet[0] == IAC)
                negoc(packet, len);
            else
                print(packet, len);
            break;
    }
}

void negoc(const unsigned char *packet, int len) {
    unsigned char *byte = (unsigned char *)packet;
    unsigned char *last;
    int r = 0;
    if (len > 0)
        fprintf(stdout, CYAN"           └─"COL_RESET" ");
    while (*byte == IAC && r < len) {
        byte++;
        r++;
        if (r != 1)
            fprintf(stdout, "\t\t");
        else
            fprintf(stdout, "  ");
        switch (*byte) {
            case DO:
                fprintf(stdout, "Do ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case DONT:
                fprintf(stdout, "Dont ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case WILL:
                fprintf(stdout, "Will ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case WONT:
                fprintf(stdout, "Wont ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case EC:
                fprintf(stdout, "Erase char ");
                break;

            case EL:
                fprintf(stdout, "Erase line ");
                break;

            case GA:
                fprintf(stdout, "Go ahead ");
                break;

            case SBEGIN:
                fprintf(stdout, "Subnegoc: ");
                byte++;
                r++;
                put_opt(*byte);
                last = byte - 1;
                while (r < len && *byte != SEND && *last != SEND) {
                    last = byte;
                    byte++;
                    r++;
                }
                break;

            case AO:
                fprintf(stdout, "Abort output ");
                break;

            case NNOP:
                fprintf(stdout, "No option ");
                break;

            case DM:
                fprintf(stdout, "Data mark ");
                break;

            case IP:
                fprintf(stdout, "Interrupt ");
                break;

            case AYT:
                fprintf(stdout, "Are you there ");
                break;

            default:
                fprintf(stdout, "Unknown");
                break;
        }
        byte++;
        r++;
        fprintf(stdout, "\n");
    }
}

void put_opt (int opt) {
    switch (opt) {
        case ECHO:
            fprintf(stdout, "Echo ");
            break;

        case SGO_AHEAD:
            fprintf(stdout, "Suppr go ahead ");
            break;

        case T_TYPE:
            fprintf(stdout, "Terminal type ");
            break;

        case W_SIZE:
            fprintf(stdout, "Windows size ");
            break;

        case T_SPEED:
            fprintf(stdout, "Terminal speed ");
            break;

        case LINE_MODE:
            fprintf(stdout, "Line mode ");
            break;

        case ENV_VAR:
            fprintf(stdout, "Environnement variable ");
            break;

        case REM_FCTRL:
            fprintf(stdout, "Remote flow control ");
            break;

        case TMG_MARK:
            fprintf(stdout, "Timing mark ");
            break;

        case RECON:
            fprintf(stdout, "Reconnect ");
            break;

        default:
            fprintf(stdout, "Unknown ");
            break;
    }
    fprintf(stdout, "(%d)", opt);
}
