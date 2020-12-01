#include "../headers/telnet.h"

void treat_telnet (const unsigned char *packet, int len, int level) {
    switch (level) {
        case V1:
            fprintf(stdout, "|| TELNET\n");
            break;

        case V2:
            fprintf(stdout, "$> TELNET\n");
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
    while (*byte == IAC && r < len) {
        byte++;
        r++;
        switch (*byte) {
            case DO:
                fprintf(stdout, "\tDo ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case DONT:
                fprintf(stdout, "\tDont ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case WILL:
                fprintf(stdout, "\tWill ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case WONT:
                fprintf(stdout, "\tWont ");
                byte++;
                r++;
                put_opt(*byte);
                break;

            case EC:
                fprintf(stdout, "\tErase char ");
                break;

            case EL:
                fprintf(stdout, "\tErase line ");
                break;

            case GA:
                fprintf(stdout, "\tGo ahead ");
                break;

            case SBEGIN:
                fprintf(stdout, "\tSubnegoc\n");
                byte++;
                r++;
                put_opt(*byte);
                fprintf(stdout, " value: ");
                last = byte - 1;
                while (r < len && *byte != SEND && *last != SEND) {
                    fprintf(stdout, "%0hhX ", *byte);
                    last = byte;
                    byte++;
                    r++;
                }
                fprintf(stdout, "%0hhX ", *byte);
                break;

            case AO:
                fprintf(stdout, "\tAbort output ");
                break;

            case NNOP:
                fprintf(stdout, "\tNo option ");
                break;

            case DM:
                fprintf(stdout, "\tData mark ");
                break;

            case IP:
                fprintf(stdout, "\tInterrupt ");
                break;

            case AYT:
                fprintf(stdout, "\tAre you there ");
                break;

            default:
                fprintf(stdout, "\tUnknown");
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
            fprintf(stdout, "Unknow ");
            break;
    }
    fprintf(stdout, "(%d)\n", opt);
}
