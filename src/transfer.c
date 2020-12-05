#include "../headers/transfer.h"

//Fonction qui invoque la fonction correpondant au protocole (de "transfert") applicatif du port passé en paramètre
void treat_transfer (const unsigned char *packet, bool resp, int len, int level, int port) {
    switch (port) {
        case HTTP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| HTTP");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> HTTP:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ HTTP ");
                    break;
            }
            break;

        case HTTPS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| HTTPS");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> HTTPS:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ HTTPS ");
                    break;
            }
            break;

        case FTPD:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| FTP Data");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> FTP Data:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ FTP Data");
                    break;
            }
            break;

        case FTPC:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| FTP Control");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> FTP Control:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ FTP Control ");
                    break;
            }
            break;

        case SMTP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| SMTP");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> SMTP:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ SMTP ");
                    break;
            }
            break;

        case SMTPS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| SMTPS");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> SMTPS:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ SMTPS ");
                    break;
            }
            break;

        case POP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| POP");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> POP:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ POP ");
                    break;
            }
            break;

        case IMAP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| IMAP");
                    break;

                case V2:
                    fprintf(stdout, CYAN"$> IMAP:"COL_RESET);
                    break;

                case V3:
                    fprintf(stdout, CYAN"           └─ IMAP ");
                    break;
            }
            break;

        default:
            return;
    }

    if (!resp)
        fprintf(stdout, " REQUEST\n"COL_RESET);
    else
        fprintf(stdout, " RESPONSE\n"COL_RESET);

    if (len <= 0 || level != V3)
        return;

    print(packet, len);
}
