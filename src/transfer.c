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
                    fprintf(stdout, "$> HTTP:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ HTTP ");
                    break;
            }
            break;

        case HTTPS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| HTTPS");
                    break;

                case V2:
                    fprintf(stdout, "$> HTTPS:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ HTTPS ");
                    break;
            }
            break;

        case FTPD:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| FTP Data");
                    break;

                case V2:
                    fprintf(stdout, "$> FTP Data:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ FTP Data");
                    break;
            }
            break;

        case FTPC:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| FTP Control");
                    break;

                case V2:
                    fprintf(stdout, "$> FTP Control:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ FTP Control ");
                    break;
            }
            break;

        case SMTP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| SMTP");
                    break;

                case V2:
                    fprintf(stdout, "$> SMTP:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ SMTP ");
                    break;
            }
            break;

        case SMTPS:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| SMTPS");
                    break;

                case V2:
                    fprintf(stdout, "$> SMTPS:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ SMTPS ");
                    break;
            }
            break;

        case POP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| POP");
                    break;

                case V2:
                    fprintf(stdout, "$> POP:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ POP ");
                    break;
            }
            break;

        case IMAP:
            switch (level) {
                case V1:
                    fprintf(stdout, "|| IMAP");
                    break;

                case V2:
                    fprintf(stdout, "$> IMAP:");
                    break;

                case V3:
                    fprintf(stdout, "           └─ IMAP ");
                    break;
            }
            break;

        default:
            return;
    }

    if (!resp)
        fprintf(stdout, " REQUEST\n");
    else
        fprintf(stdout, " RESPONSE\n");

    if (len <= 0 || level != V3)
        return;

    print(packet, len);
}
