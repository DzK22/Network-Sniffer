#include "../headers/transfer.h"

void treat_https (const unsigned char *packet, int type, int len, int level) {
    if (type == REQUEST)
        fprintf(stdout, " REQUEST\n");
    else
        fprintf(stdout, " RESPONSE\n");
    if (len <= 0)
        return;
    (void)level;
    print(packet, len);
}
