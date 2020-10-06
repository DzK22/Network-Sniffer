#include "../headers/network.h"

int threat_ipv4(const unsigned char *packet, int *protocol, int level) {
    (void)protocol;
    (void)level;
    char ip_source[LEN], ip_dest[LEN];
    struct iphdr *header = (struct iphdr *) (packet + ETH_HLEN);
    uint32_t ip_src = header->saddr;
    uint32_t ip_dst = header->daddr;
    unsigned ihl = header->ihl;
    unsigned version = header->version;

    if (header->version == 4) {
        inet_ntop(AF_INET, &ip_src, ip_source, 32);
        inet_ntop(AF_INET, &ip_dst, ip_dest, 32);
    }

    fprintf(stdout, "source @ = %s\n", ip_source);
    fprintf(stdout, "dest @ = %s\n", ip_dest);
    fprintf(stdout, "version = %d\n", version);
    fprintf(stdout, "IHL = %d\n", ihl);
    return sizeof(struct iphdr);
}
