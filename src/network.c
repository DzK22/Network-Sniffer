#include "../headers/network.h"

int threat_ipv4(const unsigned char *packet, int level, unsigned *next) {
    (void)level;
    char ip_source[LEN], ip_dest[LEN], str_version[LEN], str_ihl[LEN];
    int res;
    struct iphdr *header = (struct iphdr *) packet;
    uint32_t ip_src = header->saddr;
    uint32_t ip_dst = header->daddr;
    unsigned ihl = header->ihl;
    unsigned version = header->version;
    //header->protocol pour le protocol
    inet_ntop(AF_INET, &ip_src, ip_source, 32);
    inet_ntop(AF_INET, &ip_dst, ip_dest, 32);

    res = snprintf(str_ihl, LEN, "%#x", ihl);
    if (test_snprintf(res, LEN) == EXIT_FAILURE)
        return 0;

    snprintf(str_version, LEN, "%#x", version);
    if (test_snprintf(res, LEN) == EXIT_FAILURE)
        return 0;
    fprintf(stdout, "source @ = %s\n", ip_source);
    fprintf(stdout, "dest @ = %s\n", ip_dest);
    fprintf(stdout, "version = %s\n", str_version);
    fprintf(stdout, "IHL = %s\n", str_ihl);
    *next += ihl * 4;

    return version;
}

int threat_ipv6(const unsigned char *packet, int level, unsigned *next) {
    (void)level;
    struct ip6_hdrctl *header = (struct ip6_hdrctl *) packet;
    char str_ip_src[LEN], str_ip_dst[LEN], str_next_header[LEN];
    (void)str_ip_dst;
    (void)str_ip_src;
    int res;
    (void)res;
    uint8_t next_header = header->ip6_un1_nxt;
    (void)next_header;
    (void)str_next_header;
    *next += IPV6_LENGTH;
    return 1;
}
