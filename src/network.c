#include "../headers/network.h"

char* get_protocol(int id) {
  char* name;
  switch (id) {
    case 6:
      name = "TCP";
      break;
    case 17:
      name = "UDP";
      break;
    case 1:
      name = "ICMP";
      break;
    default:
      name = "Unknown";
      break;
  }
  return name;
}

int threat_ipv4(const unsigned char *packet, int level, unsigned *next) {
    (void)level;
    char ip_source[LEN], ip_dest[LEN]/*, str_version[LEN], str_ihl[LEN]*/;
    int res;
    const struct ip *ip;
    ip = (struct ip *)packet;
    struct in_addr src, dst;
    unsigned ihl = ip->ip_hl;
    *next += ihl * 4;
    src = ip->ip_src;
    dst = ip->ip_dst;
    res = snprintf(ip_source, LEN, "%s", inet_ntoa(src));
    if (test_snprintf(res, LEN) == EXIT_FAILURE)
        return 0;
    res = snprintf(ip_dest, LEN, "%s", inet_ntoa(dst));
    if (test_snprintf(res, LEN) == EXIT_FAILURE)
        return 0;

    int reserved, dontfrag, morefrag, foffset;
    uint16_t flags = ntohs(ip->ip_off);
    reserved = (flags & IP_RF) ? 1 : 0;
    dontfrag = (flags & IP_DF) ? 1 : 0;
    morefrag = (flags & IP_MF) ? 1 : 0;
    foffset = flags & IP_OFFMASK;
    flags = flags >> 13;

    fprintf(stdout,
      "\tFlags : 0x%02x\n      \t- Reserved bit : %d\n      \t- Don't Fragment : %d\n      \t- More Fragments : %d\n\tFragment Offset : %d\n\tttl : %d \n\tProtocol : %s (%d) \n\tChecksum : %d\n",
      flags, reserved, dontfrag, morefrag, foffset, ip->ip_ttl, get_protocol(ip->ip_p),
      ip->ip_p, ip->ip_sum);

    return 1;
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
