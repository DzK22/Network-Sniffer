#include "../headers/ip.h"

uint8_t treat_ipv4(const unsigned char *packet, int level, int *to_add, int *dataLen) {
    (void)level;
    char ip_source[LEN], ip_dest[LEN]/*, str_version[LEN], str_ihl[LEN]*/;
    int res;
    const struct ip *ip = (struct ip *)packet;
    struct in_addr src, dst;
    *to_add = ip->ip_hl*4;
    *dataLen = ntohs(ip->ip_len);
    src = ip->ip_src;
    dst = ip->ip_dst;
    res = snprintf(ip_source, LEN, "%s", inet_ntoa(src));
    if (test_snprintf(res, LEN) == EXIT_FAILURE)
        return 0;
    res = snprintf(ip_dest, LEN, "%s", inet_ntoa(dst));
    if (test_snprintf(res, LEN) == EXIT_FAILURE)
        return 0;

    fprintf(stdout, PINK"\t@ip src : %s\n"COL_RESET, ip_source);
    fprintf(stdout, GREEN"\t@ip dest : %s\n"COL_RESET, ip_dest);
    int reserved, dontfrag, morefrag, foffset;
    uint16_t flags = ntohs(ip->ip_off);
    uint8_t protocol = ip->ip_p;
    reserved = (flags & IP_RF) ? 1 : 0;
    dontfrag = (flags & IP_DF) ? 1 : 0;
    morefrag = (flags & IP_MF) ? 1 : 0;
    foffset = flags & IP_OFFMASK;
    flags = flags >> 13;
    fprintf(stdout, "\tIHL : %d (%d bytes)\n", *to_add/4, *to_add);
    fprintf(stdout, "\tToS : 0x%02x\n", ip->ip_tos);
    fprintf(stdout, "\tFlags : 0x%02x\n", flags);
    fprintf(stdout, "\t\t- Reserved bit : %d\n", reserved);
    fprintf(stdout, "\t\t- Don't Fragment : %d\n", dontfrag);
    fprintf(stdout, "\t\t- More Fragments : %d\n", morefrag);
    fprintf(stdout, "\tFragment Offset : %d\n", foffset);
    fprintf(stdout, "\tttl : %d \n", ip->ip_ttl);
    fprintf(stdout, "\tProtocol : %s (%d) \n", get_protocol(protocol), protocol);
    fprintf(stdout, "\tChecksum : 0x%04x\n", ntohs(ip->ip_sum));

    return protocol;
}

uint8_t treat_ipv6(const unsigned char *packet, int level) {
    (void)level;
    struct ip6_hdr *ip6 = (struct ip6_hdr *) packet;
    char str_ip_src[LEN], str_ip_dst[LEN];
    struct in6_addr src = ip6->ip6_src;
    struct in6_addr dst = ip6->ip6_dst;
    uint8_t next_header = ip6->ip6_nxt;
    if (inet_ntop(AF_INET6, &src, str_ip_src, LEN) == NULL) {
        fprintf(stdout, "inet_ntop error\n");
        return -1;
    }
    if (inet_ntop(AF_INET6, &dst, str_ip_dst, LEN) == NULL) {
        fprintf(stdout, "inet_ntop error\n");
        return -1;
    }
    fprintf(stdout, "\tPayload Length: %d\n", ntohs(ip6->ip6_plen));
    fprintf(stdout, "\tNext Header: %s (%d)\n", get_protocol(next_header), next_header);
    fprintf(stdout, "\tHop Limit: %d\n", ip6->ip6_hlim);
    fprintf(stdout, "\t@ip src = %s\n", str_ip_src);
    fprintf(stdout, "\t@ip dst = %s\n", str_ip_dst);
    return next_header;
}

char* get_protocol(int id) {
  char* protocol_name;
  switch (id) {
    case TCP:
      protocol_name = "TCP";
      break;
    case UDP:
      protocol_name = "UDP";
      break;
     case OSPF:
        protocol_name = "OSPF IGP";
        break;
    case ICMP:
      protocol_name = "ICMP";
      break;
    default:
      protocol_name = "Unknown";
      break;
  }
  return protocol_name;
}
