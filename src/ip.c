#include "../headers/ip.h"

//Fonction qui gère une en-tête ipv4
uint8_t treat_ipv4(const unsigned char *packet, int level, int *to_add, int *dataLen) {
    char ip_source[LEN], ip_dest[LEN];
    const struct ip *ip = (struct ip *)packet;
    struct in_addr src, dst;
    *to_add = ip->ip_hl*4;
    *dataLen = ntohs(ip->ip_len);
    src = ip->ip_src;
    dst = ip->ip_dst;
    uint8_t protocol = ip->ip_p;
    if (inet_ntop(AF_INET, &src, ip_source, LEN) == NULL) {
        fprintf(stderr, "inet_ntop\n");
        return -1;
    }
    if (inet_ntop(AF_INET, &dst, ip_dest, LEN) == NULL) {
        fprintf(stderr, "inet_ntop\n");
        return -1;
    }
    switch (level) {
        case V1:
            fprintf(stdout, "|| [IPv4] %s => %s\t", ip_source, ip_dest);
            break;

        case V2:
            fprintf(stdout, "$> IPv4: @ip src: %s, @ip dst: %s\n", ip_source, ip_dest);
            break;

        case V3:
            fprintf(stdout, PINK"\t@ip src : %s\n"COL_RESET, ip_source);
            fprintf(stdout, GREEN"\t@ip dest : %s\n"COL_RESET, ip_dest);
            int reserved, dontfrag, morefrag, foffset;
            uint16_t flags = ntohs(ip->ip_off);
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
            break;
    }
    return protocol;
}

//Fonction qui gère une en-tête ipv6
uint8_t treat_ipv6(const unsigned char *packet, int level) {
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
    switch (level) {
        case V1:
            fprintf(stdout, "|| [IPv6] %s => %s\t", str_ip_src, str_ip_dst);
            break;

        case V2:
            fprintf(stdout, "$> IPv6: @ip src: %s, @ip dst: %s\n", str_ip_src, str_ip_dst);
            break;

        case V3:
            fprintf(stdout, "\tPayload Length: %d\n", ntohs(ip6->ip6_plen));
            fprintf(stdout, "\tNext Header: %s (%d)\n", get_protocol(next_header), next_header);
            fprintf(stdout, "\tHop Limit: %d\n", ip6->ip6_hlim);
            fprintf(stdout, "\t@ip src = %s\n", str_ip_src);
            fprintf(stdout, "\t@ip dst = %s\n", str_ip_dst);
            break;
    }
    return next_header;
}

//Fonction qui convertion le numéro de port en string pour l'affichage du nom du protocol correspondant à ce protocole
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
