#include "../headers/network.h"

void treat_network(const unsigned char *packet, int e_protocol, int *t_protocol, unsigned *to_add, int level) {
    int port = -1;
    switch(e_protocol) {
        case ETHERTYPE_IP:
            //appelez fonction IP
            fprintf(stdout, YELLOW"\tType = IPv4\n"COL_RESET);
            port = treat_ipv4(packet, level);
            *to_add = sizeof(struct ip);
            break;

        case ETHERTYPE_IPV6:
            fprintf(stdout, YELLOW"\tType = IPv6\n"COL_RESET);
            treat_ipv6(packet, level);
            *to_add = sizeof(struct ip6_hdr);
            break;

        case ETHERTYPE_ARP:
            fprintf(stdout, YELLOW"\tType = ARP\n"COL_RESET);
            treat_arp(packet, level);
            *to_add = sizeof(struct arphdr);
            break;

        default :
            fprintf(stdout, "UKNOWN TYPE\n");
            break;
    }
    fprintf(stdout, COL_RESET"\n");
    *t_protocol = port;
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
    case ICMP:
      protocol_name = "ICMP";
      break;
    default:
      protocol_name = "Unknown";
      break;
  }
  return protocol_name;
}

int treat_ipv4(const unsigned char *packet, int level) {
    (void)level;
    char ip_source[LEN], ip_dest[LEN]/*, str_version[LEN], str_ihl[LEN]*/;
    int res;
    const struct ip *ip;
    ip = (struct ip *)packet;
    struct in_addr src, dst;
    //unsigned ihl = ip->ip_hl;
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
    reserved = (flags & IP_RF) ? 1 : 0;
    dontfrag = (flags & IP_DF) ? 1 : 0;
    morefrag = (flags & IP_MF) ? 1 : 0;
    foffset = flags & IP_OFFMASK;
    flags = flags >> 13;

    fprintf(stdout, "\tFlags : 0x%02x\n", flags);
    fprintf(stdout, "\t\t- Reserved bit : %d\n", reserved);
    fprintf(stdout, "\t\t- Don't Fragment : %d\n", dontfrag);
    fprintf(stdout, "\t\t- More Fragments : %d\n", morefrag);
    fprintf(stdout, "\tFragment Offset : %d\n", foffset);
    fprintf(stdout, "\tttl : %d \n", ip->ip_ttl);
    fprintf(stdout, "\tProtocol : %s (%d) \n", get_protocol(ip->ip_p), ip->ip_p);
    fprintf(stdout, "\tChecksum : %d\n", ip->ip_sum);

    return ip->ip_p;
}

void treat_ipv6(const unsigned char *packet, int level) {
    (void)level;
    struct ip6_hdr *ip6 = (struct ip6_hdr *) packet;
    char str_ip_src[LEN], str_ip_dst[LEN];
    struct in6_addr src = ip6->ip6_src;
    struct in6_addr dst = ip6->ip6_dst;
    if (inet_ntop(AF_INET6, &src, str_ip_src, LEN) == NULL) {
        fprintf(stdout, "inet_ntop error\n");
        return;
    }
    if (inet_ntop(AF_INET6, &dst, str_ip_dst, LEN) == NULL) {
        fprintf(stdout, "inet_ntop error\n");
        return;
    }
    fprintf(stdout, "\t@ip src = %s\n", str_ip_src);
    fprintf(stdout, "\t@ip dst = %s\n", str_ip_dst);
}

void treat_arp(const unsigned char *packet, int level) {
    (void)level;
    struct arphdr *arp = (struct arphdr *)packet;
    ushort hardware = ntohs(arp->ar_hrd);
    ushort p_type = ntohs(arp->ar_pro);
    u_char h_size = arp->ar_hln;
    u_char protocol = arp->ar_pln;
    ushort op_code = ntohs(arp->ar_op);
    (void)h_size;
    (void)protocol;
    fprintf(stdout, "\tHardware Type : ");
    switch (hardware) {
        case ARPHRD_ETHER:
            fprintf(stdout, "Ethernet\n");
            break;

        case ARPHRD_EETHER:
            fprintf(stdout, "Experimental Ethernet\n");
            break;

        case ARPHRD_APPLETLK:
            fprintf(stdout, "Apple Talk\n");
            break;

        default:
            fprintf(stdout, "Unknown Hardware (%d)\n", hardware);
            break;
    }
    fprintf(stdout, "\tOpcode : ");
    put_arp_opcode(op_code);

    fprintf(stdout, "\tProtocole Type : ");
    switch (p_type) {
        case ETHERTYPE_IP:
            fprintf(stdout, "IPv4\n");
            break;

        case ETHERTYPE_PUP:
            fprintf(stdout, "PUP\n");
            break;

        default:
            fprintf(stdout, "Unknown protocol (%d)\n", p_type);
            break;
    }
    data_print(packet + sizeof(struct arphdr));
}

void put_arp_opcode (int opcode) {
    switch (opcode) {
        case ARPOP_REQUEST:
            fprintf(stdout, "ARP Request\n");
            break;

        case ARPOP_RREQUEST:
            fprintf(stdout, "RARP Request\n");
            break;

        case ARPOP_InREQUEST:
            fprintf(stdout, "InARP Request\n");
            break;

        case ARPOP_REPLY:
            fprintf(stdout, "ARP Reply\n");
            break;

        case ARPOP_RREPLY:
            fprintf(stdout, "RARP Reply\n");
            break;

        case ARPOP_InREPLY:
            fprintf(stdout, "InARP Reply\n");
            break;

        default:
            fprintf(stdout, "\t\tUnknown opcode (%d)\n", opcode);
            break;
    }
}
