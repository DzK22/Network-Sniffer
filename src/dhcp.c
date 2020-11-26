#include "../headers/dhcp.h"

//Fonction qui gère bootp
void treat_bootp (const unsigned char *packet, int level) {
    (void)level;
    struct bootp *bootp = (struct bootp *)packet;
    u_int8_t opcode, htype, hlen, hops;
    u_int32_t xID;
    u_int16_t secs, flags;
    opcode = bootp->bp_op;
    htype = bootp->bp_htype;
    hlen = bootp->bp_hlen;
    hops = bootp->bp_hops;
    xID = ntohl(bootp->bp_xid);
    secs = ntohs(bootp->bp_secs);
    flags = ntohs(bootp->bp_flags);
    struct in_addr cip, yip, sip, gip;
    cip = bootp->bp_ciaddr;
    yip = bootp->bp_yiaddr;
    sip = bootp->bp_siaddr;
    gip = bootp->bp_giaddr;
    char *chaddr = ether_ntoa((struct ether_addr *)bootp->bp_chaddr);
    char *sname = *bootp->bp_sname ? ether_ntoa((struct ether_addr *)bootp->bp_sname) : "None";
    char *file = *bootp->bp_file ? ether_ntoa((struct ether_addr *)bootp->bp_file) : "None";
    //Utile pour inet_ntop plus tard
    //char str_cip[LEN], str_yip[LEN], str_sip[LEN], str_gip[LEN];
    if (opcode == BOOTREPLY)
        fprintf(stdout, "\tMessage type: Reply (%d)\n", opcode);
    else
        fprintf(stdout, "\tMessage type: Request (%d)\n", opcode);
    switch (htype) {
        case 1:
            fprintf(stdout, "\tHardware type: Ethernet (0x%02x)\n", htype);
            break;
        case 2:
            fprintf(stdout, "\tHardware type: Experimental Ethernet (0x%02x)\n", htype);
            break;
        default:
            fprintf(stdout, "\tHardware type: Unknown (0x%02x)\n", htype);
            break;
    }
    fprintf(stdout, "\tHardware address length: %d\n", hlen);
    fprintf(stdout, "\tHops: %d\n", hops);
    fprintf(stdout, "\tTransaction ID: 0x%08x\n", xID);
    fprintf(stdout, "\tSeconds elapsed: %d\n", secs);
    fprintf(stdout, "\tBootp flags: 0x%04x\n", flags);
    fprintf(stdout, "\tClient IP address: %s\n", inet_ntoa(cip));
    fprintf(stdout, "\tYour (client) IP address: %s\n", inet_ntoa(yip));
    fprintf(stdout, "\tNext server IP address: %s\n", inet_ntoa(sip));
    fprintf(stdout, "\tRelay agent IP address: %s\n", inet_ntoa(gip));
    fprintf(stdout, "\tClient MAC address: %s\n", chaddr);
    if (strcmp(sname, "None") == 0)
        fprintf(stdout, "\tServer host name not given\n");
    else
        fprintf(stdout, "\tServer host name: %s\n", sname);
    if (strcmp(file, "None") == 0)
        fprintf(stdout, "\tBoot file name not given\n");
    else
        fprintf(stdout, "\tBoot file name: %s\n", file);
    bool dhcp = is_dhcp(bootp->bp_vend);
    (void)dhcp;
    fprintf(stdout, "\tVendor Spec: ");
    unsigned i;
    for (i = 0; i < 4; i++)
        fprintf(stdout, "%d ", bootp->bp_vend[i]);
    fprintf(stdout, "\n");
    if (dhcp) {
        fprintf(stdout, "\tMagic cookie: DHCP\n");
        print_dhcp(bootp->bp_vend + 4, level);
    }
    else
        fprintf(stdout, "\n");
}

//Fonction qui check si bootp utilise l'option dhcp (à l'aide du magic cookie)
bool is_dhcp (const unsigned char *cookie) {
    bool ok = true;
    unsigned magic_cookie[4] = VM_RFC1048;
    unsigned i;
    for (i = 0; i < 4; i++) {
        if (magic_cookie[i] != cookie[i])
            ok = false;
    }
    return ok;
}

void print_dhcp (const unsigned char *packet, int level) {
    (void)level;
    fprintf(stdout, "\tDHCP:\n");
    unsigned i = 0;
    int cpt, len;
    u_int32_t time;
    int *ip;
    unsigned char *mac;
    //Le magic cookie a déjà été traité on prend donc les 60 octets suivant de Vendor spec
    do {
        fprintf(stdout, "\t\tOption: ");
        switch ((int)packet[i]) {
            case TAG_DHCP_MESSAGE:
                fprintf(stdout, "DHCP Message type: ");
                len = (int)packet[i + 1];
                i += 2;
                fprintf(stdout, "%s", get_dhcp_type((int)packet[i]));
                i += len;
                fprintf(stdout, "\n");
                break;

            case TAG_RENEWAL_TIME:
                fprintf(stdout, "Renewal time value: ");
                len = (int)packet[i + 1];
                i += 2;
                time = get_time(packet, i);
                fprintf(stdout, "%d secs\n", time);
                i += len;
                break;

            case TAG_REBIND_TIME:
                fprintf(stdout, "Rebind time value: ");
                len = (int)packet[i + 1];
                i += 2;
                time = get_time(packet, i);
                fprintf(stdout, "%d secs\n", time);
                i += len;
                break;

            case TAG_IP_LEASE:
                fprintf(stdout, "IP Address Lease Time: ");
                len = (int)packet[i + 1];
                i += 2;
                time = get_time(packet, i);
                fprintf(stdout, "%d secs\n", time);
                i += len;
                break;

            case TAG_SUBNET_MASK:
                fprintf(stdout, "Subnet Mask: ");
                len = (int)packet[i + 1];
                i += 2;
                ip = get_ip(packet, i);
                for (cpt = 0; cpt < 4; cpt++) {
                    if (cpt != 3)
                        fprintf(stdout, "%d.", ip[cpt]);
                    else
                        fprintf(stdout, "%d", ip[cpt]);
                }
                free(ip);
                i += len;
                fprintf(stdout, "\n");
                break;

            case TAG_SERVER_ID:
                fprintf(stdout, "DHCP Server ID: ");
                len = (int)packet[i + 1];
                i += 2;
                ip = get_ip(packet, i);
                for (cpt = 0; cpt < 4; cpt++) {
                    if (cpt != 3)
                        fprintf(stdout, "%d.", ip[cpt]);
                    else
                        fprintf(stdout, "%d", ip[cpt]);
                }
                free(ip);
                i += len;
                fprintf(stdout, "\n");
                break;

            case TAG_REQUESTED_IP:
                fprintf(stdout, "Requested IP Address: ");
                len = (int)packet[i + 1];
                i += 2;
                ip = get_ip(packet, i);
                for (cpt = 0; cpt < 4; cpt++) {
                    if (cpt != 3)
                        fprintf(stdout, "%d.", ip[cpt]);
                    else
                        fprintf(stdout, "%d", ip[cpt]);
                }
                free(ip);
                i += len;
                fprintf(stdout, "\n");
                break;

            case TAG_PARM_REQUEST:
                fprintf(stdout, "Parameter Request List\n");
                len = (int)packet[i + 1];
                for (cpt = 0; cpt < len; cpt++) {
                    fprintf(stdout, "\t\t\t- Parameter Request List Item: ");
                    int param = packet[i + cpt + 2];
                    switch (param) {
                        case TAG_SUBNET_MASK:
                            fprintf(stdout, "(%d) Subnet Mask\n", param);
                            break;
                        case TAG_GATEWAY:
                            fprintf(stdout, "(%d) Router\n", param);
                            break;
                        case TAG_DOMAIN_SERVER:
                            fprintf(stdout, "(%d) Domain Name Server\n", param);
                            break;
                        case TAG_NTP_SERVERS:
                            fprintf(stdout, "(%d) Network Time Protocol Servers\n", param);
                            break;
                        default:
                            fprintf(stdout, "(%d) Unknown\n", param);
                            break;
                    }
                }
                i += (int)packet[i];
                fprintf(stdout, "\n");
                break;

            case TAG_END:
                fprintf(stdout, "End\n");
                return;

            case TAG_CLIENT_ID:
                fprintf(stdout, "Client identifier ");
                len = (int)packet[i + 1];
                i += 2;
                //Si le type est ethernet alors c'est une @MAC
                if ((int)packet[i] == 0x01) {
                    mac = get_mac(packet, i);
                    for (cpt = 0; cpt < 6; cpt++) {
                        if (cpt != 5)
                            fprintf(stdout, "%02x:", mac[cpt]);
                        else
                            fprintf(stdout, "%02x", mac[cpt]);
                    }
                    free(mac);
                    fprintf(stdout, "\n");
                }
                else
                    fprintf(stdout, "Unknown\n");
                i += len;
                break;
            default:
                return;
        }
    } while (i < 60);
}

u_int32_t get_time (const unsigned char *packet, int i) {
    return packet[i] << 24 | packet[i + 1] << 16 | packet[i + 2] << 8 | packet[i + 3];
}

int *get_ip (const unsigned char *packet, int i) {
    int *ip = malloc(sizeof(int) * 4);
    if (ip == NULL) {
        fprintf(stderr, "malloc error\n");
        return NULL;
    }
    ip[0] = packet[i];
    ip[1] = packet[i + 1];
    ip[2] = packet[i + 2];
    ip[3] = packet[i + 3];
    return ip;
}

unsigned char *get_mac (const unsigned char *packet, int i) {
    unsigned char *mac = malloc(sizeof(unsigned char) * 6);
    if (mac == NULL) {
        fprintf(stderr, "malloc error\n");
        return NULL;
    }
    mac[0] = packet[i + 1];
    mac[1] = packet[i + 2];
    mac[2] = packet[i + 3];
    mac[3] = packet[i + 4];
    mac[4] = packet[i + 5];
    mac[5] = packet[i + 6];
    return mac;
}

void put_dhcp_options (int option) {
    char *dhcp_type = NULL;
    switch (option) {
        case TAG_DHCP_MESSAGE:
            fprintf(stdout, "\t\tDHCP Message Type\t");
            dhcp_type = get_dhcp_type(option);
            break;
        case TAG_RENEWAL_TIME:
            fprintf(stdout, "\t\tRenewal Time Value\t");
            break;
        case TAG_IP_LEASE:
            fprintf(stdout, "\t\tIP Address Lease Time\t");
            break;
        case TAG_SERVER_ID:
            fprintf(stdout, "\t\tDHCP Server Identifier\t");
            break;
        case TAG_SUBNET_MASK:
            fprintf(stdout, "\t\tSubnet Mask\t\t");
            break;
        case TAG_REBIND_TIME:
            fprintf(stdout, "\t\tRebinding Time Value\t");
            break;
        default:
            fprintf(stdout, "\t\tUnknown\t");
            break;
    }
    if (dhcp_type != NULL)
        return;
    fprintf(stdout, "(%d) ", option);
}

char *get_dhcp_type (int type) {
    switch (type) {
        case DHCPDISCOVER:
            return "DISCOVER";
        case DHCPOFFER:
            return "OFFER";
        case DHCPREQUEST:
            return "REQUEST";
        case DHCPDECLINE:
            return "DECLINE";
        case DHCPACK:
            return "ACK";
        case DHCPNAK:
            return "NACK";
        case DHCPRELEASE:
            return "RELEASE";
        case DHCPINFORM:
            return "INFORM";
        default:
            return NULL;
    }
}
