#include "../headers/dhcp.h"

//Fonction qui gère bootp
void treat_bootp (const unsigned char *packet, int level) {
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
    u_int8_t magic_cookie[4] = VM_RFC1048;
    char *chaddr = ether_ntoa((struct ether_addr *)bootp->bp_chaddr);
    char *sname = *bootp->bp_sname ? ether_ntoa((struct ether_addr *)bootp->bp_sname) : "None";
    char *file = *bootp->bp_file ? ether_ntoa((struct ether_addr *)bootp->bp_file) : "None";
    int is_dhcp = memcmp(bootp->bp_vend, magic_cookie, 4);
    switch (level) {
        case V3:
            fprintf(stdout, "          └─ BOOTP Message\n");
            if (opcode == BOOTREPLY)
                fprintf(stdout, "            ├─ Message type: Reply (%d)\n", opcode);
            else
                fprintf(stdout, "            ├─ Message type: Request (%d)\n", opcode);
            switch (htype) {
                case 1:
                    fprintf(stdout, "            ├─ Hardware type: Ethernet (0x%02x)\n", htype);
                    break;

                case 2:
                    fprintf(stdout, "            ├─ Hardware type: Experimental Ethernet (0x%02x)\n", htype);
                    break;

                default:
                    fprintf(stdout, "            ├─ Hardware type: Unknown (0x%02x)\n", htype);
                    break;
            }
            fprintf(stdout, "            ├─ Hardware address length: %d\n", hlen);
            fprintf(stdout, "            ├─ Hops: %d\n", hops);
            fprintf(stdout, "            ├─ Transaction ID: 0x%08x\n", xID);
            fprintf(stdout, "            ├─ Seconds elapsed: %d\n", secs);
            fprintf(stdout, "            ├─ Bootp flags: 0x%04x\n", flags);
            fprintf(stdout, "            ├─ Client IP address: %s\n", inet_ntoa(cip));
            fprintf(stdout, "            ├─ Your (client) IP address: %s\n", inet_ntoa(yip));
            fprintf(stdout, "            ├─ Next server IP address: %s\n", inet_ntoa(sip));
            fprintf(stdout, "            ├─ Relay agent IP address: %s\n", inet_ntoa(gip));
            fprintf(stdout, "            ├─ Client MAC address: %s\n", chaddr);
            if (strcmp(sname, "None") == 0)
                fprintf(stdout, "            ├─ Server host name not given\n");
            else
                fprintf(stdout, "            ├─ Server host name: %s\n", sname);
            if (strcmp(file, "None") == 0)
                fprintf(stdout, "            ├─ Boot file name not given\n");
            else
                fprintf(stdout, "            ├─ Boot file name: %s\n", file);

            if (is_dhcp == 0)
                fprintf(stdout, "            ├─ Vendor Spec: ");
            else
                fprintf(stdout, "            └─ Vendor Spec: ");
            unsigned i;
            for (i = 0; i < 4; i++)
                fprintf(stdout, "%d ", bootp->bp_vend[i]);
            fprintf(stdout, "\n");

            if (is_dhcp == 0) {
                fprintf(stdout, "            ├─ Magic cookie: DHCP\n");
                print_dhcp(bootp->bp_vend + 4, level);
            }
            else
                fprintf(stdout, "\n");
            break;

        //Si Verbose 1 et 2 on affiche uniquement les options DHCP si DHCP présent
        default:
            if (is_dhcp == 0)
                print_dhcp(bootp->bp_vend + 4, level);
            break;

    }
}

void print_dhcp (const unsigned char *packet, int level) {
    switch (level) {
        case V1:
            fprintf(stdout, "|| DHCP\n");
            return;

        case V2:
            fprintf(stdout, "$> DHCP: ");
            break;

        case V3:
            fprintf(stdout, "            ├─ DHCP:\n");
            break;
    }

    unsigned i = 0;
    int cpt, len;
    u_int32_t time;
    char str_ip[LEN];
    struct in_addr *ip;
    //Le magic cookie a déjà été traité on prend donc les 60 octets suivant de Vendor spec
    do {
        if (level == V3) {
            if ((int)packet[i] == TAG_END || (int)packet[i] == TAG_PARM_REQUEST)
                fprintf(stdout, "            └─\t\tOption: ");
            else
                fprintf(stdout, "            ├ \t\tOption: ");
        }
        switch ((int)packet[i]) {
            case TAG_DHCP_MESSAGE:
                fprintf(stdout, "DHCP Message type: ");
                len = (int)packet[i + 1];
                i += 2;
                fprintf(stdout, "%s", get_dhcp_type((int)packet[i]));
                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_RENEWAL_TIME:
                fprintf(stdout, "Renewal time value: ");
                len = (int)packet[i + 1];
                i += 2;
                time = get_time(packet, i);
                fprintf(stdout, "%d secs", time);
                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_REBIND_TIME:
                fprintf(stdout, "Rebind time value: ");
                len = (int)packet[i + 1];
                i += 2;
                time = get_time(packet, i);
                fprintf(stdout, "%d secs", time);
                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_IP_LEASE:
                fprintf(stdout, "IP Address Lease Time: ");
                len = (int)packet[i + 1];
                i += 2;
                time = get_time(packet, i);
                fprintf(stdout, "%d secs", time);
                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_SUBNET_MASK:
                fprintf(stdout, "Subnet Mask: ");
                len = (int)packet[i + 1];
                i += 2;

                ip = (struct in_addr *) (packet + i);
                if (inet_ntop(AF_INET, ip, str_ip, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop\n");
                    return;
                }
                fprintf(stdout, "%s", str_ip);

                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_SERVER_ID:
                fprintf(stdout, "DHCP Server ID: ");
                len = (int)packet[i + 1];
                i += 2;

                ip = (struct in_addr *) (packet + i);
                if (inet_ntop(AF_INET, ip, str_ip, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop\n");
                    return;
                }
                fprintf(stdout, "%s", str_ip);

                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_REQUESTED_IP:
                fprintf(stdout, "Requested IP Address: ");
                len = (int)packet[i + 1];
                i += 2;

                ip = (struct in_addr *) (packet + i);
                if (inet_ntop(AF_INET, ip, str_ip, LEN) == NULL) {
                    fprintf(stderr, "inet_ntop\n");
                    return;
                }
                fprintf(stdout, "%s", str_ip);

                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            case TAG_PARM_REQUEST:
                if (level == V3)
                    fprintf(stdout, "Parameter Request List [");
                if (level == V2)
                    fprintf(stdout, "Parameter Request List Item: { ");
                len = (int)packet[i + 1];
                for (cpt = 0; cpt < len; cpt++) {
                    int param = packet[i + cpt + 2];
                    switch (param) {
                        case TAG_SUBNET_MASK:
                            fprintf(stdout, "(%d) Subnet Mask", param);
                            break;
                        case TAG_GATEWAY:
                            fprintf(stdout, "(%d) Router", param);
                            break;
                        case TAG_DOMAIN_SERVER:
                            fprintf(stdout, "(%d) Domain Name Server", param);
                            break;
                        case TAG_NTP_SERVERS:
                            fprintf(stdout, "(%d) Network Time Protocol Servers", param);

                            break;
                        default:
                            if (level == V3)
                                fprintf(stdout, "(%d) Unknown", param);
                            break;
                    }
                    if (cpt != len - 1)
                        fprintf(stdout, ", ");
                }
                if (level == V2)
                    fprintf(stdout, " }\n");
                i += (int)packet[i];
                if (level == V3)
                    fprintf(stdout, "]\n");
                else if (i < 60)
                    fprintf(stdout, ", ");
                break;

            case TAG_END:
                if (level == V3)
                    fprintf(stdout, "End");
                fprintf(stdout, "\n");
                return;

            case TAG_CLIENT_ID:
                fprintf(stdout, "Client identifier ");
                len = (int)packet[i + 1];
                i += 2;
                //Si le type est ethernet alors c'est une @MAC
                if ((int)packet[i] == 0x01) {
                    struct ether_addr *mac = (struct ether_addr *)(packet + 6);
                    fprintf(stdout, "%s", ether_ntoa(mac));
                }
                else
                    fprintf(stdout, "Unknown\n");
                i += len;
                if (level == V3)
                    fprintf(stdout, "\n");
                else if ((int)packet[i] != TAG_END)
                    fprintf(stdout, ", ");
                break;

            default:
                return;
        }
    } while (i < 60);
}

u_int32_t get_time (const unsigned char *packet, int i) {
    return packet[i] << 24 | packet[i + 1] << 16 | packet[i + 2] << 8 | packet[i + 3];
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
