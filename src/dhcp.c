#include "../headers/dhcp.h"

/*
 * Function: treat_bootp
 * ----------------------------
 *   Fonction qui gère l'en-tête bootp
 *
 *   packet: la partie du paquet correspondante à l'en-tête bootp
 *   level: niveau de verbosité
 *
 *   returns: void
 */
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
            fprintf(stdout, CYAN"          └─ BOOTP Message\n"COL_RESET);
            if (opcode == BOOTREPLY)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Message type: Reply (%d)\n", opcode);
            else
                fprintf(stdout, CYAN"            ├─"COL_RESET" Message type: Request (%d)\n", opcode);
            switch (htype) {
                case 1:
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Hardware type: Ethernet (0x%02x)\n", htype);
                    break;

                case 2:
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Hardware type: Experimental Ethernet (0x%02x)\n", htype);
                    break;

                default:
                    fprintf(stdout, CYAN"            ├─"COL_RESET" Hardware type: Unknown (0x%02x)\n", htype);
                    break;
            }
            fprintf(stdout, CYAN"            ├─"COL_RESET" Hardware address length: %d\n", hlen);
            fprintf(stdout, CYAN"            ├─"COL_RESET" Hops: %d\n", hops);
            fprintf(stdout, CYAN"            ├─"COL_RESET" Transaction ID: 0x%08x\n", xID);
            fprintf(stdout, CYAN"            ├─"COL_RESET" Seconds elapsed: %d\n", secs);
            fprintf(stdout, CYAN"            ├─"COL_RESET" Bootp flags: 0x%04x\n", flags);
            fprintf(stdout, CYAN"            ├─"COL_RESET" Client IP address: %s\n", inet_ntoa(cip));
            fprintf(stdout, CYAN"            ├─"COL_RESET" Your (client) IP address: %s\n", inet_ntoa(yip));
            fprintf(stdout, CYAN"            ├─"COL_RESET" Next server IP address: %s\n", inet_ntoa(sip));
            fprintf(stdout, CYAN"            ├─"COL_RESET" Relay agent IP address: %s\n", inet_ntoa(gip));
            fprintf(stdout, CYAN"            ├─"COL_RESET" Client MAC address: %s\n", chaddr);
            if (strcmp(sname, "None") == 0)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Server host name not given\n");
            else
                fprintf(stdout, CYAN"            ├─"COL_RESET" Server host name: %s\n", sname);
            if (strcmp(file, "None") == 0)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Boot file name not given\n");
            else
                fprintf(stdout, CYAN"            ├─"COL_RESET" Boot file name: %s\n", file);

            if (is_dhcp == 0)
                fprintf(stdout, CYAN"            ├─"COL_RESET" Vendor Spec: ");
            else
                fprintf(stdout, CYAN"            └─"COL_RESET" Vendor Spec: ");
            unsigned i;
            for (i = 0; i < 4; i++)
                fprintf(stdout, "%d ", bootp->bp_vend[i]);
            fprintf(stdout, "\n");

            if (is_dhcp == 0) {
                fprintf(stdout, CYAN"            ├─"COL_RESET" Magic cookie: DHCP\n");
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

/*
 * Function: print_dhcp
 * ----------------------------
 *   Fonction qui gère la partie vendor specific de bootp (DHCP)
 *
 *   packet: la partie du paquet correspondante à l'en-tête bootp
 *   level: niveau de verbosité
 *
 *   returns: void
 */
void print_dhcp (const unsigned char *packet, int level) {
    switch (level) {
        case V1:
            fprintf(stdout, "|| DHCP\n");
            return;

        case V2:
            fprintf(stdout, CYAN"$> DHCP: "COL_RESET);
            break;

        case V3:
            fprintf(stdout, CYAN"            ├─"COL_RESET" DHCP:\n");
            break;
    }
    u_int8_t cpt, len, option, msg;
    u_int32_t time;
    char str_ip[LEN];
    struct in_addr *ip;
    u_int8_t *pvendor = (u_int8_t *)packet;
    while (1) {
        option = *pvendor++;
        len = *pvendor++;
        if (option != 0) {
            switch (level) {
                case V1:
                    break;

                case V2:
                    break;

                case V3:
                    if (option == TAG_END)
                        fprintf(stdout, CYAN"            └─"COL_RESET"\t\tOption (len %d): ", len);
                    else
                        fprintf(stdout, CYAN"            ├"COL_RESET" \t\tOption (len %d): ", len);
                    break;
            }
            switch (option) {
                case TAG_PAD:
                    break;

                case TAG_REBIND_TIME:
                    time = ntohl((*(u_int32_t *)pvendor));
                    fprintf(stdout, "Rebind time value: ");
                    fprintf(stdout, "%d secs", time);
                    break;

                case TAG_END:
                    fprintf(stdout, "End\n");
                    return;

                case TAG_DHCP_MESSAGE:
                    msg = *pvendor;
                    fprintf(stdout, "DHCP Message type: ");
                    fprintf(stdout, "%s", get_dhcp_type(msg));
                    break;

                case TAG_RENEWAL_TIME:
                    time = ntohl((*(u_int32_t *)pvendor));
                    fprintf(stdout, "Renewal time value: ");
                    fprintf(stdout, "%d secs", time);
                    break;

                case TAG_IP_LEASE:
                    time = ntohl((*(u_int32_t *)pvendor));
                    fprintf(stdout, "IP Address Lease Time: ");
                    fprintf(stdout, "%d secs", time);
                    break;

                case TAG_CLIENT_ID:
                    fprintf(stdout, "Client identifier ");
                    //Si le type est ethernet alors c'est une @MAC
                    if (*pvendor == 0x01) {
                        struct ether_addr *mac = (struct ether_addr *)(pvendor + 1);
                        fprintf(stdout, "%s", ether_ntoa(mac));
                    }
                    else
                        fprintf(stdout, "Unknown\n");
                    break;

                case TAG_REQUESTED_IP:
                    ip = (struct in_addr *)pvendor;
                    if (inet_ntop(AF_INET, ip, str_ip, LEN) == NULL) {
                        fprintf(stderr, "inet_ntop\n");
                        return;
                    }
                    fprintf(stdout, "Requested IP Address: %s", str_ip);
                    break;

                case TAG_SERVER_ID:
                    ip = (struct in_addr *)pvendor;
                    if (inet_ntop(AF_INET, ip, str_ip, LEN) == NULL) {
                        fprintf(stderr, "inet_ntop\n");
                        return;
                    }
                    fprintf(stdout, "DHCP Server ID: %s", str_ip);
                    break;

                case TAG_SUBNET_MASK:
                    ip = (struct in_addr *)pvendor;
                    if (inet_ntop(AF_INET, ip, str_ip, LEN) == NULL) {
                        fprintf(stderr, "inet_ntop\n");
                        return;
                    }
                    fprintf(stdout, "Subnet Mask: %s", str_ip);
                    break;

                case TAG_PARM_REQUEST:
                    fprintf(stdout, "Parameter Request List Item: { ");
                    for (cpt = 0; cpt < len; cpt++) {
                        int param = pvendor[cpt + 2];
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
                                fprintf(stdout, "(%d) Unknown", param);
                                break;
                        }
                        if (cpt != len - 1)
                            fprintf(stdout, ", ");
                    }
                    fprintf(stdout, " }");
                    break;
                default:
                    fprintf(stdout, "Unknown (%d)", option);
                    break;
            }
        }
        if (level == V3)
            fprintf(stdout, "\n");
        else //Ici on a pas de verbose 1
            fprintf(stdout, ", ");
        pvendor += len;
    }
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
