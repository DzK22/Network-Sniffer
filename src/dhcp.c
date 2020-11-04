#include "../headers/dhcp.h"

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
        //Traiter DHCP
    }
    else
        fprintf(stdout, "\n");
}

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
