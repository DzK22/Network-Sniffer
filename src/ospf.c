#include "../headers/ospf.h"

char *get_ptype (int type) {
    char *str_type = NULL;
    switch (type) {
        case HELLO:
            str_type = "Hello Packet";
            break;
        case DBD:
            str_type = "DB Description";
            break;
        case LSR:
            str_type = "LS Request";
            break;
        case LSU:
            str_type = "LS Update";
            break;
        case LSA:
            str_type = "LSA";
            break;
        default:
            str_type = "Unknown";
            break;
    }
    return str_type;
}
