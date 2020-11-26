#ifndef OSPF_H
#define OSPF_H
#include "network.h"
#define AUTH_SIZE 8

#define HELLO 1
#define DBD 2
#define LSR 3
#define LSU 4
#define LSA 5

struct lsahdr {
    uint16_t age;
    uint8_t options;
    uint8_t type;
    union {
        struct in_addr id;
        struct {
            uint8_t otype;
            uint8_t oid[3];
	    } ofield;
    } lsa_id;
    struct in_addr router;
    uint32_t seq;
    uint16_t checksum;
    uint16_t len;
};

struct ospfhdr {
    u_int8_t version;
    u_int8_t type;
    u_int16_t len;
    struct in_addr rid;
    struct in_addr aid;
    u_int16_t checksum;
    u_int16_t auth;
    u_int8_t datas[AUTH_SIZE];
    union {
        //Hello Packet
        struct {
            struct in_addr nmask;
            u_int16_t interval;
            u_int8_t options;
            u_int8_t priority;
            u_int32_t dead_interval;
            struct in_addr dr;
            struct in_addr bdr;
            struct in_addr neighbor[1];
        } hello_packet;
        //DB Packet
        struct {
            u_int16_t mtu;
            u_int8_t options;
            u_int8_t flags;
            u_int32_t seq;
            struct lsahdr dblsa[1];
        } db_packet;
        //LS request
        struct lsr {
            u_int8_t type[4];
            union {
                struct in_addr sid;
                struct {
                    u_int8_t otype;
                    u_int8_t oid;
                } ofield;
            } stateid;
            struct in_addr ls_router;
        } lsr_packet[1];
        //Link State Update
        struct {
            u_int32_t count;
            struct lsahdr lsu_lsa[1];
        } lsu_packet;
        //Link State Ack
        struct {
            struct lsahdr lshdr[1];
        } lsa_packet;
    } ospf_union;
};

char *get_ptype (int);

#endif
