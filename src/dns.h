#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define DNS_NAME_MAXSIZE 256

/*
DNS header structure
*/
struct dnsheader {
    uint16_t query_id;
    uint16_t flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t AUTHCOUNT;
    uint16_t ADDCOUNT;
};

/*
Request/Query structure from a client to a server.
*/
struct dns_query {
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
};

/*
Response structure from a server to client containing a copy of  the question answered.
*/
struct dns_response {
    struct dns_query *query;
    char *aname;
    uint16_t atype;
    uint16_t aclass;
    uint32_t ttl;
    uint16_t data_length;
    u_char *data;
};

/*
Parse the DNS packet and return the QUERY field.
*/
struct dns_query *dns_get_query(u_char *data, unsigned int dataLength);

/*
Parse the DNS packet and return the ANSWER field.
*/
struct dns_response *dns_get_answer(u_char *data, unsigned int dataLength);

/*
Check if the type of the packet is a Query or Answer.
Returns 1 if RESPONSE and 0 if QUERY
*/
int dns_get_type(u_char *data);

/*
Print functions for the above structures.
*/
void dns_print_query(struct dns_query *q);

void dns_print_header(u_char *data);

void dns_print_answer(struct dns_response *a);

#endif