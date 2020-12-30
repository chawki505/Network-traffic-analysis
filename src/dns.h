#ifndef DNS_H
#define DNS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define DNS_NAME_MAXSIZE 256


struct dnsheader {
	uint16_t query_id;
	uint16_t flags;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t AUTHCOUNT;
	uint16_t ADDCOUNT;
};

struct dns_query {
	char * qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct dns_response {
	struct dns_query * query;
	char * aname;
	uint16_t atype;
	uint16_t aclass;
	uint32_t ttl;
	uint16_t data_length;
	u_char * data;
};


struct dns_query * dns_get_question(u_char * data, unsigned int dataLength);
struct dns_response * dns_get_answer(u_char * data, unsigned int dataLength);
// returns 1 if RESPONSE and 0 if REQUEST
int dns_get_type(u_char * data);
void dns_print_question(struct dns_query * q);
void dns_print_header(u_char * data);
void dns_print_answer(struct dns_response * a);

#endif