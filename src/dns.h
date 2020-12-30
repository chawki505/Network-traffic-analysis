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


char * dns_get_question(u_char * data, unsigned int dataLength);
void dns_print_header(u_char * data);

#endif