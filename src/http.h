#ifndef MINIPROJETDPI_HTTP_H
#define MINIPROJETDPI_HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>


typedef enum Request_methods {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, UNSUPPORTED
} Request_methods;

typedef struct Request_header {
    char *name;
    char *value;
    struct Request_header *next;
} Request_header;

typedef struct Request {
    char *method;
    char *url;
    char *version;
    struct Request_header *headers;
    char *body;
} Request;

struct Request *parse_request(const char *data);

void free_header(struct Request_header *header);

void free_request(struct Request *request);

#endif //MINIPROJETDPI_HTTP_H
