//
// Created by chawki chouib on 30/12/2020.
//

#ifndef MINIPROJETDPI_HTTP_H
#define MINIPROJETDPI_HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>


typedef enum Method {
    UNSUPPORTED, GET, HEAD
} Method;
typedef struct Header {
    char *name;
    char *value;
    struct Header *next;
} Header;

typedef struct Request {
    enum Method method;
    char *url;
    char *version;
    struct Header *headers;
    char *body;
} Request;

struct Request *parse_request(const char *data);

void free_header(struct Header *header);

void free_request(struct Request *request);

#endif //MINIPROJETDPI_HTTP_H
