#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>


enum Http_Request_Methods {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, UNSUPPORTED
};

enum Http_Resonse_Version {
    HTTP09, HTTP10, HTTP11, HTTP20, UNSUPPORTED_VERSION
};

struct Http_Header {
    char *name;
    char *value;
    struct Http_Header *next;
};

struct Http_Request {
    char *method;
    char *url;
    char *version;
    struct Http_Header *headers;
    char *body;
};

struct Http_Response {
    char *version;
    char *status_code;
    char *status_text;
    struct Http_Header *headers;
    char *body;
};

struct Http_Request *http_parse_request(char *data, size_t length);

struct Http_Response *http_parse_response(char *data, size_t length);

void http_free_header(struct Http_Header *header);

void http_free_request(struct Http_Request *request);

void http_free_response(struct Http_Response *response);

#endif //_HTTP_H
