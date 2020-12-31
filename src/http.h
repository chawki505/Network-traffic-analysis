#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
HTTP request methode enum
*/
enum Http_Request_Methods {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, UNSUPPORTED_METHODE
};

/*
HTTP version enum
*/
enum Http_Resonse_Version {
    HTTP09, HTTP10, HTTP11, UNSUPPORTED_VERSION
};

/*
HTTP header structure
*/
struct Http_Header {
    char *name;
    char *value;
    struct Http_Header *next;
};

/*
HTTP request structure
*/
struct Http_Request {
    char *method;
    char *url;
    char *version;
    struct Http_Header *headers;
    char *body;
};

/*
HTTP response structure
*/
struct Http_Response {
    char *version;
    char *status_code;
    char *status_text;
    struct Http_Header *headers;
    char *body;
};

/*
HTTP parser for request data
*/
struct Http_Request *http_parse_request(char *data, size_t length);

/*
HTTP parser for response data
*/
struct Http_Response *http_parse_response(char *data, size_t length);

/*
HTTP free for header memory
*/
void http_free_header(struct Http_Header *header);

/*
HTTP free for request memory
*/
void http_free_request(struct Http_Request *request);

/*
HTTP free for response memory
*/
void http_free_response(struct Http_Response *response);

#endif //_HTTP_H
