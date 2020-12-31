
#include "http.h"

char *METHODS[9] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
                    "UNSUPPORTED"};


struct Request *parse_request(const char *raw) {
    struct Request *req = NULL;
    req = malloc(sizeof(*req));
    if (!req) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(req, 0, sizeof(*req));

    // Method
    size_t meth_len = strcspn(raw, " ");
    if (memcmp(raw, METHODS[GET], strlen("GET")) == 0) {
        req->method = METHODS[GET];
    } else if (memcmp(raw, METHODS[HEAD], strlen("HEAD")) == 0) {
        req->method = METHODS[HEAD];
    } else {
        req->method = METHODS[UNSUPPORTED];
    }

    raw += meth_len + 1; // move past <SP>

    // Request-URI
    size_t url_len = strcspn(raw, " ");
    req->url = malloc(url_len + 1);
    if (!req->url) {
        free_request(req);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }
    memset(req->url, 0, url_len + 1);
    memcpy(req->url, raw, url_len);
    req->url[url_len] = '\0';
    raw += url_len + 1; // move past <SP>

    // HTTP-Version
    size_t ver_len = strcspn(raw, "\r\n");
    req->version = malloc(ver_len + 1);
    if (!req->version) {
        free_request(req);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(req->version, 0, ver_len + 1);
    memcpy(req->version, raw, ver_len);
    req->version[ver_len] = '\0';
    raw += ver_len + 2; // move past <CR><LF>

    struct Request_header *header = NULL, *last = NULL;

    while (raw[0] != '\r' || raw[1] != '\n') {
        last = header;
        header = malloc(sizeof(*header));
        if (!header) {
            free_request(req);
            printf("Memory not allocated.\n");
            exit(EXIT_FAILURE);
        }

        // name
        size_t name_len = strcspn(raw, ":");
        header->name = malloc(name_len + 1);
        if (!header->name) {
            free_request(req);
            printf("Memory not allocated.\n");
            exit(EXIT_FAILURE);
        }

        memset(header->name, 0, name_len + 1);
        memcpy(header->name, raw, name_len);
        header->name[name_len] = '\0';
        raw += name_len + 1; // move past :
        while (*raw == ' ') {
            raw++;
        }

        // value
        size_t value_len = strcspn(raw, "\r\n");
        header->value = malloc(value_len + 1);
        if (!header->value) {
            free_request(req);
            printf("Memory not allocated.\n");
            exit(EXIT_FAILURE);
        }

        memset(header->value, 0, value_len + 1);
        memcpy(header->value, raw, value_len);
        header->value[value_len] = '\0';
        raw += value_len + 2; // move past <CR><LF>

        // next
        header->next = last;
    }

    req->headers = header;
    raw += 2; // move past <CR><LF>

    size_t body_len = strlen(raw);
    req->body = malloc(body_len + 1);
    if (!req->body) {
        free_request(req);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(req->body, 0, body_len + 1);
    memcpy(req->body, raw, body_len);
    req->body[body_len] = '\0';

    return req;
}


void free_header(struct Request_header *h) {
    if (h) {
        free(h->name);
        free(h->value);
        free_header(h->next);
        free(h);
    }
}


void free_request(struct Request *req) {
    free(req->url);
    free(req->version);
    free_header(req->headers);
    free(req->body);
    free(req);
}