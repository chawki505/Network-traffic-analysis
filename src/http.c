#include "http.h"

#define METHODS_LEN 9
char *METHODS[METHODS_LEN] = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "UNSUPPORTED"};
#define VERSION_LEN 5
char *VERSIONS[VERSION_LEN] = {"HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "UNSUPPORTED_VERSION"};


//parsing http request
struct Http_Request *http_parse_request(char *data, size_t length) {

    char *raw = malloc(length + 1);
    char *init_raw = raw;
    if (!raw) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(raw, 0, length + 1);
    memcpy(raw, data, length);

    struct Http_Request *req = NULL;
    req = malloc(sizeof(*req));
    if (!req) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(req, 0, sizeof(*req));

    // Method
    size_t meth_len = 0;
    for (size_t i = 0; i < 20; ++i) {
        meth_len = strcspn(raw, " ");
        if (memcmp(raw, METHODS[GET], strlen("GET")) == 0) {
            req->method = METHODS[GET];
            break;
        } else if (memcmp(raw, METHODS[HEAD], strlen("HEAD")) == 0) {
            req->method = METHODS[HEAD];
            break;

        } else if (memcmp(raw, METHODS[POST], strlen("POST")) == 0) {
            req->method = METHODS[POST];
            break;

        } else if (memcmp(raw, METHODS[PUT], strlen("PUT")) == 0) {
            req->method = METHODS[PUT];
            break;

        } else if (memcmp(raw, METHODS[DELETE], strlen("DELETE")) == 0) {
            req->method = METHODS[DELETE];
            break;

        } else if (memcmp(raw, METHODS[CONNECT], strlen("CONNECT")) == 0) {
            req->method = METHODS[CONNECT];
            break;

        } else if (memcmp(raw, METHODS[OPTIONS], strlen("OPTIONS")) == 0) {
            req->method = METHODS[OPTIONS];
            break;

        } else if (memcmp(raw, METHODS[TRACE], strlen("TRACE")) == 0) {
            req->method = METHODS[TRACE];
            break;

        } else {
            req->method = METHODS[UNSUPPORTED];
        }
        raw += 1;
    }

    if (memcmp(req->method, METHODS[UNSUPPORTED], strlen("UNSUPPORTED")) == 0) {
        http_free_request(req);
        return NULL;
    }

    raw += meth_len + 1; // move past <SP>

    // Request-URI
    size_t url_len = strcspn(raw, " ");
    req->url = malloc(url_len + 1);
    if (!req->url) {
        http_free_request(req);
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
        http_free_request(req);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(req->version, 0, ver_len + 1);
    memcpy(req->version, raw, ver_len);
    req->version[ver_len] = '\0';
    raw += ver_len + 2; // move past <CR><LF>

    struct Http_Header *header = NULL, *last = NULL;

    while (raw[0] != '\r' || raw[1] != '\n') {
        last = header;
        header = malloc(sizeof(*header));
        if (!header) {
            http_free_request(req);
            printf("Memory not allocated.\n");
            exit(EXIT_FAILURE);
        }

        // name
        size_t name_len = strcspn(raw, ":");
        header->name = malloc(name_len + 1);
        if (!header->name) {
            http_free_request(req);
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
            http_free_request(req);
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
        http_free_request(req);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(req->body, 0, body_len + 1);
    memcpy(req->body, raw, body_len);
    req->body[body_len] = '\0';
    free(init_raw);
    return req;
}


struct Http_Response *http_parse_response(char *data, size_t length) {

    char *raw = malloc(length + 1);
    char *init_raw = raw;
    if (!raw) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(raw, 0, length + 1);
    memcpy(raw, data, length);

    struct Http_Response *resp = NULL;
    resp = malloc(sizeof(*resp));
    if (!resp) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(resp, 0, sizeof(*resp));

    // Version HTTP
    size_t version_len = 0;
    for (size_t i = 0; i < 20; ++i) {
        version_len = strcspn(raw, " ");
        if (memcmp(raw, VERSIONS[HTTP09], strlen("HTTP/0.9")) == 0) {
            resp->version = VERSIONS[HTTP09];
            break;
        } else if (memcmp(raw, VERSIONS[HTTP10], strlen("HTTP/1.0")) == 0) {
            resp->version = VERSIONS[HTTP10];
            break;

        } else if (memcmp(raw, VERSIONS[HTTP11], strlen("HTTP/1.1")) == 0) {
            resp->version = VERSIONS[HTTP11];
            break;

        } else {
            resp->version = VERSIONS[UNSUPPORTED_VERSION];
        }
        raw += 1;
    }

    if (memcmp(resp->version, VERSIONS[UNSUPPORTED_VERSION], strlen("UNSUPPORTED_VERSION")) == 0) {
        http_free_response(resp);
        return NULL;
    }

    raw += version_len + 1; // move past <SP>

    // Status code
    size_t status_code_len = strcspn(raw, " ");
    resp->status_code = malloc(status_code_len + 1);
    if (!resp->status_code) {
        http_free_response(resp);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(resp->status_code, 0, status_code_len + 1);
    memcpy(resp->status_code, raw, status_code_len);
    resp->status_code[status_code_len] = '\0';
    raw += status_code_len + 1; // move past <SP>

    // Status text
    size_t status_text_len = strcspn(raw, "\r\n");
    resp->status_text = malloc(status_text_len + 1);
    if (!resp->status_text) {
        http_free_response(resp);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(resp->status_text, 0, status_text_len + 1);
    memcpy(resp->status_text, raw, status_text_len);
    resp->status_text[status_text_len] = '\0';
    raw += status_text_len + 2; // move past <CR><LF>

    struct Http_Header *header = NULL, *last = NULL;

    while (raw[0] != '\r' || raw[1] != '\n') {
        last = header;
        header = malloc(sizeof(*header));
        if (!header) {
            http_free_response(resp);
            printf("Memory not allocated.\n");
            exit(EXIT_FAILURE);
        }

        // name
        size_t name_len = strcspn(raw, ":");
        header->name = malloc(name_len + 1);
        if (!header->name) {
            http_free_response(resp);
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
            http_free_response(resp);
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

    resp->headers = header;
    raw += 2; // move past <CR><LF>

    size_t body_len = strlen(raw);
    resp->body = malloc(body_len + 1);
    if (!resp->body) {
        http_free_response(resp);
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }

    memset(resp->body, 0, body_len + 1);
    memcpy(resp->body, raw, body_len);
    resp->body[body_len] = '\0';
    free(init_raw);
    return resp;
}


// free http header memory
void http_free_header(struct Http_Header *h) {
    if (h) {
        free(h->name);
        free(h->value);
        http_free_header(h->next);
        free(h);
    }
}

// free http request memory
void http_free_request(struct Http_Request *req) {
    if (req) {
        free(req->url);
        free(req->version);
        http_free_header(req->headers);
        free(req->body);
        free(req);
    }
}

// free http response memory
void http_free_response(struct Http_Response *res) {
    if (res) {
        free(res->status_code);
        free(res->status_text);
        http_free_header(res->headers);
        free(res->body);
        free(res);
    }
}