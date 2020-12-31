#include "dns.h"

/*
Max size of data field in answer.
*/
#define DATASIZE 1024


/*
Auxiliary functions
*/

/*
Parse string in format "3etu4gouv2fr" and returns "etu.gouv.fr".
*/
char *parse_name(u_char *unparsed_name) {
    char *name = malloc(DNS_NAME_MAXSIZE);
    for (int i = 0; i < strlen((const char *) unparsed_name); i++) {
        int n = (int) unparsed_name[i];
        for (int j = 0; j < n; j++) {
            name[i] = unparsed_name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[strlen(name) - 1] = '\0';
    return name;
}

/*
Create mask of bits from a to b.
*/
unsigned createMask(unsigned a, unsigned b) {
    unsigned r = 0;
    for (unsigned i = a; i <= b; i++)
        r |= 1 << i;

    return r;
}

/*
Parse the control field's bits and return string corresponding to active flags.
*/
char *dns_parse_flags(uint16_t control) {
    char *flags = malloc(512);
    memset(flags, 0, 512);
    char *QR = "REQ";
    if ((control >> 15) & 1) QR = "RESP";
    char *OpCode;
    unsigned mask = createMask(11, 14);
#define QUERY 0
#define IQUERY 1
#define STATUS 2
#define NOTIFY 4
#define UPDATE 5
#define DSO 6
    switch (mask & control) {
        case QUERY :
            OpCode = "QUERY";
            break;
        case IQUERY :
            OpCode = "IQUERY";
            break;
        case STATUS :
            OpCode = "STATUS";
            break;
        case NOTIFY :
            OpCode = "NOTIFY";
            break;
        case UPDATE :
            OpCode = "UPDATE";
            break;
        case DSO :
            OpCode = "DSO";
            break;
        default :
            OpCode = "UNASSIGNED";
            break;
    }
    char *AA = "-";
    if ((control >> 10) & 1) AA = "AA";
    char *TC = "-";
    if ((control >> 9) & 1) TC = "TC";
    char *RD = "-";
    if ((control >> 8) & 1) RD = "RD";
    char *RA = "-";
    if ((control >> 7) & 1) RA = "RA";
    char *Z = "-";
    if ((control >> 6) & 1) Z = "Z";
    char *AD = "-";
    if ((control >> 5) & 1) AD = "AD";
    char *CD = "-";
    if ((control >> 4) & 1) CD = "CD";
    char *Rcode;
    mask = createMask(0, 3);
#define NOERROR 0
#define FORMERROR 1
#define SERVFAIL 2
#define NXDOMAIN 3
#define NOTIMP 4
#define REFUSED 5
    switch (mask & control) {
        case NOERROR :
            Rcode = "NOERROR";
            break;
        case FORMERROR :
            Rcode = "FORMERROR";
            break;
        case SERVFAIL :
            Rcode = "SERVFAIL";
            break;
        case NXDOMAIN :
            Rcode = "NXDOMAIN";
            break;
        case NOTIMP :
            Rcode = "NOTIMP";
            break;
        case REFUSED :
            Rcode = "REFUSED";
            break;
        default :
            Rcode = "OTHERERR";
            break;
    }
    sprintf(flags, "%s %s %s %s %s %s %s %s %s %s", QR, OpCode, AA, TC, RD, RA, Z, AD, CD, Rcode);
    return flags;


}

/*
Returns data corresponding to answer type and class  in string format.
*/
char *dns_get_response_data(struct dns_response *a) {
#define A 1
#define NS 2
#define CNAME 5
#define PTR 12
#define MX 15


    char *res = malloc(DATASIZE);
    uint16_t preference;

    switch (a->atype) {
        case CNAME :
        case A :
            if (a->aclass != 1) break;
            struct in_addr ip_addr;
            memcpy(&(ip_addr.s_addr), a->data, sizeof(int32_t));
            res = inet_ntoa(ip_addr);
            break;
        case NS :
        case PTR :
            if (a->data_length < DATASIZE)
                memcpy(res, a->data, a->data_length);
            else
                memcpy(res, "UNK", strlen("UNK"));
            break;
        case MX :
            memcpy(&preference, a->data, sizeof(uint16_t));
            char *exchange = parse_name(a->data + sizeof(uint16_t));
            snprintf(res, DATASIZE, "Preference %d | Exchange %s", preference, exchange);
            break;
        default :
            res = "OTHER";
            break;
    }
    return res;
}

/*
Parse DNS response and return it's type in string format.
*/
char *dns_get_response_type(struct dns_response *a) {
#define A 1
#define NS 2
#define CNAME 5
#define PTR 12
#define MX 15
    char *res = NULL;
    switch (a->atype) {
        case A :
            res = "A";
            break;
        case NS :
            res = "NS";
            break;
        case CNAME :
            res = "CNAME";
            break;
        case PTR :
            res = "PTR";
            break;
        case MX :
            res = "MX";
            break;
        default :
            res = "OTHER";
            break;
    }
    return res;
}

/*
Return size of Query inside the packet. Useful to calculate the offset to Answer struct.
*/
uint32_t dns_get_query_size(struct dns_query *q) {
    return sizeof(uint16_t) * 2 + strlen(q->qname) + 2;
}


/*
Main functions
*/

/*
Print functions.
*/

void dns_print_query(struct dns_query *q) {
    printf("** DNS QUERY :\n");
    printf("\tNAME : %s\n", q->qname);
    printf("\tTYPE : %d\n", q->qtype);
    printf("\tCLASS : %d\n", q->qclass);
}

void dns_print_header(u_char *data) {
    struct dnsheader *header = (struct dnsheader *) data;
    char *flags = dns_parse_flags(ntohs(header->flags));
    printf("** DNS HEADER : \n");
    printf("\tQUERY ID = %hu\n", ntohs(header->query_id));
    printf("\tFLAGS = %s\n", flags);
    printf("\tQUESTION COUNT = %hu\n", ntohs(header->QDCOUNT));
    printf("\tANSWER COUNT = %hu\n", ntohs(header->ANCOUNT));
    printf("\tAUTHORITY COUNT = %hu\n", ntohs(header->AUTHCOUNT));
    printf("\tADDITIONAL COUNT = %hu\n", ntohs(header->ADDCOUNT));
    free(flags);
}

void dns_print_answer(struct dns_response *a) {
    dns_print_query(a->query);
    printf("** DNS ANSWER :\n");
    printf("\tNAME : %s\n", a->aname);
    printf("\tTYPE : %s\n", dns_get_response_type(a));
    printf("\tCLASS : %s\n", (a->aclass == 1) ? "IN" : "OTHER");
    printf("\tTTL : %d\n", a->ttl);
    printf("\tDATA LENGTH : %d\n", a->data_length);
    printf("\tDATA : %s\n", dns_get_response_data(a));
}

/*
Check if the type of the packet is a Query or Answer.
Returns 1 if RESPONSE and 0 if QUERY
*/
int dns_get_type(u_char *data) {
    struct dnsheader *header = (struct dnsheader *) data;
    uint16_t control = header->flags;
    if ((control >> 15) & 1) return 1;
    return 0;
}

/*
Getters for the Query and Answer structures.
*/

struct dns_query *dns_get_query(u_char *data, unsigned int dataLength) {
    struct dns_query *qst = malloc(sizeof(struct dns_query));
    memset(qst, 0, sizeof(struct dns_query));
    char *name = parse_name(data + sizeof(struct dnsheader));
    uint32_t offset = sizeof(struct dnsheader) + strlen(name) + 2;
    qst->qname = name;
    memcpy(&(qst->qtype), data + offset, sizeof(uint16_t));
    qst->qtype = ntohs(qst->qtype);
    offset += 2;
    memcpy(&(qst->qclass), data + offset, sizeof(uint16_t));
    qst->qclass = ntohs(qst->qclass);
    return qst;
}

struct dns_response *dns_get_answer(u_char *data, unsigned int dataLength) {

    struct dns_response *ans = malloc(sizeof(struct dns_response));
    memset(ans, 0, sizeof(struct dns_response));
    ans->query = dns_get_query(data, dataLength);


    uint32_t offset = sizeof(struct dnsheader) + dns_get_query_size(ans->query);
    unsigned mask = createMask(14, 15);
    uint16_t decide;
    memcpy(&decide, data + offset, sizeof(uint16_t));
    if ((mask & ntohs(decide)) == mask) {
        mask = createMask(0, 13);
        uint16_t addr_offset = mask & ntohs(decide);
        offset += 2;
        ans->aname = parse_name(data + addr_offset);
    } else {
        ans->aname = parse_name(data + offset);
        offset += strlen(ans->aname) + 2;
    }
    memcpy(&(ans->atype), data + offset, sizeof(uint16_t));
    ans->atype = ntohs(ans->atype);
    offset += 2;
    memcpy(&(ans->aclass), data + offset, sizeof(uint16_t));
    ans->aclass = ntohs(ans->aclass);

    offset += 2;
    memcpy(&(ans->ttl), data + offset, sizeof(uint32_t));
    ans->ttl = ntohl(ans->ttl);

    offset += 4;
    memcpy(&(ans->data_length), data + offset, sizeof(uint16_t));
    ans->data_length = ntohs(ans->data_length);
    offset += 2;
    ans->data = data + offset;

    return ans;
}