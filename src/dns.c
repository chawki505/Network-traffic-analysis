#include "dns.h"

char * dns_get_question(u_char * data, unsigned int dataLength){
    char * domain_name = malloc(DNS_NAME_MAXSIZE);
    memset(domain_name, 0, DNS_NAME_MAXSIZE);
    for(int i =  sizeof(struct dnsheader); i < dataLength; i++){
        if(data[i] == '\n')
            break;
        domain_name[i-sizeof(struct dnsheader)] = data[i];
    }
    return domain_name;
}

unsigned  createMask(unsigned a, unsigned b)
{
   unsigned r = 0;
   for (unsigned i=a; i<=b; i++)
       r |= 1 << i;

   return r;
}

char * dns_parse_flags(uint16_t control){
    char * flags = malloc(512);
    memset(flags, 0, 512);
    char * QR = "REQ";
    if((control >> 15) & 1) QR = "RESP";
    char * OpCode;
    unsigned mask = createMask(11, 14);
    #define QUERY 0
    #define IQUERY 1
    #define STATUS 2
    #define NOTIFY 4
    #define UPDATE 5
    #define DSO 6
    switch(mask & control){
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
    char * AA = "-";
    if((control >> 10) & 1)  AA = "AA";
    char * TC = "-";
    if((control >> 9) & 1) TC = "TC";
    char * RD = "-";
    if((control >> 8) & 1) RD = "RD";
    char * RA = "-";
    if((control >> 7) & 1) RA = "RA";
    char * Z = "-";
    if((control >> 6) & 1) Z = "Z";
    char * AD = "-";
    if((control >> 5) & 1) AD = "AD";
    char * CD = "-";
    if((control >> 4) & 1) CD = "CD";
    char * Rcode;
    mask = createMask(0,3);
    #define NOERROR 0
    #define FORMERROR 1
    #define SERVFAIL 2
    #define NXDOMAIN 3
    #define NOTIMP 4
    #define REFUSED 5
    switch(mask & control){
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
    sprintf(flags, "%s %s %s %s %s %s %s %s %s %s", QR, OpCode, AA, TC, RD, RA, Z , AD, CD, Rcode);
    return flags;


}

void dns_print_header(u_char * data){
    struct dnsheader * header = (struct dnsheader *) data;
    char * flags = dns_parse_flags(ntohs(header->flags));
    printf("** DNS HEADER : \n");
    printf("\tQUERY ID = %hu\n", ntohs(header->query_id));
    printf("\tFLAGS = %s\n", flags);
    printf("\tQUESTION COUNT = %hu\n", ntohs(header->QDCOUNT));
    printf("\tANSWER COUNT = %hu\n", ntohs(header->ANCOUNT));
    printf("\tAUTHORITY COUNT = %hu\n", ntohs(header->AUTHCOUNT));
    printf("\tADDITIONAL COUNT = %hu\n", ntohs(header->ADDCOUNT));
    free(flags);
}

int dns_get_type(u_char * data) {
    struct dnsheader * header = (struct dnsheader *) data;
    uint16_t control = header->flags;
    if((control >> 15) & 1) return 1;
    return 0;
}


char * extract_line(u_char * start){
    u_char * p = start;
    char * res = malloc(DNS_NAME_MAXSIZE);
    uint32_t i = 0;
    while(*p != '\n'){
        res[i] = *p;
        i++;
        p++;
    }
    return res;
}

char * dns_get_answer(u_char * data, unsigned int dataLength){
    char * qst = dns_get_question(data, dataLength);
    uint32_t offset = sizeof(struct dnsheader) + strlen(qst);
    free(qst);
    u_char * pos_p = data + offset;
    char * domain_name = extract_line(pos_p);
    printf("** ANSWER :\n");
    printf("\t DOMAIN NAME : %s", domain_name);
    offset += strlen(domain_name);
    free(domain_name);
    for(int i = offset; i<dataLength; i++) printf("%c", data[i]);
    return NULL;
}