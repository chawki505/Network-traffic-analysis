#include "utils.h"


//methode to parse packet
void packetHandler(struct pcap_pkthdr *header, const u_char *packet) {

    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;

    const struct tcphdr *tcpHeader;
    const struct udphdr *udpHeader;

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    u_int sourcePort, destPort;
    u_char *data;

    size_t dataLength;

    //ethernet fragment
    ethernetHeader = (struct ether_header *) packet;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {

        //ip fragment
        ipHeader = (struct ip *) (packet + sizeof(struct ether_header));

        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);



        //TCP fragment
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->th_sport);
            destPort = ntohs(tcpHeader->th_dport);

            data = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            print_ip_port(sourceIP, destIP, sourcePort, destPort);

            //http port = 80
            if (sourcePort == 80 || destPort == 80) {

                printf("======================= HTTP PACKET =======================\n\n");
                struct Http_Request *req = http_parse_request((char *) data, dataLength);
                if (req) {
                    printf("Method: %s\n", req->method);
                    printf("Request-URI: %s\n", req->url);
                    printf("HTTP-Version: %s\n", req->version);
                    printf("Headers:\n");
                    struct Http_Header *h;
                    for (h = req->headers; h; h = h->next) {
                        printf("\t%s: %s\n", h->name, h->value);
                    }
                    printf("message-body: %s\n", req->body);
                } else {
                    struct Http_Response *resp = http_parse_response((char *) data, dataLength);
                    if (resp) {
                        printf("HTTP-Version: %s\n", resp->version);
                        printf("Status code: %s\n", resp->status_code);
                        printf("Status text: %s\n", resp->status_text);
                        printf("Headers:\n");
                        struct Http_Header *h;
                        for (h = resp->headers; h; h = h->next) {
                            printf("\t%s: %s\n", h->name, h->value);
                        }
                        printf("message-body: %s\n", resp->body);
                    }
                    http_free_response(resp);
                }
                http_free_request(req);
                printf("==========================================================\n");
            }

            //UDP fragment
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(udpHeader->uh_sport);
            destPort = ntohs(udpHeader->uh_dport);

            data = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

            print_ip_port(sourceIP, destIP, sourcePort, destPort);


            if (sourcePort == 53 || destPort == 53) {

                printf("======================= DNS PACKET =======================\n\n");
                dns_print_header(data);
                if (dns_get_type(data) == 1) {
                    struct dns_response *a = dns_get_answer(data, dataLength);
                    dns_print_answer(a);
                    free(a);
                } else {
                    struct dns_query *q = dns_get_query(data, dataLength);
                    dns_print_query(q);
                    free(q);
                }
                printf("==========================================================\n");
            }
        }
    }
}

//methode to print ip and port to src and dest
void print_ip_port(const char *sourceIP, const char *destIP, u_int sourcePort, u_int destPort) {
    printf(" Ip src : %s Port : %u | Ip src : %s Port : %u\n", sourceIP, sourcePort, destIP, destPort);
}
