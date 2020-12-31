#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "utils.h"
#include "dns.h"
#include "http.h"

void packetHandler(struct pcap_pkthdr *header, const u_char *packet);


int main(int argc, char *argv[]) {
    const char *input_file = NULL;
    pcap_t *packets = NULL;
    const u_char *packet = NULL;
    struct pcap_pkthdr *header = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("- Checking arg count ...\n");
    //test input arg
    if (argc != 2) {
        printf("\tERROR: %s <pcap file>", argv[0]);
        exit(EXIT_FAILURE);
    }
    printf("\tChecking arg count OK!\n");

    // save pcap file path
    input_file = argv[1];
    printf("- Input File: %s ...\n", input_file);

    //read pcap file
    packets = pcap_open_offline(input_file, errbuf);

    //test read .pcap file
    if (packets == NULL) {
        printf("\tERROR: Could not open file - %s", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("- Opened %s attempting to read packet lengths ...\n", input_file);

    int compteur = 0;
    header = malloc(sizeof(struct pcap_pkthdr));

    // Check if the memory has been successfully allocated by malloc or not
    if (header == NULL) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }
    //init struct with 0
    memset(header, 0, sizeof(struct pcap_pkthdr));

    //print all packets
    while (pcap_next_ex(packets, &header, &packet) != -2) {
        printf("\n\t%d - Packet of length [%d bytes] [%d bits]\n", compteur, header->len, header->len * 8);
        printf("\n\t");
        for (int i = 0; i < header->len; i++) {
            if (i % 8 == 0 && i != 0) printf("\n\t");
            printf("%2X ", packet[i]);
        }
        compteur++;
        printf("\n\n");
        packetHandler(header, packet);
    }
    printf("- Finish !\n");

    //free(header);

    //close packet file
    pcap_close(packets);

    printf("- Closing %s ...\n", input_file);
    printf("\tClosing %s OK!\n", input_file);

    return EXIT_SUCCESS;
}

void packetHandler(struct pcap_pkthdr *header, const u_char *packet) {

    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;

    const struct tcphdr *tcpHeader;
    const struct udphdr *udpHeader;

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];

    u_int sourcePort, destPort;
    u_char *data;

    unsigned int dataLength = 0;

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

            //http port = 80 , https port = 443
            if (sourcePort == 80 || sourcePort == 443 || destPort == 80 || destPort == 443) {
                //print http protocol
                struct Request *req = parse_request((const char *) data);
                if (req) {
                    printf("Method: %s\n", req->method);
                    printf("Request-URI: %s\n", req->url);
                    printf("HTTP-Version: %s\n", req->version);
                    puts("Headers:");
                    struct Request_header *h;
                    for (h = req->headers; h; h = h->next) {
                        printf("%32s: %s\n", h->name, h->value);
                    }
                    puts("message-body:");
                    puts(req->body);
                }
                free_request(req);
            }

            if (tcpHeader->th_flags & TH_SYN) {
                //print syn tcp
            }

            //UDP fragment
        } else if (ipHeader->ip_p == IPPROTO_UDP) {
            udpHeader = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));
            sourcePort = ntohs(udpHeader->uh_sport);
            destPort = ntohs(udpHeader->uh_dport);

            data = (u_char *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

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
        } else if (ipHeader->ip_p == IPPROTO_ICMP) {
            //print icmp
        }
    }
}
