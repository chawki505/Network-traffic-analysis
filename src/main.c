#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "utils.h"


int main(int argc, char *argv[]) {
    char *input_file = NULL;
    pcap_t *packets = NULL;
    const u_char *packet;
    struct pcap_pkthdr *header = malloc(sizeof(struct pcap_pkthdr));
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

    //print all packets
    int compteur = 0;
    while (pcap_next_ex(packets, &header, &packet) != -2) {
        printf("\t%d - Packet of length [%d bytes] [%d bits]\n", compteur, header->len, header->len * 8);
        printf("\n\t");
        for (int i = 0; i < header->len; i++) {
            if (i % 8 == 0 && i != 0) printf("\n\t");
            printf("%2X ", packet[i]);
        }
        compteur++;
        printf("\n\n");
    }
    printf("- Finish !\n");

    //close packet file
    pcap_close(packets);

    printf("- Closing %s ...\n", input_file);
    printf("\tClosing %s OK!\n", input_file);

    return EXIT_SUCCESS;
}