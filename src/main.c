
#include "utils.h"

//main
int main(int argc, char *argv[]) {
    const char *input_file = NULL;
    pcap_t *packets = NULL;
    const u_char *packet = NULL;
    struct pcap_pkthdr *header = NULL;
    char err_buf[PCAP_ERRBUF_SIZE];
    system("clear");
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
    packets = pcap_open_offline(input_file, err_buf);

    //test read .pcap file
    if (packets == NULL) {
        printf("\tERROR: Could not open file - %s", err_buf);
        exit(EXIT_FAILURE);
    }

    printf("- Opened %s attempting to read packet lengths ...\n", input_file);

    int count = 0;
    header = malloc(sizeof(struct pcap_pkthdr));
    struct pcap_pkthdr *save_header = header; //use in free();


    // Check if the memory has been successfully allocated by malloc or not
    if (header == NULL) {
        printf("Memory not allocated.\n");
        exit(EXIT_FAILURE);
    }
    //init struct with 0
    memset(header, 0, sizeof(struct pcap_pkthdr));


    //print all packets
    while (pcap_next_ex(packets, &header, &packet) != -2) {
        printf("\n\t%d - Packet of length [%d bytes] [%d bits]\n", count + 1, header->len, header->len * 8);
        printf("\n\t");
        for (int i = 0; i < header->len; i++) {
            if (i % 16 == 0 && i != 0) printf("\n\t");
            printf("%02X ", packet[i]);
        }
        count++;
        printf("\n\n");
        packetHandler(header, packet);
        printf("\nPress enter to continue ... \n");
        getchar();
        system("clear");
    }
    printf("- Finish !\n");

    free(save_header);

    //close packet file
    pcap_close(packets);

    printf("- Closing %s ...\n", input_file);
    printf("\tClosing %s OK!\n", input_file);

    return EXIT_SUCCESS;
}