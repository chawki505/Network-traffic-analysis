#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "utils.h"
#include "dns.h"
#include "http.h"


void packetHandler(struct pcap_pkthdr *header, const u_char *packet);


#endif //UTILS_H
