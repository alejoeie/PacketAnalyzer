/*

    Un socket creado por cada vez que creamos el programa?
    O un socket por cada paquete que ingresa al puerto?

    AF_INET -> ipv4 lo que necesitamos
    sa_data -> contiene una direccion de destino y numero de puerto en el socket

    Existe struct sockaddr y struct sockaddr_in ("in" de Internet)
    // (IPv4 only--see struct sockaddr_in6 for IPv6)

    // (IPv4 only--see struct in6_addr for IPv6)

    // Internet address (a structure for historical reasons)
    struct in_addr {
        uint32_t s_addr; // that's a 32-bit int (4 bytes)
    };

    struct sockaddr_in {
        short int          sin_family;  // Address family, AF_INET
        unsigned short int sin_port;    // Port number
        struct in_addr     sin_addr;    // Internet address
        unsigned char      sin_zero[8]; // Same size as struct sockaddr
};
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include "pkt_headers.h"
#include "pkt_analyzer.h"

packet_parser_result_e packet_parser_retrieve_pkt_data(int unix_cmd, char* cmd){
    struct addrinfo hints, *res, *p;
    int status;
    char ip_str[INET_ADDRSTRLEN];

    if (unix_cmd < 2) {
        fprintf(stderr, "Usage: packet_analyzer hostname\n");
        return PACKET_ANALYZER_RES_NONE;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Connection ready
    if(0 != (status = getaddrinfo(cmd, NULL, &hints, &res))){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return PACKET_ANALYZER_RES_FAIL;
    }

    for(p = res;p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;

        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ip_str, sizeof ip_str);
        printf("  %s: %s\n", ipver, ip_str);
    }

    freeaddrinfo(res); // free the linked list
    return PACKET_ANALYZER_RES_OK;
}

int main(int argc, char* argv[]) {

    if(PACKET_ANALYZER_RES_OK != packet_parser_retrieve_pkt_data(argc, argv[1])){
        fprintf(stderr, "Invalid packet data fetching");
        return -1;
    }
    
    
    return 0;
}