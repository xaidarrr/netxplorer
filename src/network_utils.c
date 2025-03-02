#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "../include/network_utils.h"


// Check for IPv4
bool is_ipv4(const char *address) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, address, &(sa.sin_addr)) == 1;   
}

// Check for FQDN 
bool is_fqdn(const char *hostname) {
    regex_t regex;
    const char *pattern = "^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        return false;
    }

    int result = regexec(&regex, hostname, 0, NULL, 0);
    regfree(&regex);
    
    return result == 0;
}

char* check_type(const char *input) {
    if (is_ipv4(input)) return "IPv4";
    if (is_fqdn(input)) return "FQDN";
    return "None";
}


// Convert FQDN to IPv4 
char* get_ip_from_fqdn(char *fqdn) {
    struct addrinfo hints, *res;
    int status;
    static char ip[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(fqdn, NULL, &hints, &res);
    if (status != 0) {
        perror("\nFailure: Incorrect FQDN\n\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &ipv4->sin_addr, ip,  INET_ADDRSTRLEN);

    freeaddrinfo(res);
    
    return ip;

}

// Convert IPv4 to FQDN
char* get_fqdn_from_ip(char *ip) {
    struct sockaddr_in sa;
    static char host[NI_MAXHOST];

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);

    return (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) ? host : ip;


}

// Calculating checksum for IPv4
unsigned short checksum(void *b, int len) {     
    unsigned short *buf = (unsigned short *)b; 
    unsigned int sum = 0; 
    unsigned short result; 
 
    for (sum = 0; len > 1; len -= 2) 
        sum += *buf++; 
    if (len == 1) 
        sum += *(unsigned char *)buf; 
     
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

// Set network interface
char* set_interface(int sockfd, char *interface_name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        printf("\nFailure: Impossible to get IP address of %s\n\n", interface_name);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1) {
        printf("\nFailure: Impossible to bind socket to %s\n\n", interface_name);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    return inet_ntoa(ipaddr->sin_addr);
}

void print_output(char *ip, double rtt, int ttl, int is_final) {
    if (strcmp(ip, "* * *") == 0) {
        printf("%-8d %-15s %s (%s) \n", ttl, "* * *", "* * *", ip);
    }

    else {
        char *fqdn = get_fqdn_from_ip(ip);
        if (is_final == 0) {
            printf("%-8d %-15.3f %s (%s) \n", ttl, rtt, fqdn, ip);
        }
        else {
            printf("%-8d %-15.3f %s (%s) <--- TARGET HOST\n", ttl, rtt, fqdn, ip);
        }
    }

}

void print_statistic(int ttl, double avg_rtt, double max_rtt) {
    printf("-----------------------------------------------------------------------------------------\n\n");
    printf("Diagnostic completed.\n");
    printf("Total hops: %d\n", ttl);
    printf("Max RTT: %.3f ms\n", max_rtt);
    printf("Average RTT: %.3f ms\n\n", avg_rtt);
}
    



