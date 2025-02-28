#include "../include/network_utils.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>

// Check for IPv4
bool is_ipv4(const char *address) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, address, &(sa.sin_addr)) == 1;   
}

// Check for IPv6
bool is_ipv6(const char *address) {
    struct sockaddr_in6 sa6;
    return inet_pton(AF_INET6, address, &(sa6.sin6_addr)) == 1;   
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
    if (is_ipv6(input)) return "IPv6";
    if (is_fqdn(input)) return "FQDN";
    return "None";
}


// Convert FQDN to IPv4 or IPv6
char* get_ip_from_fqdn(const char *fqdn) {
    struct addrinfo hints, *res;
    int status;
    static char ip[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(fqdn, NULL, &hints, &res);
    if (status != 0) {
        printf("Failure with FQDN");
        return NULL;
    }

    if (res->ai_family == AF_INET) {  // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &ipv4->sin_addr, ip,  INET_ADDRSTRLEN);
    }
    else if (res->ai_family = AF_INET6) { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, INET6_ADDRSTRLEN);
    }

    freeaddrinfo(res);
    
    return ip;

}

