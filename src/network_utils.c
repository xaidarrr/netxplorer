#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <regex.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>


// Returns 1 if the address is a valid IPv4 address, 0 otherwise 
int is_ipv4(const char *ip_address)
{
    struct sockaddr_in sa;

    return inet_pton(AF_INET, ip_address, &(sa.sin_addr)) == 1;
}

// Returns 1 if the address is a valid FQDN, 0 otherwise 
int is_fqdn(const char *hostname)
{
    regex_t regex;
    const char *pattern = "^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        return 0;
    }

    int result = regexec(&regex, hostname, 0, NULL, 0);
    regfree(&regex);
    
    return result == 0;
}

// Determines the type of the input string: IPv4, FQDN, or None  
char *check_type(const char *input)
{
    if (is_ipv4(input) == 1) {
        return "IPv4";
    }
    if (is_fqdn(input) == 1) {
        return "FQDN";
    }

    return "None";
}

//  Resolves the given FQDN to its corresponding IPv4 address, returns NULL if unsuccessful  
char *get_ip_from_fqdn(char *fqdn)
{
    struct addrinfo hints, *addr_result;
    static char ip_address[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(fqdn, NULL, &hints, &addr_result) != 0) {
        fprintf(stderr, "\nFailure: Incorrect FQDN\n\n");
        return NULL;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr_result->ai_addr;
    inet_ntop(AF_INET, &ipv4->sin_addr, ip_address, INET_ADDRSTRLEN);

    freeaddrinfo(addr_result);
    
    return ip_address;
}

// Resolves the given IPv4 address to its corresponding FQDN, returns the IP address if unsuccessful  
char *get_fqdn_from_ip(char *ip_address)
{
    struct sockaddr_in sa;
    static char host[NI_MAXHOST];

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &sa.sin_addr);

    return (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) ? host : ip_address;
}

// Calculates the checksum for the packet  
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    // Summing all 16-bit words  
    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    
    // Adding the odd byte, if present  
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }

    // Adding carries  
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

// Binds the socket to the specified network interface and returns the IP address of the interface 
char *set_interface(int sockfd, char *interface_name)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

    // Retrieves the IP address of the interface  
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
        return NULL;
    }

    // Binding the socket to the interface  
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1) {
        fprintf(stderr, "\nFailure: Cannot bind socket to %s\n\n", interface_name);
        return NULL;
    }

    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;

    return inet_ntoa(ipaddr->sin_addr);
}

// Returns 0 if the interface was successfully found, -1 otherwise 
char *get_primary_interface() 
{
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr, "Failure: It's impossible to detect network interface\n");
        return NULL;
    }

    // Iterate through the list of network interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue; // Skip if no address is assigned

        // Check if it's an IPv4 interface and not a loopback
        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {

            return ifa->ifa_name;  // Successfully found the interface
        }
    }

    return NULL;  // No valid interface found
}

// Prints information about the node's IP address, RTT, TTL
void print_output(char *ip, double rtt, int ttl, int is_final)
{
    if (strcmp(ip, "* * *") == 0) {
        printf("%-8d %-12s %s (%s)\n", ttl, "* * *", "* * *", ip);
    } else {
        char *fqdn = get_fqdn_from_ip(ip);
        if (is_final == 0) {
            printf("%-8d %-12.3f %s (%s)\n", ttl, rtt, fqdn, ip);
        } else {
            printf("%-8d %-12.3f %s (%s) <-- TARGET HOST\n", ttl, rtt, fqdn, ip);
        }
    }
}

// Prints diagnostic statistics, including total hops, maximum RTT, and average RTT 
void print_statistic(int ttl, double avg_rtt, double max_rtt)
{
    printf("--------------------------------------------------------------------------------\n\n");
    printf("Diagnostic completed.\n");
    printf("Total hops: %d\n", ttl);
    printf("Max RTT: %.3f ms\n", max_rtt);
    printf("Average RTT: %.3f ms\n\n", avg_rtt);
}