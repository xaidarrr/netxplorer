#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 if the address is a valid IPv4 address, 0 otherwise
int is_ipv4(const char *ip_address);

// Checks if the given string is an FQDN
int is_fqdn(const char *hostname);

// Determines the type of the input string: IPv4, FQDN, or None 
char *check_type(const char *input);

// Resolves the given FQDN to its corresponding IPv4 address, returns NULL if unsuccessful  
char *get_ip_from_fqdn(char *fqdn);

// Resolves the given IPv4 address to its corresponding FQDN, returns the IP address if unsuccessful
char *get_fqdn_from_ip(char *ip_address);

// Calculates the checksum for the packet 
unsigned short checksum(void *b, int len);

// Binds the socket to the specified network interface and returns the IP address of the interface
char *set_interface(int sockfd, char *interface_name);

// Returns 0 if the interface was successfully found, -1 otherwise 
char *get_primary_interface();

// Prints information about the node's IP address, RTT, TTL
void print_output(char *ip, double rtt, int ttl, int is_final);

// Prints diagnostic statistics, including total hops, maximum RTT, and average RTT 
void print_statistic(int ttl, double avg_rtt, double max_rtt);

#ifdef __cplusplus
}
#endif

#endif // NETWORK_UTILS_H