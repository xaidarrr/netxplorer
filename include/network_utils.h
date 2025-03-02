#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>


bool is_ipv4(const char *address);
bool is_fqdn(const char *hostname);
char* check_type(const char *input);
char* get_ip_from_fqdn(char *fqdn);
char* get_fqdn_from_ip(char *ip);
unsigned short checksum(void *b, int len);
char* set_interface(int sockfd, char *interface_name);
void print_output(char *ip, double rtt, int ttl, int is_final);
void print_statistic(int ttl, double avg_rtt, double max_rtt);

#ifdef __cplusplus
}
#endif

#endif // NETWORK_UTILS_H