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

#ifdef __cplusplus
}
#endif

#endif // NETWORK_UTILS_H