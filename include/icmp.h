#ifndef ICMP_H
#define ICMP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

int send_icmp_request(int sockfd, char *dst_ip, int ttl);
int receive_icmp_reply(int sockfd, char *dst_ip, int sent_packet_size, int ttl, double *rtt, bool bandwidth);
int icmp_trace(char *dst_ip, bool is_fqdn, int max_hops, bool bandwidth, char *interface);



#ifdef __cplusplus
}
#endif

#endif // ICMP_H