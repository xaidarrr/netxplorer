#ifndef TCP_H
#define TCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

long send_syn_packet(int sockfd, char *src_ip, char *dst_ip, unsigned short dst_port, int ttl);
int receive_syn_ack_packet(int sockfd, int ttl, int *rtt);
int tcp_trace(char *dst_ip, unsigned short port, bool is_fqdn, bool bandwidth, int max_hops, char *interface);



#ifdef __cplusplus
}
#endif

#endif // TCP_H