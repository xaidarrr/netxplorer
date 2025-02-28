#ifndef ICMP_H
#define ICMP_H

#ifdef __cplusplus
extern "C" {
#endif


unsigned short checksum(void *b, int len);
int send_icmp_request(int sockfd, char *dst_ip, int ttl);
int receive_icmp_reply(int sockfd, char *dst_ip, int ttl, double *rtt);
int icmp_trace(char *dst_ip, char *type_addr, int max_hops);

#ifdef __cplusplus
}
#endif

#endif // ICMP_H