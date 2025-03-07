#ifndef ICMP_H
#define ICMP_H

#ifdef __cplusplus
extern "C" {
#endif

// Create and send an ICMP Echo Request packet with the specified TTL
int send_icmp_request(int sockfd, char *dst_ip, int ttl);

// Receiving ICMP Echo Reply or ICMP Time Exceeded
int receive_icmp_reply(int sockfd, char *dst_ip, int sent_packet_size, int ttl, double *rtt);

// Function to perform ICMP route tracing
int icmp_trace(char *dst_ip, int is_fqdn, int max_hops, char *interface);

#ifdef __cplusplus
}
#endif

#endif // ICMP_H