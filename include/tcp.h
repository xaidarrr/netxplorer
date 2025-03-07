#ifndef TCP_H
#define TCP_H

#ifdef __cplusplus
extern "C" {
#endif


// Create and send an TCP SYN packet with the specified TTL
long send_syn_packet(int sockfd, char *src_ip, char *dst_ip, unsigned short dst_port, int ttl);
// Function to receive a TCP SYN-ACK packet and an ICMP reply
int receive_syn_ack_packet(int sockfd, int ttl, int *rtt);
// Function to perform TCP route tracing
int tcp_trace(char *dst_ip, unsigned short port, int is_fqdn, int max_hops, char *interface);



#ifdef __cplusplus
}
#endif

#endif // TCP_H