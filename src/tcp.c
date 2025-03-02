#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <time.h>


#include "../include/network_utils.h"

#define PSEUDO_HEADER_SIZE 12
#define PACKET_SIZE 4096

// Pseudo header for TCP checksum
struct pseudo_header {
    u_int32_t src_address; // Source IP address
    u_int32_t dst_address; // Destination IP address
    u_int8_t place_holder; // Reserved field. Always equal 0
    u_int8_t protocol; // Protocol
    u_int16_t tcp_length; // TCP segment length
};

// Sending TCP SYN packet
long send_syn_packet(int sockfd, const char *src_ip, char *dst_ip, unsigned short dst_port, int ttl, struct timespec *start_time) {
    char packet[PACKET_SIZE]; 
    struct iphdr *ip_header = (struct iphdr *)packet; 
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr)); 

    struct sockaddr_in dst_addr; 
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = dst_port;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    memset(ip_header, 0, sizeof(struct iphdr));
    memset(tcp_header, 0, sizeof(struct tcphdr));

    // Filling IP header
    ip_header->ihl = 5; // IP header length
    ip_header->version = 4; // IP version
    ip_header->tos = 0; // Type of Service
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // Total length
    ip_header->id = htons(54321); // Random ID
    ip_header->frag_off = 0; // Fragment Offset
    ip_header->ttl = ttl; // Time to Live
    ip_header->protocol = IPPROTO_TCP; // Protocol
    ip_header->check = 0; // Checksum (will be calculated later)
    ip_header->saddr = inet_addr(src_ip); // Source address
    ip_header->daddr = dst_addr.sin_addr.s_addr; // Destination address

    // Filling TCP header
    tcp_header->source = htons(34553); // Random source port
    tcp_header->dest = htons(dst_port); // Destination port
    tcp_header->seq = htonl(53466); // Sequence number
    tcp_header->ack_seq = 0; // Acknowledge number 
    tcp_header->doff = 5; // TCP header length
    tcp_header->urg = 0; // URG flag (Urgent pointer)
    tcp_header->fin = 0; // FIN flag (Finish)
    tcp_header->syn = 1; // SYN flag (Synchronize)
    tcp_header->rst = 0; // RST flag (Reset connection)
    tcp_header->psh = 0; // PSH flag (Push function)
    tcp_header->ack = 0; // ACK flag (Acknowledgement)
    tcp_header->window = htons(5840); // Window size
    tcp_header->check = 0; // Checksum (will be calculated later)
    tcp_header->urg_ptr = 0; // Urgent pointer. Pointer on urgent data (only if urg flag = 1)

    // Pseudo header for calculating checksum
    struct pseudo_header pshdr;
    pshdr.src_address = inet_addr(src_ip);
    pshdr.dst_address = dst_addr.sin_addr.s_addr;
    pshdr.place_holder = 0;
    pshdr.protocol = IPPROTO_TCP;
    pshdr.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr); // Pseudo + TCP header's size
    char *pgram = (char *)malloc(psize); // Buffer for pseudo + tcp headers

    // Copy data to the pseudo header
    memcpy(pgram, (char *)&pshdr, sizeof(struct pseudo_header));
    memcpy(pgram + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr));

    // Calculating checksum for TCP header
    tcp_header->check = checksum((unsigned short *)pgram, psize);

    // Calculating checksum for IP header
    ip_header->check = checksum((unsigned short *)packet, ip_header->tot_len);
    
    int one = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    clock_gettime(CLOCK_MONOTONIC, start_time);
    int sent_bytes = sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if(sent_bytes < 0) {
        perror("Failure: Troubles with sending packet");
        free(pgram);
        exit(EXIT_FAILURE);
    }

    

    free(pgram);

    return 0;
}

// Receiving TCP ACK packet
int receive_syn_ack_packet(int sock_tcp, int sock_icmp, int ttl, struct timespec *start_time, double *rtt_icmp, double *rtt_tcp) {
    char buffer[PACKET_SIZE];
    struct iphdr *ip_header = (struct iphdr *)buffer;
    struct tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    struct sockaddr_in recv_addr;
    struct timespec end_time_tcp, end_time_icmp;
    socklen_t addr_len = sizeof(recv_addr);

    struct timeval timeout;
    timeout.tv_sec = 2;  // 2 seconds
    timeout.tv_usec = 0;
    setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock_icmp, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));


    ssize_t recv_bytes = recvfrom(sock_icmp, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len); 
    clock_gettime(CLOCK_MONOTONIC, &end_time_icmp);

     
    if (recv_bytes >= 0) {
        if (ip_header->protocol == IPPROTO_ICMP) {
            char *ip = inet_ntoa(((struct sockaddr_in *)&recv_addr)->sin_addr);
            *rtt_icmp = ((end_time_icmp.tv_sec - start_time->tv_sec) * 1000 + (end_time_icmp.tv_nsec - start_time->tv_nsec) / 1e6) ;
            print_output(ip, *rtt_icmp, ttl, 0);

            return 0;   
            }      

    }
    else {      
        recv_bytes = recvfrom(sock_tcp, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);
        clock_gettime(CLOCK_MONOTONIC, &end_time_tcp);
        if (recv_bytes >= 0) {
            if (ip_header->protocol == IPPROTO_TCP && tcp_header->syn == 1 && tcp_header->ack == 1) {
                
                *rtt_tcp = (((end_time_tcp.tv_sec - start_time->tv_sec) * 1000 + (end_time_tcp.tv_nsec - start_time->tv_nsec) / 1.0e6)) - timeout.tv_sec * 1000;
                

                char *ip = inet_ntoa(((struct sockaddr_in *)&recv_addr)->sin_addr);


                print_output(ip, (*rtt_tcp), ttl, 1);

                return 1;
            }
        }
    }
    print_output("* * *", 0, ttl, 0);
    return 0;
}





int tcp_trace(char *dst_ip, unsigned short port, bool is_fqdn, bool bandwidth, int max_hops, char *interface) {;
    int ttl;
    double rtt_icmp, rtt_tcp;
    double avg_rtt = 0;
    double max_rtt = 0;
    int sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    struct timespec start_time;
    struct sockaddr_in recv_addr;
    if (sock_tcp < 0 || sock_icmp < 0) {
        perror("Failure: troubles with creating socket\n");
        return -1;
    }
    // Set interface 
    if (interface != NULL) {

        if (is_fqdn) {
            char *fqdn = dst_ip;
            dst_ip = get_ip_from_fqdn(dst_ip);
        }

        for (ttl = 1; ttl < max_hops; ttl++) {
            char *src_ip = set_interface(sock_tcp, interface);

            
            ssize_t sent_bytes = send_syn_packet(sock_tcp, src_ip, dst_ip, port, ttl, &start_time);
            if (sent_bytes < 0) {;
                printf("Sent bytes err");
                return -1;
            }
            
            int reply_status = receive_syn_ack_packet(sock_tcp, sock_icmp, ttl, &start_time, &rtt_icmp, &rtt_tcp);
            avg_rtt += rtt_icmp + rtt_tcp;
            if (rtt_icmp > max_rtt) {
                max_rtt = rtt_icmp;
            }
            else if (rtt_tcp > max_rtt) {
                max_rtt = rtt_tcp;
            }
            if (reply_status == 1) {
                avg_rtt = avg_rtt / ttl;
                break; 
            }

    
        }
        print_statistic(ttl, avg_rtt, max_rtt);

        close(sock_tcp);
        close(sock_icmp);
        return 0;
    }
    else {
        printf("Interface err");
        close(sock_tcp);
        close(sock_icmp);
        return -1;
    }

}