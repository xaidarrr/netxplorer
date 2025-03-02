#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>

#include "../include/network_utils.h"

#define PACKET_SIZE 64


// Sending ICMP echo request
int send_icmp_request(int sockfd, char *dst_ip, int ttl, struct timespec *start_time) {
    struct icmphdr icmp_hdr;

    // ICMP header
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid(); // Proccess id
    icmp_hdr.un.echo.sequence = 1; // Sequence number
    icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));


    struct sockaddr_in dst_addr_ipv4;
    dst_addr_ipv4.sin_family = AF_INET;
    dst_addr_ipv4.sin_port = 0;
    dst_addr_ipv4.sin_addr.s_addr = inet_addr(dst_ip);
        
    // Setting TTL
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        
    clock_gettime(CLOCK_MONOTONIC, start_time);   
    // Sending packet
    ssize_t sent_bytes = sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&dst_addr_ipv4, sizeof(dst_addr_ipv4));

    if (sent_bytes < 0) {
        perror("Failure: Troubles with sending ICMP echo request");
        return -1;
    }


    return sent_bytes;
    
   
}

// Receiving ICMP echo reply or ICMP time exceeded
int receive_icmp_reply(int sockfd, char *dst_ip, int sent_packet_size, int ttl, double *rtt, bool bandwidth, struct timespec *start_time) {
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct timespec end_time;
    struct sockaddr_in recv_addr_ipv4;
    char buffer[PACKET_SIZE];
    struct icmphdr *icmp_header;


    struct timeval timeout;
    timeout.tv_sec = 2;  
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    
    ssize_t received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                                    (struct sockaddr *)(struct sockaddr *)&recv_addr_ipv4, &addr_len);

    // End time
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    if (received_bytes < 0) {
        printf("* * *\n");
        return 0;
    }
    

    

    *rtt = ((end_time.tv_sec - start_time->tv_sec) * 1000 + (end_time.tv_nsec - start_time->tv_nsec) / 1e6);

    icmp_header = (struct icmphdr *)(buffer + sizeof(struct ip));

    if (icmp_header->type == ICMP_ECHOREPLY) {
        // Intermediate host's IP
        char *ip = inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr);

        print_output(ip, *rtt, ttl, 1);
        
        return 1;
    }
    else if (icmp_header->type == ICMP_TIME_EXCEEDED) {
        // Intermediate host's IP
        char *ip = inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr);

        print_output(ip, *rtt, ttl, 0);

        return 0;  // Intermediate host, keep increasing TTL
    } 
    else {
        printf("Received unexpected ICMP packet type: %d\n", icmp_header->type);
        return -1;
}

}


// Main function
int icmp_trace(char *dst_ip, bool is_fqdn, int max_hops, bool bandwidth, char *interface) {
    double rtt;
    int ttl;
    double max_rtt = 0;
    struct timespec start_time;
    double avg_rtt;

    // Creating raw-socket (raw socket require sudo)
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        perror("Failure: troubles with creating socket");
        return -1;
    }

    // Set interface if necessary
    if (interface != NULL) {
        set_interface(sockfd, interface);
    }

    // Convert FQDN to IPv4 if it is necessary
    if (is_fqdn) {
        char *fqdn = dst_ip;
        dst_ip = get_ip_from_fqdn(dst_ip);
    }

    for (ttl = 1; ttl <= max_hops; ttl++) {
        int packet_size = send_icmp_request(sockfd, dst_ip, ttl, &start_time);
        
        if (packet_size == -1) {
            close(sockfd);
            return -1;
        }
        
        int reply_status = receive_icmp_reply(sockfd, dst_ip, packet_size, ttl, &rtt, bandwidth, &start_time);
        avg_rtt += rtt;
        if (rtt > max_rtt) {
            max_rtt = rtt;
        }
        if (reply_status == 1) {
            avg_rtt = avg_rtt / ttl;
            break; // We got reply from target host
        }

        
    }
    
    print_statistic(ttl, avg_rtt, max_rtt);



    close(sockfd);


    return 0;
}