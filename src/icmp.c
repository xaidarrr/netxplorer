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



// Calculating checksum for ipv4
unsigned short checksum(void *b, int len) {     
    unsigned short *buf = (unsigned short *)b; 
    unsigned int sum = 0; 
    unsigned short result; 
 
    for (sum = 0; len > 1; len -= 2) 
        sum += *buf++; 
    if (len == 1) 
        sum += *(unsigned char *)buf; 
     
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
} 

// Sending ICMP echo request
int send_icmp_request(int sockfd, char *dst_ip, int ttl) {
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
        
        
    // Sending packet
    ssize_t sent_bytes = sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&dst_addr_ipv4, sizeof(dst_addr_ipv4));

    if (sent_bytes < 0) {
        perror("Failure: Troubles with sending ICMP echo request");
        return -1;
    }


    return sent_bytes;
    
   
}

// Receiving ICMP echo reply or ICMP time exceeded
int receive_icmp_reply(int sockfd, char *dst_ip, int sent_packet_size, int ttl, double *rtt, bool bandwidth) {
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct timespec start_time, end_time;
    struct sockaddr_in recv_addr_ipv4;
    char buffer[PACKET_SIZE];
    struct icmphdr *icmp_header;



    // Start time
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    ssize_t received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                                    (struct sockaddr *)(struct sockaddr *)&recv_addr_ipv4, &addr_len);

    if (received_bytes < 0) {
        perror("Failure: Troubles with receiving ICMP reply");
        return -1;
    }

    // End time
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    *rtt = (end_time.tv_sec - start_time.tv_sec) * 1000; // Time in miliseconds
    *rtt += (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0; // Adding rest of the nanoseconds

    icmp_header = (struct icmphdr *)(buffer + sizeof(struct ip));

    if (icmp_header->type == ICMP_ECHOREPLY) {
        // Intermediate host's IP
        char *itr_ip = inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr);
        // Intermediate host's FQDN
        char *itr_fqdn = get_fqdn_from_ip(itr_ip);

        if (bandwidth) {
            // Calculating estimated bandwidth
            double bandwidth = sent_packet_size / (*rtt / 1000.0); // bytes per second

            printf("%-8d %-15.3f %-20.3f %s (%s) \n", ttl, *rtt, bandwidth, itr_fqdn, itr_ip);
        }
        else {
            printf("%-8d %-15.3f %s (%s) \n", ttl, *rtt, itr_fqdn, itr_ip);
        }
        
        return 1;
    }
    else if (icmp_header->type == ICMP_TIME_EXCEEDED) {
        // Intermediate host's IP
        char *itr_ip = inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr);
        // Intermediate host's FQDN
        char *itr_fqdn = get_fqdn_from_ip(itr_ip);
        if (bandwidth) {
            // Calculating estimated bandwidth
            double bandwidth = sent_packet_size / (*rtt / 1000.0); // bytes per second

            printf("%-8d %-15.3f %-20.3f %s (%s) \n", ttl, *rtt, bandwidth, itr_fqdn, itr_ip);
        }
        else {
            printf("%-8d %-15.3f %s (%s) \n", ttl, *rtt, itr_fqdn, itr_ip);
        }
        return 0;  // Intermediate host, keep increasing TTL
    } 
    else {
        printf("Received unexpected ICMP packet type: %d\n", icmp_header->type);
        return -1;
}

}


// Main function
int icmp_trace(char *dst_ip, bool is_fqdn, int max_hops, bool bandwidth) {
    double rtt;
    // Creating raw-socket (raw socket require sudo)
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        perror("Failure: troubles with creating socket");
        return -1;
    }
    // Convert FQDN to IPv4 if it is necessary
    if (is_fqdn) {
        char *fqdn = dst_ip;
        dst_ip = get_ip_from_fqdn(dst_ip);
    }
    if (bandwidth)
        printf("%-8s %-14s %-30s %s\n", "Hop", "RTT(ms)", "Bandwidth(bps)", "Address / FQDN");
    else
        printf("%-8s %-22s %s\n", "Hop", "RTT(ms)", "Address / FQDN");
    printf("-----------------------------------------------------------------------------------------\n");
    for (int ttl = 1; ttl <= max_hops; ttl++) {
        
        int packet_size = send_icmp_request(sockfd, dst_ip, ttl);
        
        if (packet_size == -1) {
            close(sockfd);
            return -1;
        }
        
        int reply_status = receive_icmp_reply(sockfd, dst_ip, packet_size, ttl, &rtt, bandwidth);
        if (reply_status == 1) {
            break; // We got reply from target host
        }

        
    }

    close(sockfd);


    return 0;
}