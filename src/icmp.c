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


struct icmp_packet {
    struct icmphdr hdr;
    char payload[PACKET_SIZE];
};

// Calculating checksum for ipv4
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }

    

    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
        
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    result = ~sum;

    return htons(result);

}

// Sending ICMP echo request
int send_icmp_request(int sockfd, char *dst_ip, int family, int ttl) {
    struct icmp_packet packet;
    

    // ICMP header
    packet.hdr.type = ICMP_ECHO;
    packet.hdr.un.echo.id = getpid(); // Proccess id
    packet.hdr.un.echo.sequence = 1; // Sequence number

    strcpy(packet.payload, "ICMP request");
    packet.hdr.checksum = checksum(&packet, sizeof(packet));


    // IPv4
    if (family == AF_INET) {
        struct sockaddr_in dst_addr_ipv4;
        dst_addr_ipv4.sin_family = AF_INET;
        dst_addr_ipv4.sin_port = 0;
        dst_addr_ipv4.sin_addr.s_addr = inet_addr(dst_ip);
        
        // Setting TTL
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        // Sending packet
        ssize_t sent_bytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr_ipv4, sizeof(dst_addr_ipv4));

        if (sent_bytes < 0) {
            perror("Failure: Troubles with sending ICMP echo request");
            return -1;
        }
    
    // IPv6
    else if (family == AF_INET6) {
        struct sockaddr_in6 dst_addr_ipv6;
        struct sockaddr_in6 *dst_addr_ipv6_ptr = (struct sockaddr_in6*)&dst_addr_ipv6;
        inet_pton(AF_INET6, dst_ip, &(dst_addr_ipv6_ptr->sin6_addr));
        
        // Setting TTL
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));

        // Sending packet
        ssize_t sent_bytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst_addr_ipv6, sizeof(dst_addr_ipv6));

        if (sent_bytes < 0) {
            perror("Failure: Troubles with sending ICMP echo request");
            return -1;
            }

        }

    }

    return 0;
    

    

}

// Receiving ICMP echo reply or ICMP time exceeded
int receive_icmp_reply(int sockfd, char *dst_ip, int family, int ttl, double *rtt) {
    struct icmp_packet recv_packet;
    socklen_t addr_len;
    struct timespec start_time, end_time;
    struct sockaddr_in recv_addr_ipv4;
    struct sockaddr_in6 recv_addr_ipv6;


    if (family == AF_INET) {
        addr_len = sizeof(recv_addr_ipv4);
    }
    else if (family == AF_INET6) {
        addr_len = sizeof(recv_addr_ipv6);
    }

    // Start time
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    ssize_t received_bytes = recvfrom(sockfd, &recv_packet, sizeof(recv_packet), 0, 
                                    (struct sockaddr *)(family == AF_INET ? (struct sockaddr *)&recv_addr_ipv4 : (struct sockaddr *)&recv_addr_ipv6), &addr_len);

    if (received_bytes < 0) {
        perror("Failure: Troubles with receiving ICMP reply");
        return -1;
    }

    // End time
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    *rtt = (end_time.tv_sec - start_time.tv_sec) * 1000; // Time in miliseconds
    *rtt += (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0; // Adding rest of the nanoseconds

    if (recv_packet.hdr.type == ICMP_ECHOREPLY) {
        printf("Received ICMP Echo Reply from %s, RTT = %.3f ms\n", dst_ip, *rtt);
        return 1;
    }
    else if (recv_packet.hdr.type == ICMP_TIME_EXCEEDED) {
        if (family == AF_INET) {
            printf("TTL expired at %s, hop %d\n", inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr), ttl);
        }
        else if (family == AF_INET6) {
            printf("TTL expired at %s, hop %d\n", inet_ntop(AF_INET6, &recv_addr_ipv6.sin6_addr, dst_ip, INET6_ADDRSTRLEN), ttl);
        }
        return 0;  // Intermediate host, keep increasing TTL
    } 
    else {
        printf("Received unexpected ICMP packet type: %d\n", recv_packet.hdr.type);
        return -1;
}

}


// Main function
int icmp_trace(char *dst_ip, int family, char *type_addr, int max_hops) {
    double rtt;

    // Creating raw-socket (raw socket require sudo)
    int sockfd = socket(family, SOCK_RAW, (family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);

    if (sockfd < 0) {
        perror("Failure: troubles with creating socket");
        return -1;
    }

    // Convert FQDN to IPv4 or IPv6 if it is necessary
    if (type_addr == "FQDN") {
        char *fqdn = dst_ip;
        dst_ip = get_ip_from_fqdn(dst_ip);
        printf("Starting traceroute to %s (%s)\n", fqdn, dst_ip);
    }
    else {
        printf("Starting traceroute to %s\n", dst_ip);
    }

    for (int ttl = 1; ttl <= max_hops; ttl++) {
        printf("Hop %d:\n", ttl);

        if (send_icmp_request(sockfd, dst_ip, family, ttl) != 0) {
            close(sockfd);
            return -1;
        }
        int reply_status = receive_icmp_reply(sockfd, dst_ip, family, ttl, &rtt);
        if (reply_status == 1) {
            break; // We got reply from target host
        }

        
    }

    close(sockfd);
    

    return 0;
}