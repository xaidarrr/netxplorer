#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <time.h>

#include "../include/network_utils.h"

#define PACKET_SIZE 64


// Create and send an ICMP Echo Request packet with the specified TTL
int send_icmp_request(int sockfd, char *dst_ip, int ttl, struct timespec *start_time)
{
    struct icmphdr icmp_hdr;

    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid(); // Progress ID
    icmp_hdr.un.echo.sequence = 1;  // Packet number
    icmp_hdr.checksum = checksum(&icmp_hdr, sizeof(icmp_hdr));

    struct sockaddr_in dst_addr_ipv4;
    dst_addr_ipv4.sin_family = AF_INET;
    dst_addr_ipv4.sin_port = 0;
    dst_addr_ipv4.sin_addr.s_addr = inet_addr(dst_ip);

    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    clock_gettime(CLOCK_MONOTONIC, start_time); // Sending time
    ssize_t sent_bytes = sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0,
                                (struct sockaddr *)&dst_addr_ipv4, sizeof(dst_addr_ipv4));

    if (sent_bytes < 0)
    {   
        fprintf(stderr, "\nFailure: Troubles with sending ICMP echo request\n\n");
        return -1;
    }

    return 0;
}

// Receiving ICMP Echo Reply or ICMP Time Exceeded
int receive_icmp_reply(int sockfd, char *dst_ip, int ttl,
                       double *rtt, struct timespec *start_time)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct timespec end_time;
    struct sockaddr_in recv_addr_ipv4;
    char buffer[PACKET_SIZE];
    struct icmphdr *icmp_header;

    struct timeval timeout = {2, 0}; // Timeout waiting for a response

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    ssize_t received_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&recv_addr_ipv4, &addr_len);

    clock_gettime(CLOCK_MONOTONIC, &end_time); // Response time

    if (received_bytes < 0)
    {
        print_output("* * *", 0, ttl, 0);
        return 0;
    }

    *rtt = ((end_time.tv_sec - start_time->tv_sec) * 1000 + (end_time.tv_nsec - start_time->tv_nsec) / 1e6);

    icmp_header = (struct icmphdr *)(buffer + sizeof(struct ip));

    if (icmp_header->type == ICMP_ECHOREPLY)
    {
        // Response received from the target host (ICMP Echo Reply)
        char *ip = inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr);
        print_output(ip, *rtt, ttl, 1);
        return 1;
    }
    else if (icmp_header->type == ICMP_TIME_EXCEEDED)
    {
        // Time Exceeded reply from an intermediate host
        char *ip = inet_ntoa(((struct sockaddr_in *)&recv_addr_ipv4)->sin_addr);
        print_output(ip, *rtt, ttl, 0);
        return 0;
    }
    else if (icmp_header->type == ICMP_ECHO) 
    {
        return -1;
    }
    else 
    {
        fprintf(stderr, "Received unexpected ICMP packet type: %d\n", icmp_header->type);
        return -2;
    }
}

// Function to perform ICMP route tracing
int icmp_trace(char *dst_ip, int is_fqdn, int max_hops, char *interface)
{
    double rtt;
    int ttl;
    double max_rtt = 0;
    struct timespec start_time;
    double avg_rtt = 0;

    // Creating a raw socket for ICMP
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0)
    {
        perror("Failure: troubles with creating socket");
        return -1;
    }

    // Set the network interface if specified by the user
    if (interface != NULL)
    {   
        if(set_interface(sockfd, interface) == NULL) {
            perror("\nFailure: It's impossible to set interface");
            return -1;
        }
    }

    // If the destination is an FQDN, convert it to an IP address
    if (is_fqdn == 1)
    {   
        dst_ip = get_ip_from_fqdn(dst_ip);
        if(dst_ip == NULL) {
            return -1;
        }
    }

    for (ttl = 1; ttl <= max_hops; ttl++)
    {
        // Sending ICMP request
        int sent_packet_status = send_icmp_request(sockfd, dst_ip, ttl, &start_time);

        if (sent_packet_status == -1)
        {   
            close(sockfd);
            return -1;
        }

        // Receiving ICMP reply
        int reply_status = receive_icmp_reply(sockfd, dst_ip, ttl, &rtt, &start_time);
        if (reply_status == -1) 
        {
            ttl -= 1;
        }
        else 
        {
            avg_rtt += rtt;

            // Update the maximum RTT value if the current RTT is greater
            if (rtt > max_rtt)
            {
                max_rtt = rtt;
            }
        }   
        // If a response is received from the target host (Echo Reply)
        if (reply_status == 1)
        {
            avg_rtt = avg_rtt / ttl;
            break;
        }
    }
    if (max_rtt == avg_rtt) 
    {
        avg_rtt == avg_rtt / max_hops;
    }

    // Display the statistics after the diagnostic is complete
    print_statistic(ttl, avg_rtt, max_rtt);

    close(sockfd);
    return 0;
}