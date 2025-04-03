/**
 * Port Scanner - A simple network port scanner
 * advanced_scan.c - Advanced scanning techniques implementation
 *
 * This file implements advanced scanning techniques like TCP SYN scanning
 * and OS detection.
 */

#include "advanced_scan.h"
#include "scanner.h"
#include "scan_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#ifdef _WIN32
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

// Function to calculate TCP checksum
unsigned short tcp_checksum(unsigned short *ptr, int nbytes)
{
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;
  while (nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1)
  {
    oddbyte = 0;
    *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short)~sum;

  return answer;
}

// Function to calculate IP checksum
unsigned short ip_checksum(unsigned short *ptr, int nbytes)
{
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;
  while (nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1)
  {
    oddbyte = 0;
    *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short)~sum;

  return answer;
}

// Function to perform TCP SYN scan
bool tcp_syn_scan(const char *target, int port, int timeout)
{
#ifdef _WIN32
  SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
  if (sock == INVALID_SOCKET)
  {
    return false;
  }
#else
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0)
  {
    return false;
  }
#endif

  // Set socket options
  int one = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0)
  {
    close(sock);
    return false;
  }

  // Create packet
  char packet[sizeof(ip_header_t) + sizeof(tcp_header_t)];
  memset(packet, 0, sizeof(packet));

  // Fill IP header
  ip_header_t *ip = (ip_header_t *)packet;
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = htons(sizeof(packet));
  ip->id = htons(54321);
  ip->frag_off = 0;
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  ip->check = 0;
  ip->saddr = inet_addr("127.0.0.1");
  ip->daddr = inet_addr(target);

  // Fill TCP header
  tcp_header_t *tcp = (tcp_header_t *)(packet + sizeof(ip_header_t));
  tcp->source = htons(54321);
  tcp->dest = htons(port);
  tcp->seq = htonl(12345);
  tcp->ack_seq = 0;
  tcp->doff = 5;
  tcp->syn = 1;
  tcp->window = htons(5840);
  tcp->check = 0;
  tcp->urg_ptr = 0;

  // Calculate checksums
  tcp->check = tcp_checksum((unsigned short *)tcp, sizeof(tcp_header_t));
  ip->check = ip_checksum((unsigned short *)ip, sizeof(ip_header_t));

  // Send packet
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr(target);
  dest.sin_port = htons(port);

  if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
  {
    close(sock);
    return false;
  }

  // Wait for response
  struct timeval tv;
  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(sock, &readfds);

  if (select(sock + 1, &readfds, NULL, NULL, &tv) > 0)
  {
    char response[1024];
    int bytes = recv(sock, response, sizeof(response), 0);
    if (bytes > 0)
    {
      ip_header_t *resp_ip = (ip_header_t *)response;
      tcp_header_t *resp_tcp = (tcp_header_t *)(response + (resp_ip->ihl * 4));
      if (resp_tcp->syn && resp_tcp->ack)
      {
        close(sock);
        return true;
      }
    }
  }

  close(sock);
  return false;
}

// Function to perform custom TCP scan
bool tcp_custom_scan(const char *target, int port, uint8_t flags, int timeout)
{
  // Implementation similar to tcp_syn_scan but with custom flags
  // For now, just return false as this is a placeholder
  (void)target;
  (void)port;
  (void)flags;
  (void)timeout;
  return false;
}

// Function to detect OS
bool detect_os(const char *target, char *os_info, size_t os_info_size)
{
  // Simple OS detection based on TCP/IP stack fingerprinting
  // For now, just return a generic response
  (void)target;
  snprintf(os_info, os_info_size, "Unknown OS (TCP/IP stack fingerprinting not implemented)");
  return true;
}