#ifndef ADVANCED_SCAN_H
#define ADVANCED_SCAN_H

#include <stdbool.h>
#include <stdint.h>

// TCP flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// Scan types
typedef enum
{
  SCAN_CONNECT, // TCP connect scan
  SCAN_SYN,     // TCP SYN scan
  SCAN_FIN,     // TCP FIN scan
  SCAN_XMAS,    // TCP XMAS scan
  SCAN_NULL,    // TCP NULL scan
  SCAN_ACK,     // TCP ACK scan
  SCAN_WINDOW,  // TCP Window scan
  SCAN_MAIMON   // TCP Maimon scan
} scan_type_t;

// IP header structure
typedef struct
{
  uint8_t version : 4; // Version
  uint8_t ihl : 4;     // Internet header length
  uint8_t tos;         // Type of service
  uint16_t tot_len;    // Total length
  uint16_t id;         // Identification
  uint16_t frag_off;   // Fragment offset
  uint8_t ttl;         // Time to live
  uint8_t protocol;    // Protocol
  uint16_t check;      // Checksum
  uint32_t saddr;      // Source address
  uint32_t daddr;      // Destination address
} ip_header_t;

// TCP header structure
typedef struct
{
  uint16_t source;       // Source port
  uint16_t dest;         // Destination port
  uint32_t seq;          // Sequence number
  uint32_t ack_seq;      // Acknowledgment number
  uint8_t doff : 4;      // Data offset
  uint8_t reserved : 4;  // Reserved bits
  uint8_t fin : 1;       // FIN flag
  uint8_t syn : 1;       // SYN flag
  uint8_t rst : 1;       // RST flag
  uint8_t psh : 1;       // PSH flag
  uint8_t ack : 1;       // ACK flag
  uint8_t urg : 1;       // URG flag
  uint8_t reserved2 : 2; // Reserved bits
  uint16_t window;       // Window size
  uint16_t check;        // Checksum
  uint16_t urg_ptr;      // Urgent pointer
} tcp_header_t;

// Function declarations
bool tcp_syn_scan(const char *target, int port, int timeout);
bool tcp_custom_scan(const char *target, int port, uint8_t flags, int timeout);
bool detect_os(const char *target, char *os_info, size_t os_info_size);

#endif /* ADVANCED_SCAN_H */