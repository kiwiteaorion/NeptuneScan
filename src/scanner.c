/**
 * Port Scanner - A simple network port scanner
 * scanner.c - Scanner functionality implementation
 *
 * This file implements the functions for scanning ports on a target host.
 */

#include <stdio.h>  // For input/output functions
#include <string.h> // For string manipulation functions

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// Windows doesn't need these headers
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#endif

#include "../include/scanner.h"
#include "../include/config.h"
#include "../include/utils.h"

// Array of common services for port identification
typedef struct
{
  int port;
  const char *service;
  const char *description;
} PortInfo;

// Common port information
static const PortInfo PORT_INFO[] = {
    {20, "FTP-DATA", "File Transfer Protocol (Data)"},
    {21, "FTP", "File Transfer Protocol (Control)"},
    {22, "SSH", "Secure Shell"},
    {23, "TELNET", "Telnet protocol"},
    {25, "SMTP", "Simple Mail Transfer Protocol"},
    {53, "DNS", "Domain Name System"},
    {80, "HTTP", "Hypertext Transfer Protocol"},
    {110, "POP3", "Post Office Protocol v3"},
    {143, "IMAP", "Internet Message Access Protocol"},
    {443, "HTTPS", "HTTP Secure"},
    {445, "SMB", "Server Message Block"},
    {3306, "MYSQL", "MySQL Database"},
    {3389, "RDP", "Remote Desktop Protocol"},
    {5432, "POSTGRESQL", "PostgreSQL Database"},
    {8080, "HTTP-ALT", "Alternative HTTP Port"},
    // Add more common ports as needed
    {0, NULL, NULL} // Sentinel value to mark the end of the array
};

/**
 * Gets service information for a specific port
 *
 * @param port The port number
 * @return A pointer to the service name or "Unknown" if not found
 */
const char *get_service_name(int port)
{
  for (int i = 0; PORT_INFO[i].service != NULL; i++)
  {
    if (PORT_INFO[i].port == port)
    {
      return PORT_INFO[i].service;
    }
  }
  return "Unknown";
}

/**
 * Gets service description for a specific port
 *
 * @param port The port number
 * @return A pointer to the service description or "Unknown service" if not found
 */
const char *get_service_description(int port)
{
  for (int i = 0; PORT_INFO[i].description != NULL; i++)
  {
    if (PORT_INFO[i].port == port)
    {
      return PORT_INFO[i].description;
    }
  }
  return "Unknown service";
}

/**
 * Scans common ports on the specified target host.
 *
 * @param target The hostname or IP address to scan
 * @return The number of open ports found
 */
int scan_common_ports(const char *target)
{
  int open_count = 0;               // Counter for open ports
  int open_ports[MAX_COMMON_PORTS]; // Array to store open ports

  printf("Scanning %d common ports on %s...\n\n", MAX_COMMON_PORTS, target);

  // Loop through each common port
  for (int i = 0; i < MAX_COMMON_PORTS; i++)
  {
    int port = COMMON_PORTS_TO_SCAN[i];

    // Check if the current port is open
    if (is_port_open(target, port))
    {
      open_ports[open_count] = port; // Store the open port
      open_count++;                  // Increment the counter of open ports
    }
  }

  // Print results in a nice table format
  if (open_count > 0)
  {
    printf("PORT     STATE   SERVICE    DESCRIPTION\n");
    printf("-------- ------- ---------- ------------------------------------------\n");

    for (int i = 0; i < open_count; i++)
    {
      int port = open_ports[i];
      printf("%-8d OPEN    %-10s %s\n",
             port,
             get_service_name(port),
             get_service_description(port));
    }
  }
  else
  {
    printf("No open ports found.\n");
  }

  // Print summary
  printf("\nScan completed: %d open ports found out of %d common ports scanned.\n",
         open_count, MAX_COMMON_PORTS);

  return open_count;
}

/**
 * Scans a range of ports on the specified target host.
 *
 * @param target The hostname or IP address to scan
 * @param start_port The first port to scan
 * @param end_port The last port to scan
 * @return The number of open ports found
 */
int scan_ports(const char *target, int start_port, int end_port)
{
  int open_count = 0;                          // Counter for open ports
  int total_ports = end_port - start_port + 1; // Total number of ports to scan
  int open_ports[1000];                        // Array to store open ports

  // Validate port range
  if (start_port < 1 || end_port > 65535 || start_port > end_port)
  {
    printf("Error: Invalid port range. Valid ports are 1-65535.\n");
    return -1;
  }

  printf("Scanning %d ports on %s...\n\n", total_ports, target);

  // Loop through each port in the specified range
  for (int port = start_port; port <= end_port; port++)
  {
    if (is_port_open(target, port))
    {
      open_ports[open_count] = port;
      open_count++;
    }
  }

  // Print results in a nice table format
  if (open_count > 0)
  {
    printf("PORT     STATE   SERVICE    DESCRIPTION\n");
    printf("-------- ------- ---------- ------------------------------------------\n");

    for (int i = 0; i < open_count; i++)
    {
      int port = open_ports[i];
      printf("%-8d OPEN    %-10s %s\n",
             port,
             get_service_name(port),
             get_service_description(port));
    }
  }
  else
  {
    printf("No open ports found.\n");
  }

  printf("\nScan completed: %d open ports found out of %d ports scanned.\n",
         open_count, total_ports);

  return open_count;
}

/**
 * Checks if a specific port is open on the target host.
 *
 * @param target The hostname or IP address to check
 * @param port The port number to check
 * @return 1 if the port is open, 0 if closed or error
 */
int is_port_open(const char *target, int port)
{
  struct sockaddr_in server_addr;
  struct hostent *host;
  SOCKET sock;
  int status;

  // Create a socket
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET)
  {
    printf("Socket creation failed\n");
    return 0;
  }

// Set socket to non-blocking mode
#ifdef _WIN32
  u_long mode = 1;
  ioctlsocket(sock, FIONBIO, &mode);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

  // Initialize server address
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  // Convert hostname to IP address
  if (inet_addr(target) != INADDR_NONE)
  {
    server_addr.sin_addr.s_addr = inet_addr(target);
  }
  else
  {
    host = gethostbyname(target);
    if (!host)
    {
#ifdef _WIN32
      closesocket(sock);
#else
      close(sock);
#endif
      return 0;
    }
    memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);
  }

  // Attempt to connect
  status = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

#ifdef _WIN32
  if (status == SOCKET_ERROR)
  {
    if (WSAGetLastError() == WSAEWOULDBLOCK)
    {
      // Connection in progress
      fd_set write_fds;
      struct timeval timeout;

      FD_ZERO(&write_fds);
      FD_SET(sock, &write_fds);

      timeout.tv_sec = CONNECT_TIMEOUT;
      timeout.tv_usec = 0;

      status = select(0, NULL, &write_fds, NULL, &timeout);

      if (status > 0)
      {
        closesocket(sock);
        return 1; // Port is open
      }
    }
  }
  else if (status == 0)
  {
    closesocket(sock);
    return 1; // Port is open
  }

  closesocket(sock);
#else
  if (status < 0 && errno == EINPROGRESS)
  {
    // Set up for select() to wait for connection
    struct timeval timeout;
    fd_set fdset;

    timeout.tv_sec = CONNECT_TIMEOUT;
    timeout.tv_usec = 0;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    // Wait for the socket to become writable (connection established)
    // or for timeout to expire
    status = select(sock + 1, NULL, &fdset, NULL, &timeout);

    // Check if select() succeeded and socket is writable
    if (status > 0 && FD_ISSET(sock, &fdset))
    {
      // Check if there was an error with the connection
      int so_error;
      socklen_t len = sizeof(so_error);
      getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

      if (so_error == 0)
      {
        close(sock);
        return 1; // Port is open
      }
    }
  }
  else if (status == 0)
  {
    // Immediate success (rare with non-blocking sockets)
    close(sock);
    return 1; // Port is open
  }

  close(sock);
#endif

  return 0; // Port is closed or error occurred
}