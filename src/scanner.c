/**
 * Neptune Scanner - Network Port Scanner
 * scanner.c - Implementation of scanning functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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

// Thread arguments structure
typedef struct
{
  const char *target;
  int port;
  int *result;
  int timeout;
} scan_thread_args_t;

// Function to set socket to non-blocking mode
static int set_nonblocking(int sockfd)
{
#ifdef _WIN32
  unsigned long mode = 1;
  return ioctlsocket(sockfd, FIONBIO, &mode);
#else
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags == -1)
    return -1;
  return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
#endif
}

// Thread function to scan a single port
void *scan_port_thread(void *arg)
{
  scan_thread_args_t *args = (scan_thread_args_t *)arg;
  struct sockaddr_in addr;
  int sockfd;
  int result = 0;

  // Create socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    *args->result = 0;
    return NULL;
  }

  // Set non-blocking mode
  if (set_nonblocking(sockfd) < 0)
  {
    close(sockfd);
    *args->result = 0;
    return NULL;
  }

  // Setup address structure
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(args->port);

  // Resolve hostname if needed
  struct hostent *he = gethostbyname(args->target);
  if (he == NULL)
  {
    close(sockfd);
    *args->result = 0;
    return NULL;
  }
  memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

  // Attempt connection
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK)
    {
#else
    if (errno != EINPROGRESS)
    {
#endif
      close(sockfd);
      *args->result = 0;
      return NULL;
    }
  }

  // Setup select for timeout
  fd_set fdset;
  struct timeval tv;
  FD_ZERO(&fdset);
  FD_SET(sockfd, &fdset);
  tv.tv_sec = args->timeout / 1000;
  tv.tv_usec = (args->timeout % 1000) * 1000;

  // Wait for connection or timeout
  if (select(sockfd + 1, NULL, &fdset, NULL, &tv) > 0)
  {
    int so_error;
    socklen_t len = sizeof(so_error);
#ifdef _WIN32
    char optval[4];
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, optval, &len);
    so_error = *(int *)optval;
#else
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
#endif
    if (so_error == 0)
    {
      result = 1;
    }
  }

  close(sockfd);
  *args->result = result;
  return NULL;
}

int scan_ports(const char *target, int start_port, int end_port)
{
  int num_ports = end_port - start_port + 1;
  int *results = (int *)calloc(num_ports, sizeof(int));
  pthread_t *threads = (pthread_t *)malloc(num_ports * sizeof(pthread_t));
  scan_thread_args_t *args = (scan_thread_args_t *)malloc(num_ports * sizeof(scan_thread_args_t));
  int open_ports = 0;

  // Create threads for each port
  for (int i = 0; i < num_ports; i++)
  {
    args[i].target = target;
    args[i].port = start_port + i;
    args[i].result = &results[i];
    args[i].timeout = DEFAULT_TIMEOUT;
    pthread_create(&threads[i], NULL, scan_port_thread, &args[i]);
  }

  // Wait for all threads to complete
  for (int i = 0; i < num_ports; i++)
  {
    pthread_join(threads[i], NULL);
    if (results[i])
    {
      printf("Port %d is open\n", start_port + i);
      open_ports++;
    }
  }

  free(results);
  free(threads);
  free(args);
  return open_ports;
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