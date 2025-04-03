/**
 * Neptune Scanner - Network Port Scanner
 * scanner.c - Implementation of scanning functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define close closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include "../include/scanner.h"
#include "../include/config.h"
#include "../include/utils.h"
#include "../include/advanced_scan.h"

// Static variables for tracking open ports
static int *open_ports = NULL;
static int num_open_ports = 0;
static pthread_mutex_t open_ports_mutex = PTHREAD_MUTEX_INITIALIZER;

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

// Common ports to scan
static const int COMMON_PORTS_TO_SCAN[MAX_COMMON_PORTS] = {
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    25,   // SMTP
    53,   // DNS
    80,   // HTTP
    110,  // POP3
    143,  // IMAP
    443,  // HTTPS
    445,  // SMB
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    5900, // VNC
    8080, // HTTP Proxy
    8443  // HTTPS Alternative
};

// Thread arguments structure
typedef struct
{
  const char *target;
  int port;
  int *result;
  int timeout;
  scan_type_t scan_type;
} scan_thread_args_t;

// Forward declaration of is_port_open_connect
int is_port_open_connect(const char *target, int port);

/**
 * Gets a list of all open ports found during the scan.
 * The caller is responsible for freeing the returned array.
 *
 * @return A dynamically allocated array of open ports
 */
int *get_open_ports(void)
{
  pthread_mutex_lock(&open_ports_mutex);

  if (num_open_ports == 0)
  {
    pthread_mutex_unlock(&open_ports_mutex);
    return NULL;
  }

  // Allocate memory for the copy
  int *ports_copy = malloc(num_open_ports * sizeof(int));
  if (!ports_copy)
  {
    pthread_mutex_unlock(&open_ports_mutex);
    return NULL;
  }

  // Copy the ports
  memcpy(ports_copy, open_ports, num_open_ports * sizeof(int));

  pthread_mutex_unlock(&open_ports_mutex);
  return ports_copy;
}

/**
 * Gets the number of open ports found during the scan.
 *
 * @return The number of open ports
 */
int get_num_open_ports(void)
{
  pthread_mutex_lock(&open_ports_mutex);
  int count = num_open_ports;
  pthread_mutex_unlock(&open_ports_mutex);
  return count;
}

/**
 * Adds a port to the list of open ports.
 * This function is for internal use by the scanner.
 *
 * @param port The port number to add
 * @return 0 on success, -1 if the list is full
 */
int add_open_port(int port)
{
  pthread_mutex_lock(&open_ports_mutex);

  // Reallocate memory for the new port
  int *new_ports = realloc(open_ports, (num_open_ports + 1) * sizeof(int));
  if (!new_ports)
  {
    pthread_mutex_unlock(&open_ports_mutex);
    return 0;
  }

  open_ports = new_ports;
  open_ports[num_open_ports++] = port;

  pthread_mutex_unlock(&open_ports_mutex);
  return 1;
}

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
 * @param scan_type The type of scan to perform
 */
void scan_common_ports(const char *target, scan_type_t scan_type)
{
  printf("Scanning %d common ports on %s...\n\n", MAX_COMMON_PORTS, target);

  // Loop through each common port
  for (int i = 0; i < MAX_COMMON_PORTS; i++)
  {
    int port = COMMON_PORTS_TO_SCAN[i];
    if (is_port_open(target, port, scan_type))
    {
      printf("Port %d is open\n", port);
      add_open_port(port);
    }
  }
}

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

/**
 * Checks if a specific port is open on the target host.
 *
 * @param target The hostname or IP address to check
 * @param port The port number to check
 * @param scan_type The type of scan to perform (TCP connect, SYN, etc.)
 * @return 1 if the port is open, 0 if closed or error
 */
int is_port_open(const char *target, int port, scan_type_t scan_type)
{
  switch (scan_type)
  {
  case SCAN_SYN:
    return tcp_syn_scan(target, port, DEFAULT_TIMEOUT) ? 1 : 0;
  case SCAN_FIN:
    return tcp_custom_scan(target, port, TCP_FIN, DEFAULT_TIMEOUT) ? 1 : 0;
  case SCAN_XMAS:
    return tcp_custom_scan(target, port, TCP_FIN | TCP_URG | TCP_PSH, DEFAULT_TIMEOUT) ? 1 : 0;
  case SCAN_NULL:
    return tcp_custom_scan(target, port, 0, DEFAULT_TIMEOUT) ? 1 : 0;
  case SCAN_ACK:
    return tcp_custom_scan(target, port, TCP_ACK, DEFAULT_TIMEOUT) ? 1 : 0;
  default:
    // Default to TCP connect scan
    return is_port_open_connect(target, port);
  }
}

/**
 * Scans a range of ports on the specified target host.
 *
 * @param target The hostname or IP address to scan
 * @param start_port The first port to scan
 * @param end_port The last port to scan
 * @param scan_type The type of scan to perform
 */
void scan_ports(const char *target, int start_port, int end_port, scan_type_t scan_type)
{
  int num_ports = end_port - start_port + 1;
  int *results = (int *)malloc(num_ports * sizeof(int));
  scan_thread_args_t *args = (scan_thread_args_t *)malloc(num_ports * sizeof(scan_thread_args_t));
  pthread_t *threads = (pthread_t *)malloc(num_ports * sizeof(pthread_t));

  // Initialize thread arguments
  for (int i = 0; i < num_ports; i++)
  {
    args[i].target = target;
    args[i].port = start_port + i;
    args[i].result = &results[i];
    args[i].timeout = DEFAULT_TIMEOUT;
    args[i].scan_type = scan_type;
  }

  // Create threads
  for (int i = 0; i < num_ports; i++)
  {
    pthread_create(&threads[i], NULL, scan_port_thread, &args[i]);
  }

  // Wait for threads to complete
  for (int i = 0; i < num_ports; i++)
  {
    pthread_join(threads[i], NULL);
    if (results[i] == 1)
    {
      printf("Port %d is open\n", start_port + i);
      add_open_port(start_port + i);
    }
  }

  free(results);
  free(args);
  free(threads);
}

// Function to initialize the scanner
bool init_scanner(void)
{
  // Initialize the open ports list
  open_ports = NULL;
  num_open_ports = 0;

  return true;
}

// Function to cleanup the scanner
void cleanup_scanner(void)
{
  pthread_mutex_lock(&open_ports_mutex);

  if (open_ports)
  {
    free(open_ports);
    open_ports = NULL;
  }
  num_open_ports = 0;

  pthread_mutex_unlock(&open_ports_mutex);
}

/**
 * Performs a TCP connect scan on a specific port.
 *
 * @param target The hostname or IP address to scan
 * @param port The port to check
 * @return 1 if the port is open, 0 if closed or error
 */
int is_port_open_connect(const char *target, int port)
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    return 0;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  struct hostent *he = gethostbyname(target);
  if (he == NULL)
  {
    close(sockfd);
    return 0;
  }

  memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

  // Set socket to non-blocking
  set_nonblocking(sockfd);

  // Try to connect
  int result = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
  if (result < 0)
  {
#ifdef _WIN32
    if (WSAGetLastError() == WSAEWOULDBLOCK)
#else
    if (errno == EINPROGRESS)
#endif
    {
      // Connection in progress, wait for it
      struct timeval tv;
      tv.tv_sec = DEFAULT_TIMEOUT / 1000;
      tv.tv_usec = (DEFAULT_TIMEOUT % 1000) * 1000;

      fd_set writefds;
      FD_ZERO(&writefds);
      FD_SET(sockfd, &writefds);

      result = select(sockfd + 1, NULL, &writefds, NULL, &tv);
      if (result > 0)
      {
#ifdef _WIN32
        char error = 0;
        int len = sizeof(error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error == 0)
#else
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error == 0)
#endif
        {
          close(sockfd);
          return 1; // Port is open
        }
      }
    }
  }
  else
  {
    close(sockfd);
    return 1; // Port is open
  }

  close(sockfd);
  return 0; // Port is closed or error occurred
}