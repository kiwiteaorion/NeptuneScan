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
  int open_count = 0; // Counter for open ports

  // Validate port range
  if (start_port < 1 || end_port > 65535 || start_port > end_port)
  {
    printf("Error: Invalid port range. Valid ports are 1-65535.\n");
    return -1;
  }

  printf("Port\tState\n");
  printf("----\t-----\n");

  // Loop through each port in the specified range
  for (int port = start_port; port <= end_port; port++)
  {
    // Check if the current port is open
    if (is_port_open(target, port))
    {
      printf("%d\tOPEN\n", port);
      open_count++; // Increment the counter of open ports
    }
  }

  // Print summary
  printf("\nScan completed: %d open ports found.\n", open_count);

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