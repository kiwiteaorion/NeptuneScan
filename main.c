/**
 * Port Scanner - A simple network port scanner
 * main.c - Entry point for the application
 *
 * This file contains the main function that parses command line arguments
 * and initiates the port scanning process.
 */

#include <stdio.h>           // For input/output functions like printf
#include <stdlib.h>          // For utility functions like atoi (ASCII to integer)
#include "include/scanner.h" // Our custom scanner functionality
#include "include/config.h"  // Configuration constants
#include "include/ui.h"      // User interface functions

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

/**
 * Main function - Entry point of the program
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on success, non-zero on error
 */
int main(int argc, char *argv[])
{
#ifdef _WIN32
  // Initialize Winsock
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
  {
    printf("WSAStartup failed\n");
    return 1;
  }
#endif

  // If no arguments provided, show banner and usage
  if (argc < 2)
  {
    show_banner();
    show_usage(argv[0]);
    return 1; // Return non-zero to indicate error
  }

  // Parse command line arguments
  char *target = argv[1];

  // Determine if we should use common ports or a specific range
  if (argc == 2)
  {
    // Only target specified, use common ports
    use_common_ports = 1;
    show_scanning_header(target, 0, 0);
    scan_common_ports(target);
  }
  else
  {
    // Specific port range provided
    use_common_ports = 0;
    int start_port = (argc > 2) ? atoi(argv[2]) : DEFAULT_START_PORT;
    int end_port = (argc > 3) ? atoi(argv[3]) : DEFAULT_END_PORT;
    show_scanning_header(target, start_port, end_port);
    scan_ports(target, start_port, end_port);
  }

#ifdef _WIN32
  // Cleanup Winsock
  WSACleanup();
#endif

  return 0; // Return zero to indicate success
}