/**
 * Port Scanner - A simple network port scanner
 * main.c - Entry point for the application
 *
 * This file contains the main function that parses command line arguments
 * and initiates the port scanning process.
 */

#include <stdio.h>  // For input/output functions like printf
#include <stdlib.h> // For utility functions like atoi (ASCII to integer)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include "include/scanner.h" // Our custom scanner functionality
#include "include/config.h"  // Configuration constants

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

  // Print welcome message
  printf("Port Scanner v0.1\n");
  printf("=================\n\n");

  // Check if we have at least one argument (the target host)
  if (argc < 2)
  {
    // If not, print usage instructions and exit
    printf("Usage: %s <target_host> [start_port] [end_port]\n", argv[0]);
    return 1; // Return non-zero to indicate error
  }

  // Parse command line arguments
  char *target = argv[1]; // First argument is the target host

  // If start_port is provided, use it; otherwise use the default
  int start_port = (argc > 2) ? atoi(argv[2]) : DEFAULT_START_PORT;

  // If end_port is provided, use it; otherwise use the default
  int end_port = (argc > 3) ? atoi(argv[3]) : DEFAULT_END_PORT;

  // Inform the user about the scan parameters
  printf("Scanning %s from port %d to %d...\n\n", target, start_port, end_port);

  // Call the function that performs the actual port scanning
  scan_ports(target, start_port, end_port);

#ifdef _WIN32
  // Cleanup Winsock
  WSACleanup();
#endif

  return 0; // Return zero to indicate success
}