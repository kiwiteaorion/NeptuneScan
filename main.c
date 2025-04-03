/**
 * Neptune Scanner - A network port scanner
 * main.c - Entry point for the application
 *
 * This file contains the main function that parses command line arguments
 * and initiates the port scanning process.
 */

#include <stdio.h>                     // For input/output functions like printf
#include <stdlib.h>                    // For utility functions like atoi (ASCII to integer)
#include "include/scanner.h"           // Our custom scanner functionality
#include "include/config.h"            // Configuration constants
#include "include/ui.h"                // User interface functions
#include "include/args.h"              // Argument parsing functionality
#include "include/service_detection.h" // Service detection functionality

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

  // Parse command line arguments
  scan_config_t config;
  if (parse_args(argc, argv, &config) != 0)
  {
    return 1;
  }

  // Show banner
  show_banner();

  // Perform the scan based on configuration
  if (config.use_common_ports)
  {
    show_scanning_header(config.target, 0, 0);
    scan_common_ports(config.target);
  }
  else
  {
    show_scanning_header(config.target, config.start_port, config.end_port);
    scan_ports(config.target, config.start_port, config.end_port);
  }

  // If service detection is enabled, perform service detection on open ports
  if (config.detect_services)
  {
    printf("\nPerforming service detection...\n");
    ServiceInfo service_info;

    // Get list of open ports from the scanner
    int *open_ports = get_open_ports();
    int num_ports = get_num_open_ports();

    for (int i = 0; i < num_ports; i++)
    {
      if (detect_service(config.target, open_ports[i], &service_info))
      {
        printf("Port %d: %s (%s) - %s\n",
               service_info.port,
               service_info.service_name,
               service_info.protocol,
               service_info.version[0] ? service_info.version : "Version unknown");

        if (service_info.banner[0])
        {
          printf("Banner: %s\n", service_info.banner);
        }
      }
    }

    free(open_ports);
  }

#ifdef _WIN32
  // Cleanup Winsock
  WSACleanup();
#endif

  return 0;
}