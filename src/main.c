#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "scanner.h"
#include "args.h"
#include "ui.h"
#include "config.h"
#include "advanced_scan.h"
#include "utils.h" // For get_timestamp

int main(int argc, char *argv[])
{
  // Initialize Winsock on Windows
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
  {
    print_error("WSAStartup failed");
    return 1;
  }
#endif

  // Parse command line arguments
  Args args;
  if (!parse_args(argc, argv, &args))
  {
    print_help();
    return 1;
  }

  // Initialize scanner
  if (!init_scanner())
  {
    print_error("Failed to initialize scanner");
    return 1;
  }

  // Print header
  print_header();

  // Get start time
  long start_time = get_timestamp();

  // Perform scan based on arguments
  if (args.scan_type == SCAN_SYN || args.scan_type == SCAN_FIN ||
      args.scan_type == SCAN_XMAS || args.scan_type == SCAN_NULL ||
      args.scan_type == SCAN_ACK)
  {
    // Advanced scanning techniques
    printf("Performing %s scan on %s...\n",
           scan_type_to_string(args.scan_type), args.target);

    if (args.port_range[0] != 0)
    {
      scan_ports(args.target, args.port_range[0], args.port_range[1], args.scan_type);
    }
    else
    {
      scan_common_ports(args.target, args.scan_type);
    }
  }
  else
  {
    // Default TCP connect scan
    printf("Performing TCP connect scan on %s...\n", args.target);

    if (args.port_range[0] != 0)
    {
      scan_ports(args.target, args.port_range[0], args.port_range[1], SCAN_CONNECT);
    }
    else
    {
      scan_common_ports(args.target, SCAN_CONNECT);
    }
  }

  // Get end time and calculate duration
  long end_time = get_timestamp();
  long duration = end_time - start_time;

  // Get open ports
  int *open_ports = get_open_ports();
  int num_open_ports = get_num_open_ports();

  // Print results
  print_results(args.target, open_ports, num_open_ports);

  // Print service information for each open port
  for (int i = 0; i < num_open_ports; i++)
  {
    const char *service_name = get_service_name(open_ports[i]);
    const char *service_desc = get_service_description(open_ports[i]);
    print_service_info(open_ports[i], service_name, service_desc);
  }

  // Perform OS detection if requested
  if (args.detect_os)
  {
    char os_info[256];
    if (detect_os(args.target, os_info, sizeof(os_info)))
    {
      print_os_info(os_info);
    }
    else
    {
      print_warning("OS detection failed or inconclusive");
    }
  }

  // Print scan summary
  print_scan_summary(args.target, num_open_ports, duration);

  // Cleanup
  cleanup_scanner();
  free(open_ports);

#ifdef _WIN32
  WSACleanup();
#endif

  return 0;
}