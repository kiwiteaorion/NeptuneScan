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
#include "../include/scanner.h"
#include "../include/args.h"
#include "../include/ui.h"
#include "../include/config.h"
#include "../include/advanced_scan.h"
#include "../include/utils.h" // For get_timestamp
#include "../include/service_detection.h" // For service detection functions

// Color codes for terminal output
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_RESET "\x1b[0m"

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
    print_args_help();
    return 1;
  }

  // Print debug info
  printf("Target: %s\n", args.target);
  if (args.use_port_list) {
    printf("Ports to scan: ");
    for (int i = 0; i < args.port_list_size; i++) {
      printf("%d", args.port_list[i]);
      if (i < args.port_list_size - 1) {
        printf(",");
      }
    }
    printf("\n");
  } else if (args.port_range[0] != 0) {
    printf("Port range: %d-%d\n", args.port_range[0], args.port_range[1]);
  } else {
    printf("Using common ports\n");
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

    if (args.use_port_list)
    {
      // Scan specific ports from the list
      for (int i = 0; i < args.port_list_size; i++)
      {
        scan_port(args.target, args.port_list[i], args.scan_type);
      }
    }
    else if (args.port_range[0] != 0)
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

    if (args.use_port_list)
    {
      // Scan specific ports from the list
      for (int i = 0; i < args.port_list_size; i++)
      {
        scan_port(args.target, args.port_list[i], SCAN_CONNECT);
      }
    }
    else if (args.port_range[0] != 0)
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

  // Perform service detection if requested
  if (args.detect_services && num_open_ports > 0)
  {
    printf("\nPerforming service detection...\n\n");
    
    // Allocate array of ServiceInfo structures
    ServiceInfo *service_info_array = malloc(num_open_ports * sizeof(ServiceInfo));
    if (service_info_array)
    {
      // Detect services for each open port
      for (int i = 0; i < num_open_ports; i++)
      {
        // Initialize service info
        memset(&service_info_array[i], 0, sizeof(ServiceInfo));
        service_info_array[i].port = open_ports[i];
        
        // Detect service
        bool detected = detect_service(args.target, open_ports[i], &service_info_array[i]);
        
        if (args.verbose)
        {
          printf("Port %d: Service detection %s\n", 
                 open_ports[i], 
                 detected ? "successful" : "failed");
          if (detected)
          {
            printf("  Service: %s\n", 
                   service_info_array[i].service_name[0] ? 
                   service_info_array[i].service_name : "unknown");
            printf("  Protocol: %s\n", 
                   service_info_array[i].protocol[0] ? 
                   service_info_array[i].protocol : "unknown");
            printf("  Version: %s\n", 
                   service_info_array[i].version[0] ? 
                   service_info_array[i].version : "unknown");
          }
        }
      }
      
      // Print scan results header
      printf("\nScan Results for %s\n", args.target);
      printf("========================\n\n");
      
      if (num_open_ports == 0)
      {
        printf("No open ports found.\n");
      }
      else 
      {
        // Print header in Nmap-like format with version information
        printf("PORT      STATE   SERVICE          VERSION\n");
        printf("--------  -----   --------------   -------------------------\n");
        
        // Print each open port with its service and version information
        for (int i = 0; i < num_open_ports; i++)
        {
          int port = open_ports[i];
          
          // Print port with padding
          printf("%-8d  ", port);
          
          // Print state with color
          printf("%sOPEN%s    ", COLOR_GREEN, COLOR_RESET);
          
          // Print service name with padding
          const char *service = service_info_array[i].service_name[0] ? 
                       service_info_array[i].service_name : 
                       (get_service_name(port) ? get_service_name(port) : "unknown");
          printf("%-15s  ", service);
          
          // Print version info if available
          if (service_info_array[i].version[0]) {
            printf("%s%s", COLOR_CYAN, service_info_array[i].version);
            
            // Print protocol info if available
            if (service_info_array[i].protocol[0] && 
                !strstr(service, service_info_array[i].protocol) && 
                strcasecmp(service_info_array[i].protocol, "tcp") != 0) {
              printf(" (%s)", service_info_array[i].protocol);
            }
            
            printf("%s", COLOR_RESET);
          } else if (service_info_array[i].protocol[0] && 
                    strcasecmp(service_info_array[i].protocol, "tcp") != 0) {
            printf("(%s)", service_info_array[i].protocol);
          }
          
          printf("\n");
          
          // Print banner snippet in verbose mode, formatting it like Nmap
          if (args.verbose && service_info_array[i].banner[0]) {
            printf("| ");
            // Print first line of banner, cleaning up non-printable chars
            int line_length = 0;
            int max_length = 60; // Limit line length
            
            for (int j = 0; service_info_array[i].banner[j] && line_length < max_length; j++) {
              char c = service_info_array[i].banner[j];
              if (c == '\r' || c == '\n')
                break;  // Stop at first newline
                
              if (isprint(c)) {
                printf("%c", c);
                line_length++;
              } else {
                printf(".");  // Replace non-printable with dot
                line_length++;
              }
            }
            
            // Compare with the same type by using size_t
            size_t banner_len = strlen(service_info_array[i].banner);
            if (banner_len > (size_t)line_length)
              printf("...");  // Indicate truncation
              
            printf("\n");
          }
        }
      }
      
      // Free service info array
      free(service_info_array);
    }
    else
    {
      // Fall back to basic results if memory allocation failed
      print_results(args.target, open_ports, num_open_ports);
    }
  }
  else
  {
    // Print basic results without service detection
    print_results(args.target, open_ports, num_open_ports);
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

  // Print summary
  printf("\nNeptune Scan completed in %ld seconds. %d open ports found.\n", 
         duration, num_open_ports);

  // Cleanup
  cleanup_scanner();
  cleanup_args(&args);

#ifdef _WIN32
  WSACleanup();
#endif

  return 0;
}