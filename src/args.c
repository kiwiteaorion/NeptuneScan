/**
 * Neptune Scanner - Command Line Argument Handling
 * args.c - Implementation of argument parsing
 */

#include "args.h"
#include "scanner.h"
#include "scan_utils.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

// Default values
#define DEFAULT_TIMEOUT 1000 // 1 second timeout
#define DEFAULT_START_PORT 1
#define DEFAULT_END_PORT 1024

// Version information
#define VERSION "3.0.0"

void print_usage(void)
{
  printf("Usage: neptunescan [options] target\n\n");
  printf("Options:\n");
  printf("  -p <start>-<end>  Port range to scan\n");
  printf("  -sS              TCP SYN scan\n");
  printf("  -sF              TCP FIN scan\n");
  printf("  -sX              TCP XMAS scan\n");
  printf("  -sN              TCP NULL scan\n");
  printf("  -sA              TCP ACK scan\n");
  printf("  -O               Enable OS detection\n");
  printf("  -v               Verbose output\n");
  printf("  -h               Show this help message\n\n");
  printf("Examples:\n");
  printf("  neptunescan localhost              # Scan common ports\n");
  printf("  neptunescan -p 80-443 example.com  # Scan specific port range\n");
  printf("  neptunescan -sS -O 192.168.1.1    # SYN scan with OS detection\n");
}

/**
 * Parse command line arguments
 *
 * @param argc Number of arguments
 * @param argv Array of argument strings
 * @param args Pointer to Args structure to fill
 * @return true if parsing successful, false otherwise
 */
bool parse_args(int argc, char *argv[], Args *args)
{
  // Initialize default values
  memset(args, 0, sizeof(Args));
  args->scan_type = SCAN_CONNECT;
  args->port_list = NULL;
  args->port_list_size = 0;
  args->use_port_list = false;

  // Need at least one argument (the target)
  if (argc < 2)
  {
    return false;
  }

  // Loop through arguments
  for (int i = 1; i < argc; i++)
  {
    if (argv[i][0] == '-')
    {
      // Handle options
      if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
      {
        show_help(argv[0]);
        exit(0);
      }
      else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
      {
        args->verbose = true;
      }
      else if (strcmp(argv[i], "--version") == 0)
      {
        show_version();
        exit(0);
      }
      else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
      {
        // Parse port range: -p <start>-<end> or -p <port> or -p <port1,port2,port3,...>
        char *port_arg = argv[++i];
        
        // Check if it's a list of ports (contains comma)
        if (strchr(port_arg, ',') != NULL)
        {
          // It's a list of ports
          args->use_port_list = true;
          
          // Count the number of ports in the list
          int port_count = 1;  // Start with 1 for the first port
          for (char *c = port_arg; *c; c++)
          {
            if (*c == ',')
            {
              port_count++;
            }
          }
          
          // Allocate memory for the port list
          args->port_list = (int *)malloc(port_count * sizeof(int));
          if (!args->port_list)
          {
            fprintf(stderr, "Memory allocation error\n");
            return false;
          }
          
          // Parse the ports
          char *token = strtok(port_arg, ",");
          int index = 0;
          
          while (token != NULL && index < port_count)
          {
            args->port_list[index++] = atoi(token);
            token = strtok(NULL, ",");
          }
          
          args->port_list_size = index;
        }
        else
        {
          // Check if it's a range (contains dash)
          char *dash = strchr(port_arg, '-');
          if (dash)
          {
            // Range of ports
            *dash = '\0';
            args->port_range[0] = atoi(port_arg);
            args->port_range[1] = atoi(dash + 1);
          }
          else
          {
            // Single port
            args->port_range[0] = atoi(port_arg);
            args->port_range[1] = args->port_range[0];
          }
          args->use_port_list = false;
        }
      }
      else if (strcmp(argv[i], "-sS") == 0)
      {
        args->scan_type = SCAN_SYN;
      }
      else if (strcmp(argv[i], "-sF") == 0)
      {
        args->scan_type = SCAN_FIN;
      }
      else if (strcmp(argv[i], "-sX") == 0)
      {
        args->scan_type = SCAN_XMAS;
      }
      else if (strcmp(argv[i], "-sN") == 0)
      {
        args->scan_type = SCAN_NULL;
      }
      else if (strcmp(argv[i], "-sA") == 0)
      {
        args->scan_type = SCAN_ACK;
      }
      else if (strcmp(argv[i], "-O") == 0)
      {
        args->detect_os = true;
      }
      else if (strcmp(argv[i], "-sV") == 0)
      {
        args->detect_services = true;
      }
      else
      {
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return false;
      }
    }
    else
    {
      // Set target (only the first non-option argument is considered)
      if (args->target[0] == '\0')
      {
        strncpy(args->target, argv[i], sizeof(args->target) - 1);
      }
    }
  }

  // Must have a target
  if (args->target[0] == '\0')
  {
    return false;
  }

  return true;
}

void show_help(const char *program_name)
{
  printf("Neptune Scanner %s\n", VERSION);
  printf("Usage: %s [Options] target\n\n", program_name);
  printf("Options:\n");
  printf("  -p <port range>    Port range to scan (e.g., 1-1024)\n");
  printf("  -sS               TCP SYN scan (stealth)\n");
  printf("  -sT               TCP Connect scan\n");
  printf("  -sU               UDP scan\n");
  printf("  -c                Scan common ports only\n");
  printf("  -v                Verbose output\n");
  printf("  -t <timeout>      Timeout in milliseconds (default: %d)\n", DEFAULT_TIMEOUT);
  printf("  -sV               Enable service detection\n");
  printf("  -V                Show version information\n");
  printf("  -h                Show this help message\n\n");
  printf("Examples:\n");
  printf("  %s example.com\n", program_name);
  printf("  %s -p 1-1024 example.com\n", program_name);
  printf("  %s -sS -v example.com\n", program_name);
  printf("  %s -sV example.com\n", program_name);
}

void show_version(void)
{
  printf("Neptune Scanner %s\n", VERSION);
}

void cleanup_args(Args *args)
{
  if (args->use_port_list && args->port_list != NULL) {
    free(args->port_list);
    args->port_list = NULL;
    args->port_list_size = 0;
  }
}

void print_args_help(void)
{
  printf("Neptune Scanner %s\n\n", VERSION);
  printf("  -sS               TCP SYN scan (stealth)\n");
  printf("  -sT               TCP Connect scan\n");
  printf("  -sU               UDP scan\n");
  printf("  -c                Scan common ports only\n");
  printf("  -v                Verbose output\n");
  printf("  -t <timeout>      Timeout in milliseconds (default: 1000)\n");
  printf("  -sV               Enable service detection\n");
  printf("  -V                Show version information\n");
  printf("  -h                Show this help message\n");
  printf("\n");
  printf("Examples:\n");
  printf("  neptunescan.exe example.com\n");
  printf("  neptunescan.exe -p 1-1024 example.com\n");
  printf("  neptunescan.exe -p 80,443,8080 example.com\n");
  printf("\n");
  printf("  neptunescan.exe -sS -v example.com\n");
  printf("  neptunescan.exe -sV example.com\n");
}