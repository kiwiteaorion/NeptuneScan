/**
 * Neptune Scanner - Command Line Argument Handling
 * args.c - Implementation of argument parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/args.h"

// Default values
#define DEFAULT_TIMEOUT 1000 // 1 second timeout
#define DEFAULT_START_PORT 1
#define DEFAULT_END_PORT 1024

// Version information
#define VERSION "2.0.0"

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
  printf("  -V                Show version information\n");
  printf("  -h                Show this help message\n\n");
  printf("Examples:\n");
  printf("  %s example.com\n", program_name);
  printf("  %s -p 1-1024 example.com\n", program_name);
  printf("  %s -sS -v example.com\n", program_name);
}

void show_version(void)
{
  printf("Neptune Scanner %s\n", VERSION);
}

int parse_args(int argc, char *argv[], scan_config_t *config)
{
  // Initialize config with default values
  config->target = NULL;
  config->start_port = DEFAULT_START_PORT;
  config->end_port = DEFAULT_END_PORT;
  config->use_common_ports = false;
  config->scan_type = SCAN_DEFAULT;
  config->verbose = false;
  config->show_version = false;
  config->show_help = false;
  config->timeout = DEFAULT_TIMEOUT;

  // Parse arguments
  for (int i = 1; i < argc; i++)
  {
    if (argv[i][0] == '-')
    {
      // Handle options
      switch (argv[i][1])
      {
      case 'p': // Port range
        if (i + 1 >= argc)
        {
          fprintf(stderr, "Error: -p requires a port range\n");
          return 1;
        }
        if (sscanf(argv[++i], "%d-%d", &config->start_port, &config->end_port) != 2)
        {
          fprintf(stderr, "Error: Invalid port range format\n");
          return 1;
        }
        break;

      case 's': // Scan type
        if (strcmp(argv[i], "-sS") == 0)
        {
          config->scan_type = SCAN_TCP_SYN;
        }
        else if (strcmp(argv[i], "-sT") == 0)
        {
          config->scan_type = SCAN_TCP_CONNECT;
        }
        else if (strcmp(argv[i], "-sU") == 0)
        {
          config->scan_type = SCAN_UDP;
        }
        else
        {
          fprintf(stderr, "Error: Unknown scan type\n");
          return 1;
        }
        break;

      case 'c': // Common ports
        config->use_common_ports = true;
        break;

      case 'v': // Verbose
        config->verbose = true;
        break;

      case 't': // Timeout
        if (i + 1 >= argc)
        {
          fprintf(stderr, "Error: -t requires a timeout value\n");
          return 1;
        }
        config->timeout = atoi(argv[++i]);
        break;

      case 'V': // Version
        config->show_version = true;
        break;

      case 'h': // Help
        config->show_help = true;
        break;

      default:
        fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
        return 1;
      }
    }
    else
    {
      // This should be the target
      if (config->target != NULL)
      {
        fprintf(stderr, "Error: Multiple targets specified\n");
        return 1;
      }
      config->target = argv[i];
    }
  }

  // Validate configuration
  if (config->show_help)
  {
    show_help(argv[0]);
    return 0;
  }

  if (config->show_version)
  {
    show_version();
    return 0;
  }

  if (config->target == NULL)
  {
    fprintf(stderr, "Error: No target specified\n");
    show_help(argv[0]);
    return 1;
  }

  if (config->start_port < 1 || config->end_port > 65535 || config->start_port > config->end_port)
  {
    fprintf(stderr, "Error: Invalid port range\n");
    return 1;
  }

  return 0;
}