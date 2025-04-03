/**
 * Neptune Scanner - Command Line Argument Handling
 * args.c - Implementation of argument parsing
 */

#include "args.h"
#include "scanner.h"
#include "scan_utils.h"
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

bool parse_args(int argc, char *argv[], Args *args)
{
  // Initialize args with default values
  args->target = NULL;
  args->port_range[0] = 0;
  args->port_range[1] = 0;
  args->scan_type = SCAN_CONNECT;
  args->detect_os = false;
  args->verbose = false;

  // Check for minimum arguments
  if (argc < 2)
  {
    return false;
  }

  // Parse arguments
  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-h") == 0)
    {
      return false;
    }
    else if (strcmp(argv[i], "-v") == 0)
    {
      args->verbose = true;
    }
    else if (strcmp(argv[i], "-O") == 0)
    {
      args->detect_os = true;
    }
    else if (strcmp(argv[i], "-p") == 0)
    {
      if (i + 1 >= argc)
        return false;
      char *range = argv[++i];
      char *dash = strchr(range, '-');
      if (!dash)
        return false;

      *dash = '\0';
      args->port_range[0] = atoi(range);
      args->port_range[1] = atoi(dash + 1);

      if (args->port_range[0] <= 0 || args->port_range[1] <= 0 ||
          args->port_range[0] > args->port_range[1])
      {
        return false;
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
    else if (argv[i][0] != '-')
    {
      args->target = argv[i];
    }
    else
    {
      return false;
    }
  }

  // Validate required arguments
  if (!args->target)
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