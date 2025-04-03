/**
 * Port Scanner - A simple network port scanner
 * ui.c - User interface functions
 *
 * This file implements functions related to the user interface.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include "../include/ui.h"
#include "../include/config.h"
#include "../include/utils.h"
#include "../include/scanner.h"

// Color codes for terminal output
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_RESET "\x1b[0m"

// ASCII art banners
static const char *banners[] = {
    "    _   __      __  __  ___  ____  ____  ____  ____  ____  ____ \n"
    "   / | / /___  / /_/ / / _ \\/ __ \\/ __ \\/ __ \\/ __ \\/ __ \\/ __ \\\n"
    "  /  |/ / __ \\/ __/ / /  __/ /_/ / /_/ / /_/ / /_/ / /_/ / /_/ /\n"
    " / /|  / /_/ / /_/ / /\\___/\\____/\\____/\\____/\\____/\\____/\\____/ \n"
    "/_/ |_/\\____/\\__/_/ /                                          \n"
    "\n"
    "                    Neptune Scanner v3.0.0\n"
    "                    ---------------------\n",

    "  _   _                _             _____                      \n"
    " | \\ | | ___ _ __ ___ | |_ ___ _ __ | ____|_ __  _   _ _ __ ___ \n"
    " |  \\| |/ _ \\ '_ ` _ \\| __/ _ \\ '_ \\|  _| | '_ \\| | | | '__/ _ \\\n"
    " | |\\  |  __/ | | | | | ||  __/ |_) | |___| | | | |_| | | |  __/\n"
    " |_| \\_|\\___|_| |_| |_|\\__\\___| .__/|_____|_| |_|\\__,_|_|  \\___|\n"
    "                               |_|                                \n"
    "\n"
    "                    Neptune Scanner v3.0.0\n"
    "                    ---------------------\n",

    "  _   _           _       _             _____                      \n"
    " | \\ | | ___ _ __| |_ ___| |_ ___ _ __ | ____|_ __  _   _ _ __ ___ \n"
    " |  \\| |/ _ \\ '_ \\ __/ _ \\ __/ _ \\ '_ \\|  _| | '_ \\| | | | '__/ _ \\\n"
    " | |\\  |  __/ |_) | ||  __/ ||  __/ |_) | |___| | | | |_| | | |  __/\n"
    " |_| \\_|\\___| .__/ \\__\\___|\\__\\___| .__/|_____|_| |_|\\__,_|_|  \\___|\n"
    "             |_|                   |_|                                \n"
    "\n"
    "                    Neptune Scanner v3.0.0\n"
    "                    ---------------------\n"};

// Function to print the program header
void print_header(void)
{
  printf("\n%sNeptune Scanner%s - Advanced Port Scanner\n", COLOR_CYAN, COLOR_RESET);
  printf("==========================================\n\n");
}

// Function to print scan results
void print_results(const char *target, int *open_ports, int num_ports)
{
  printf("\n%sScan Results for %s%s\n", COLOR_GREEN, target, COLOR_RESET);
  printf("========================\n\n");

  if (num_ports == 0)
  {
    printf("No open ports found.\n");
    return;
  }

  printf("Open Ports:\n");
  for (int i = 0; i < num_ports; i++)
  {
    printf("  %d\n", open_ports[i]);
  }
}

// Function to print service information
void print_service_info(int port, const char *service_name, const char *service_desc)
{
  printf("%sPort %d%s: %s (%s)\n",
         COLOR_BLUE, port, COLOR_RESET,
         service_name, service_desc);
}

// Function to print OS detection results
void print_os_info(const char *os_info)
{
  printf("\n%sOS Detection Results%s\n", COLOR_MAGENTA, COLOR_RESET);
  printf("====================\n\n");
  printf("%s\n", os_info);
}

// Function to print error message
void print_error(const char *message)
{
  printf("%sError%s: %s\n", COLOR_RED, COLOR_RESET, message);
}

// Function to print warning message
void print_warning(const char *message)
{
  printf("%sWarning%s: %s\n", COLOR_YELLOW, COLOR_RESET, message);
}

// Function to print success message
void print_success(const char *message)
{
  printf("%sSuccess%s: %s\n", COLOR_GREEN, COLOR_RESET, message);
}

// Function to print help message
void print_help(void)
{
  print_header();
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

// Function to print version information
void print_version(void)
{
  printf("Neptune Scanner v2.0.0\n");
  printf("Copyright (c) 2024\n");
}

// Function to print scan progress
void print_scan_progress(int current, int total, const char *target)
{
  printf("\rScanning %s: ", target);
  print_progress(current, total);
}

// Function to print scan summary
void print_scan_summary(const char *target, int num_ports, long duration)
{
  char time_str[32];
  format_duration(duration, time_str, sizeof(time_str));

  printf("\n%sScan Summary%s\n", COLOR_CYAN, COLOR_RESET);
  printf("=============\n\n");
  printf("Target: %s\n", target);
  printf("Open Ports: %d\n", num_ports);
  printf("Duration: %s\n", time_str);
}

void show_banner()
{
  printf("\n");
  printf("  _   _            _                      _____                 \n");
  printf(" | \\ | |          | |                    / ____|                \n");
  printf(" |  \\| | ___ _ __ | |_ _   _ _ __   ___ | (___   ___ __ _ _ __  \n");
  printf(" | . ` |/ _ \\ '_ \\| __| | | | '_ \\ / _ \\ \\___ \\ / __/ _` | '_ \\ \n");
  printf(" | |\\  |  __/ |_) | |_| |_| | | | |  __/ ____) | (_| (_| | | | |\n");
  printf(" |_| \\_|\\___| .__/ \\__|\\__,_|_| |_|\\___||_____/ \\___\\__,_|_| |_|\n");
  printf("            | |                                                 \n");
  printf("            |_|                                                 \n");
  printf("\n");
  printf("                   Neptune Port Scanner v2.0\n");
  printf("              A high-performance network scanner\n");
  printf("                  Created by kiwiteaorion\n");
  printf("\n");
  printf("================================================================\n");
  printf("\n");
}

void show_usage(const char *program_name)
{
  printf("USAGE:\n");
  printf("  %s <target> [start_port] [end_port]\n\n", program_name);
  printf("EXAMPLES:\n");
  printf("  %s localhost         # Scan common ports on localhost\n", program_name);
  printf("  %s example.com 80 443 # Scan ports 80-443 on example.com\n", program_name);
  printf("  %s 192.168.1.1 22    # Scan only port 22 on 192.168.1.1\n\n", program_name);
}

void show_scanning_header(const char *target, int start_port, int end_port)
{
  printf("================================================================\n");
  printf("Starting Neptune Scan on %s\n", target);

  if (use_common_ports)
  {
    printf("Scanning %d common ports\n", COMMON_PORTS_COUNT);
  }
  else
  {
    printf("Scanning ports %d to %d\n", start_port, end_port);
  }

  printf("================================================================\n\n");
}