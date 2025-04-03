/**
 * Port Scanner - A simple network port scanner
 * ui.c - User interface functions
 *
 * This file implements functions related to the user interface.
 */

#include <stdio.h>
#include "../include/ui.h"
#include "../include/config.h"

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
  printf("                   Neptune Port Scanner v1.0\n");
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
    printf("Scanning %d common ports\n", MAX_COMMON_PORTS);
  }
  else
  {
    printf("Scanning ports %d to %d\n", start_port, end_port);
  }

  printf("================================================================\n\n");
}