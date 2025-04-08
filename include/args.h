/**
 * Neptune Scanner - Command Line Argument Handling
 * args.h - Argument parsing and configuration
 */

#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>
#include "config.h"
#include "advanced_scan.h"

// Configuration structure to hold all scan options
typedef struct
{
  char target[256];       // Target host or IP
  int port_range[2];      // [start_port, end_port]
  int *port_list;         // List of specific ports to scan
  int port_list_size;     // Number of ports in the list
  bool use_port_list;     // Whether to use port_list instead of port_range
  scan_type_t scan_type;  // Type of scan to perform
  bool detect_os;         // Enable OS detection
  bool detect_services;   // Enable service detection
  bool verbose;           // Verbose output
} Args;

/**
 * Parse command line arguments
 *
 * @param argc Number of arguments
 * @param argv Array of argument strings
 * @param args Pointer to Args structure to fill
 * @return true if parsing successful, false otherwise
 */
bool parse_args(int argc, char *argv[], Args *args);

/**
 * Print usage information
 */
void print_usage(void);

/**
 * Show help message with command usage
 *
 * @param program_name The name of the program
 */
void show_help(const char *program_name);

/**
 * Show version information
 */
void show_version(void);

/**
 * Print help message
 */
void print_args_help(void);

/**
 * Print version information
 */
void print_version(void);

/**
 * Clean up dynamically allocated resources in Args structure
 *
 * @param args Pointer to Args structure to clean up
 */
void cleanup_args(Args *args);

/**
 * Convert scan type to string
 *
 * @param scan_type The scan type to convert
 * @return String representation of the scan type
 */
const char *scan_type_to_string(scan_type_t scan_type);

#endif /* ARGS_H */