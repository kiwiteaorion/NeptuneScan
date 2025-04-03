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
  char *target;          // Target host or IP
  int port_range[2];     // [start_port, end_port]
  scan_type_t scan_type; // Type of scan to perform
  bool detect_os;        // Enable OS detection
  bool verbose;          // Verbose output
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
 * Convert scan type to string
 *
 * @param scan_type The scan type to convert
 * @return String representation of the scan type
 */
const char *scan_type_to_string(scan_type_t scan_type);

#endif /* ARGS_H */