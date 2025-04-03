/**
 * Neptune Scanner - Command Line Argument Handling
 * args.h - Argument parsing and configuration
 */

#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>

// Scan types
typedef enum
{
  SCAN_TCP_SYN,     // TCP SYN scan (stealth)
  SCAN_TCP_CONNECT, // TCP Connect scan
  SCAN_UDP,         // UDP scan
  SCAN_DEFAULT      // Default scan type
} scan_type_t;

// Configuration structure to hold all scan options
typedef struct
{
  char *target;          // Target host or IP
  int start_port;        // Starting port
  int end_port;          // Ending port
  bool use_common_ports; // Use common ports list
  scan_type_t scan_type; // Type of scan to perform
  bool verbose;          // Verbose output
  bool show_version;     // Show version information
  bool show_help;        // Show help message
  int timeout;           // Connection timeout in milliseconds
} scan_config_t;

/**
 * Parse command line arguments and populate the configuration structure
 *
 * @param argc Number of arguments
 * @param argv Array of argument strings
 * @param config Pointer to configuration structure to populate
 * @return 0 on success, non-zero on error
 */
int parse_args(int argc, char *argv[], scan_config_t *config);

/**
 * Display help message
 *
 * @param program_name Name of the program (argv[0])
 */
void show_help(const char *program_name);

/**
 * Display version information
 */
void show_version(void);

#endif /* ARGS_H */