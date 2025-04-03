/**
 * Neptune Scanner - Network Port Scanner
 * scanner.h - Scanner functionality declarations
 *
 * This header file declares the functions related to port scanning.
 */

#ifndef SCANNER_H // Include guard to prevent multiple inclusion
#define SCANNER_H

#include <stdbool.h>
#include "advanced_scan.h"

// Default timeout in milliseconds
#define DEFAULT_TIMEOUT 1000

// Maximum number of open ports to track
#define MAX_OPEN_PORTS 1000

// Function declarations
bool init_scanner(void);
void cleanup_scanner(void);

// Port scanning functions
void scan_ports(const char *target, int start_port, int end_port, scan_type_t scan_type);
void scan_common_ports(const char *target, scan_type_t scan_type);
int is_port_open(const char *target, int port, scan_type_t scan_type);

// Open ports tracking
int *get_open_ports(void);
int get_num_open_ports(void);
int add_open_port(int port);

// Service detection
const char *get_service_name(int port);
const char *get_service_description(int port);

/**
 * Performs OS detection on the target host.
 *
 * @param target The hostname or IP address to check
 * @param os_info Buffer to store OS information
 * @param os_info_size Size of the buffer
 * @return true if OS detection was successful, false otherwise
 */
bool detect_os(const char *target, char *os_info, size_t os_info_size);

#endif /* SCANNER_H */ // End of include guard