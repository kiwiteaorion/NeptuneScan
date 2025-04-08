/**
 * Port Scanner - A simple network port scanner
 * config.h - Configuration settings
 *
 * This header file contains configuration constants used throughout the application.
 * Centralizing these values makes it easier to modify the behavior of the program.
 */

#ifndef CONFIG_H // Include guard to prevent multiple inclusion
#define CONFIG_H

#include <stdbool.h>

// Version information
#define VERSION "4.0.0"

// Default configuration values
// #define DEFAULT_TIMEOUT 2000 // Default timeout in milliseconds
#define MAX_THREADS 10        // Maximum number of scanning threads
#define MAX_OPEN_PORTS 1000   // Maximum number of open ports to track
#define MAX_BANNER_SIZE 1024  // Maximum size of service banner
#define MAX_VERSION_SIZE 32   // Maximum size of version string
#define MAX_COMMON_PORTS 1024 // Maximum number of common ports to scan

// Common ports to scan
#define COMMON_PORTS_COUNT 16
extern const int COMMON_PORTS[COMMON_PORTS_COUNT];

// Service detection timeouts
#define HTTP_TIMEOUT 2000   // HTTP service detection timeout
#define FTP_TIMEOUT 2000    // FTP service detection timeout
#define SMTP_TIMEOUT 2000   // SMTP service detection timeout
#define SSH_TIMEOUT 2000    // SSH service detection timeout
#define TELNET_TIMEOUT 2000 // Telnet service detection timeout

// OS detection parameters
#define OS_DETECTION_TIMEOUT 3000 // OS detection timeout
#define OS_DETECTION_TRIES 3      // Number of OS detection attempts

// Global configuration variables
extern bool use_common_ports; // Flag to indicate if common ports should be scanned

#endif /* CONFIG_H */ // End of include guard