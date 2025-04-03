/**
 * Port Scanner - A simple network port scanner
 * config.h - Configuration settings
 *
 * This header file contains configuration constants used throughout the application.
 * Centralizing these values makes it easier to modify the behavior of the program.
 */

#ifndef CONFIG_H // Include guard to prevent multiple inclusion
#define CONFIG_H

// Default port range for scanning if not specified by the user
#define DEFAULT_START_PORT 1  // Start with the lowest port number
#define DEFAULT_END_PORT 1024 // End with the last well-known port

// Network operation settings
#define CONNECT_TIMEOUT 1 // Timeout in seconds for connection attempts

#endif /* CONFIG_H */ // End of include guard