/**
 * Port Scanner - A simple network port scanner
 * ui.h - User interface function declarations
 *
 * This header file declares functions related to the user interface.
 */

#ifndef UI_H
#define UI_H

#include <stdio.h>
#include <string.h>

// Color codes for terminal output
#define RESET "\033[0m"
#define BLUE "\033[34m"
#define CYAN "\033[36m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"

// Function declarations
/**
 * Displays a cool ASCII art banner and program information
 */
void show_banner();

/**
 * Displays usage information
 *
 * @param program_name The name of the executable
 */
void show_usage(const char *program_name);

/**
 * Displays scanning header information
 *
 * @param target The target being scanned
 * @param start_port The first port in the scan range
 * @param end_port The last port in the scan range
 */
void show_scanning_header(const char *target, int start_port, int end_port);

#endif // UI_H