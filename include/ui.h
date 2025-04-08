/**
 * Port Scanner - A simple network port scanner
 * ui.h - User interface function declarations
 *
 * This header file declares functions related to the user interface.
 */

#ifndef UI_H
#define UI_H

#pragma once

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "service_detection.h" // For ServiceInfo structure

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

// Function to print the program header
void print_header(void);

// Function to print scan results
void print_results(const char *target, int *open_ports, int num_ports);

// Function to print scan results with version information
void print_results_with_versions(const char *target, int *open_ports, ServiceInfo *service_info, int num_ports);

// Function to print service information
void print_service_info(int port, const char *service_name, const char *service_desc);

// Function to print OS detection results
void print_os_info(const char *os_info);

// Function to print error message
void print_error(const char *message);

// Function to print warning message
void print_warning(const char *message);

// Function to print success message
void print_success(const char *message);

// Function to print help message
void print_help(void);

// Function to print version information
void print_version(void);

// Function to print scan progress
void print_scan_progress(int current, int total, const char *target);

// Function to print scan summary
void print_scan_summary(const char *target, int num_ports, long duration);

#endif // UI_H