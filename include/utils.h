/**
 * Port Scanner - A simple network port scanner
 * utils.h - Utility function declarations
 *
 * This header file declares utility functions that can be used throughout the application.
 * Currently empty, but can be expanded as needed.
 */

#ifndef UTILS_H // Include guard to prevent multiple inclusion
#define UTILS_H

#include <stdbool.h>

/**
 * Displays a progress bar in the console
 *
 * @param progress Current progress value (0.0 to 1.0)
 * @param width Width of the progress bar in characters
 */
void display_progress_bar(float progress, int width);

// Function to check if a string is a valid IP address
bool is_valid_ip(const char *ip);

// Function to check if a string is a valid hostname
bool is_valid_hostname(const char *hostname);

// Function to resolve a hostname to an IP address
bool resolve_hostname(const char *hostname, char *ip, size_t ip_size);

// Function to print a progress bar
void print_progress(int current, int total);

// Function to format a time duration
void format_duration(long milliseconds, char *buffer, size_t buffer_size);

// Function to get current timestamp
long get_timestamp(void);

// Function to check if a port number is valid
bool is_valid_port(int port);

// Function to convert a string to lowercase
void str_tolower(char *str);

// Function to trim whitespace from a string
void str_trim(char *str);

// Function to get the executable name
const char* get_executable_name(void);

// Utility function declarations will be added here as the project grows

#endif /* UTILS_H */ // End of include guard