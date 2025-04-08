/**
 * Port Scanner - A simple network port scanner
 * utils.c - Utility functions
 *
 * This file contains utility functions that can be used throughout the application.
 * Currently empty, but can be expanded as needed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* Explicitly satisfy clangd's static analysis while keeping actual compilation working */
#ifdef __CLANGD__
/* These definitions help clangd but aren't compiled with gcc */
struct hostent {
    char* h_name;
    char** h_aliases;
    int h_addrtype;
    int h_length;
    char** h_addr_list;
};
struct in_addr {
    unsigned int s_addr;
};
char* inet_ntoa(struct in_addr in) { return NULL; }
struct hostent* gethostbyname(const char* name) { return NULL; }
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include "../include/utils.h"

/**
 * Displays a progress bar in the console
 *
 * @param progress Current progress value (0.0 to 1.0)
 * @param width Width of the progress bar in characters
 */
void display_progress_bar(float progress, int width)
{
  int pos = width * progress;
  int percent = progress * 100;

  // Print the percentage at the start
  printf("%3d%% [", percent);

  // Print the bar
  for (int i = 0; i < width; i++)
  {
    if (i < pos)
      printf("=");
    else if (i == pos)
      printf(">");
    else
      printf(" ");
  }

  // Print the end of the bar and carriage return
  printf("] \r");
  fflush(stdout); // Ensure output is displayed immediately
}

// Function to check if a string is a valid IP address
bool is_valid_ip(const char *ipaddr)
{
  int num;
  int dots = 0;
  const char *ptr = ipaddr;

  if (ipaddr == NULL)
  {
    return false;
  }

  while (*ptr)
  {
    if (*ptr == '.')
    {
      dots++;
      ptr++;
      continue;
    }
    if (!isdigit(*ptr))
    {
      return false;
    }
    num = 0;
    while (isdigit(*ptr))
    {
      num = num * 10 + (*ptr - '0');
      ptr++;
    }
    if (num > 255)
    {
      return false;
    }
  }

  return (dots == 3);
}

// Function to check if a string is a valid hostname
bool is_valid_hostname(const char *hostname)
{
  if (hostname == NULL || strlen(hostname) > 255)
  {
    return false;
  }

  const char *ptr = hostname;
  int label_length = 0;

  while (*ptr)
  {
    if (*ptr == '.')
    {
      if (label_length == 0 || label_length > 63)
      {
        return false;
      }
      label_length = 0;
      ptr++;
      continue;
    }
    if (!isalnum(*ptr) && *ptr != '-')
    {
      return false;
    }
    label_length++;
    ptr++;
  }

  return (label_length > 0 && label_length <= 63);
}

// Function to resolve a hostname to an IP address
bool resolve_hostname(const char *hostname, char *ipaddr, size_t ipaddr_size)
{
  struct hostent *he;
  struct in_addr **addr_list;

  if ((he = gethostbyname(hostname)) == NULL)
  {
    return false;
  }

  addr_list = (struct in_addr **)he->h_addr_list;
  if (addr_list[0] != NULL)
  {
    strncpy(ipaddr, inet_ntoa(*addr_list[0]), ipaddr_size - 1);
    ipaddr[ipaddr_size - 1] = '\0';
    return true;
  }

  return false;
}

// Function to print a progress bar
void print_progress(int current, int total)
{
  const int width = 50;
  float progress = (float)current / total;
  int pos = width * progress;

  printf("[");
  for (int i = 0; i < width; i++)
  {
    if (i < pos)
    {
      printf("=");
    }
    else if (i == pos)
    {
      printf(">");
    }
    else
    {
      printf(" ");
    }
  }
  printf("] %d%%\r", (int)(progress * 100));
  fflush(stdout);
}

// Function to format a time duration
void format_duration(long milliseconds, char *buffer, size_t buffer_size)
{
  long seconds = milliseconds / 1000;
  long minutes = seconds / 60;
  long hours = minutes / 60;

  if (hours > 0)
  {
    snprintf(buffer, buffer_size, "%ldh %ldm %lds", hours, minutes % 60, seconds % 60);
  }
  else if (minutes > 0)
  {
    snprintf(buffer, buffer_size, "%ldm %lds", minutes, seconds % 60);
  }
  else
  {
    snprintf(buffer, buffer_size, "%lds", seconds);
  }
}

// Function to get current timestamp
long get_timestamp(void)
{
#ifdef _WIN32
  SYSTEMTIME st;
  GetSystemTime(&st);
  return (long)st.wMilliseconds + (long)st.wSecond * 1000 + (long)st.wMinute * 60000 + (long)st.wHour * 3600000;
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

// Function to check if a port number is valid
bool is_valid_port(int port)
{
  return (port >= 0 && port <= 65535);
}

// Function to convert a string to lowercase
void str_tolower(char *string)
{
  if (string == NULL)
  {
    return;
  }
  for (int i = 0; string[i]; i++)
  {
    string[i] = tolower(string[i]);
  }
}

// Function to trim whitespace from a string
void str_trim(char *string)
{
  if (string == NULL)
  {
    return;
  }

  char *end;
  while (isspace((unsigned char)*string))
  {
    string++;
  }

  if (*string == 0)
  {
    return;
  }

  end = string + strlen(string) - 1;
  while (end > string && isspace((unsigned char)*end))
  {
    end--;
  }

  end[1] = '\0';
}

// Function to get the executable name
const char* get_executable_name(void)
{
  static const char* executable_name = "neptunescan.exe";
  return executable_name;
}

// Utility functions will be added here as the project grows