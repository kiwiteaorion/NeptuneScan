/**
 * Port Scanner - A simple network port scanner
 * utils.c - Utility functions
 *
 * This file contains utility functions that can be used throughout the application.
 * Currently empty, but can be expanded as needed.
 */

#include <stdio.h>
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

// Utility functions will be added here as the project grows