# Port Scanner - A simple network port scanner
# Makefile - Build configuration

# Compiler to use
CC = gcc

# Compiler flags
# -Wall: Enable all warnings
# -Wextra: Enable extra warnings
# -g: Include debugging information
CFLAGS = -Wall -Wextra -g

# Source files
SRCS = main.c src/scanner.c src/utils.c src/config.c

# Object files (automatically generated from source files)
OBJS = $(SRCS:.c=.o)

# Name of the executable
TARGET = port_scanner

# Add Windows-specific flags
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32
endif

# Default target
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean target to remove compiled files
clean:
	rm -f $(OBJS) $(TARGET)

# Run target to build and execute the program
run: $(TARGET)
	./$(TARGET)

# Add test targets
test-local: $(TARGET)
	./$(TARGET) localhost 79 81

test-web: $(TARGET)
	./$(TARGET) www.google.com 79 81

test-range: $(TARGET)
	./$(TARGET) localhost 20 25

# Phony targets (targets that don't represent files)
.PHONY: all clean run test-local test-web test-range