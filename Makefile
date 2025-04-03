# Neptune Scanner - A network port scanner
# Makefile - Build configuration

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS = 

# Detect operating system
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32 -liphlpapi
    TARGET = neptunescan.exe
    RM = del /Q /F
    MKDIR = mkdir
    OBJ_DIR = obj
    OBJ_FILES = $(OBJ_DIR)\*.o
else
    TARGET = neptunescan
    RM = rm -f
    MKDIR = mkdir -p
    OBJ_DIR = obj
    OBJ_FILES = $(OBJ_DIR)/*.o
endif

# Source files
SRCS = src/main.c src/scanner.c src/args.c src/ui.c src/utils.c src/advanced_scan.c src/config.c src/scan_utils.c
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

# Default target
all: $(TARGET)

# Create object directory if it doesn't exist
$(OBJ_DIR):
	$(MKDIR) $(OBJ_DIR)

# Compile source files
$(OBJ_DIR)/%.o: src/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Clean build artifacts
clean:
	$(RM) $(OBJ_FILES) $(TARGET)

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

test-services: $(TARGET)
	./$(TARGET) -sV localhost 20 25

# Phony targets (targets that don't represent files)
.PHONY: all clean run test-local test-web test-range test-services