# Neptune Scanner - A network port scanner
# Makefile - Build configuration

# Compiler to use
CC = gcc

# Compiler flags
# -Wall: Enable all warnings
# -Wextra: Enable extra warnings
# -g: Include debugging information
CFLAGS = -Wall -Wextra -g

# Source files
SRCS = main.c src/scanner.c src/utils.c src/config.c src/ui.c src/args.c

# Object files (automatically generated from source files)
OBJS = $(SRCS:.c=.o)

# Name of the executable
TARGET = neptunescan

# Add Windows-specific flags and commands
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32 -lpthread
    RM = del /Q
    TARGET := $(TARGET).exe
else
    LDFLAGS += -lpthread
    RM = rm -f
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
	$(RM) $(subst /,\,$(OBJS)) $(TARGET)

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