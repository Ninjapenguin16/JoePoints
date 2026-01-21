# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2 -static
LDFLAGS = -static

# Static library paths (adjust if installed elsewhere)
LIBS = /usr/local/lib/libmicrohttpd.a \
       /usr/local/lib/libsqlite3.a \
       /usr/local/lib/libjson-c.a \
       -lpthread -lm

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Source and object files
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/server.c $(SRC_DIR)/api.c $(SRC_DIR)/db.c $(SRC_DIR)/crypto.c
OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/api.o $(BUILD_DIR)/server.o $(BUILD_DIR)/db.o $(BUILD_DIR)/crypto.o
TARGET = $(BIN_DIR)/server

# Default target
all: $(TARGET)

# Link step
$(TARGET): $(OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(TARGET)

# Compile step
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean
