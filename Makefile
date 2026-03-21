CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -std=c11 -pthread -Iinclude
AR      = ar
ARFLAGS = rcs

SRC_DIR   = src
BUILD_DIR = build
LIB       = $(BUILD_DIR)/libdidaqt.a

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
