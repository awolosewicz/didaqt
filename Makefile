CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -std=c11 -pthread -Iinclude
AR      = ar
ARFLAGS = rcs

SRC_DIR   = src
BUILD_DIR = build
LIB       = $(BUILD_DIR)/libdidaqt.a

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean examples

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# --- Examples ---
# sender and receiver build on any Linux host.
# controller requires the Intel Barefoot SDE ($SDE_INSTALL).

examples: $(BUILD_DIR)/sender $(BUILD_DIR)/receiver $(BUILD_DIR)/heartbeat_monitor

$(BUILD_DIR)/sender: examples/sender.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $<

$(BUILD_DIR)/receiver: examples/receiver.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $< -L$(BUILD_DIR) -ldidaqt -lpthread

$(BUILD_DIR)/heartbeat_monitor: artifact/heartbeat_monitor.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $<

# Build controller only when SDE_INSTALL is set.
controller: examples/controller.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -I$(SDE_INSTALL)/include \
		-o $(BUILD_DIR)/controller $< \
		-L$(SDE_INSTALL)/lib -lbf_switchd_lib -lbfrt -lpthread

clean:
	rm -rf $(BUILD_DIR)
