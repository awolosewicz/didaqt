CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -std=c11 -pthread -Iinclude
AR      = ar
ARFLAGS = rcs

SRC_DIR   = src
BUILD_DIR = build
LIB       = $(BUILD_DIR)/libdidaqt.a

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean examples bench

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# --- Examples ---

examples: $(BUILD_DIR)/sender $(BUILD_DIR)/receiver \
          $(BUILD_DIR)/controller $(BUILD_DIR)/heartbeat_monitor

$(BUILD_DIR)/sender: examples/sender.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $<

$(BUILD_DIR)/receiver: examples/receiver.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $< -L$(BUILD_DIR) -ldidaqt -lyaml -lpthread

$(BUILD_DIR)/controller: examples/controller.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $< -L$(BUILD_DIR) -ldidaqt -lyaml -lpthread

$(BUILD_DIR)/heartbeat_monitor: artifact/heartbeat_monitor.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $<

# --- Benchmarks ---

bench: $(BUILD_DIR)/bench_ctrl

$(BUILD_DIR)/bench_ctrl: benchmarking/bench_ctrl.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $< -L$(BUILD_DIR) -ldidaqt -lyaml -lpthread

clean:
	rm -rf $(BUILD_DIR)
