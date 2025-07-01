TARGET := code_headerfile

SRC_DIR := ./src
BUILD_DIR := ./build

SRCS := $(shell find $(SRC_DIR) -name '*.c')
ELFS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.bin,$(SRCS))
CC := gcc

CFLAGS := -g -masm=intel -fno-asynchronous-unwind-tables -nostdlib -ffreestanding -fno-stack-protector -fno-PIE

all: code_headerfile

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@$(CC) $(CFLAGS) $< -o $@
	@echo $(CC) $< -o $@
$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.o
	objcopy -O binary -j .text $< $@
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

code_headerfile: $(OBJS)
	python3 generate_headerfile.py

.PHONY: clean all code_headerfile

clean:
	rm -rf $(BUILD_DIR)
	rm *.h
