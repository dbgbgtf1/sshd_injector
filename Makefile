TARGET := injector

SRC_DIR := ./src
INC_DIR := ./include
BUILD_DIR := ./build

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(SRCS))
CC := gcc

CFLAGS := -fpie -fstack-protector -Wall -Wextra
LDFLAGS := -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra

ifdef DEBUG
	ifeq ($(DEBUG),1)
		CFLAGS += -g -O2
		LDFLAGS += -g -O2
	else ifeq ($(DEBUG),2)
		CFLAGS += -g
		LDFLAGS += -g
	endif
else
	CFLAGS += -O2
	LDFLAGS += -O2
endif

DEST_DIR ?= 

all: injector

injector: $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@
	mv -f $@ $(BUILD_DIR)
	@echo "injector is baked"
	@echo ""

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR) $(BUILD_UTIL) $(BUILD_TEST)

.PHONY: clean all injector

clean:
	rm -rf $(BUILD_DIR)
