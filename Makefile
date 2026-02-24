TARGET_EXEC ?= fise

BUILD_DIR ?= ./build
SRC_DIRS ?= ./src
PREFIX ?= /usr/local

MKDIR_P ?= mkdir -p

SRCS := $(shell find $(SRC_DIRS) -name "*.c")
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS ?= $(INC_FLAGS) -MMD -MP
CFLAGS ?= -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS ?= -pie -lssl -lcrypto -luuid

.PHONY: all clean install debug release

all: $(BUILD_DIR)/$(TARGET_EXEC)

$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# c source
$(BUILD_DIR)/%.c.o: %.c
	$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -r $(BUILD_DIR)

install: $(BUILD_DIR)/$(TARGET_EXEC)
	$(MKDIR_P) $(PREFIX)/bin
	install -m 755 $(BUILD_DIR)/$(TARGET_EXEC) $(PREFIX)/bin/

debug: CFLAGS = -g -O0 -Wall -Wextra -DDEBUG
debug: clean all

release: CFLAGS = -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -DNDEBUG
release: clean all
	strip $(BUILD_DIR)/$(TARGET_EXEC)

-include $(DEPS)