PROJECT := openvpn-otp
SRC := src/otp.c src/base32.c
TARGET := lib/$(PROJECT).so
CFLAGS := -fPIC -O2 -Wall -Werror -pipe 
#CFLAGS += -g -DDEBUG -O0
LDFLAGS := -lcrypto
CC := gcc
PLUGIN_FILE := /usr/lib/openvpn/$(PROJECT).so

BUILD := .build
OBJ := $(SRC:%.c=$(BUILD)/%.o)

all $(PROJECT): $(TARGET)

$(shell mkdir -p $(BUILD))
$(shell $(CC) $(CFLAGS) -MM $(SRC) > $(BUILD)/.depend)
include $(BUILD)/.depend

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(shell dirname $@)
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET): $(OBJ)
	@mkdir -p $(shell dirname $@)
	@echo LD $(shell basename $@)
	@$(CC) -shared -o $(TARGET) $(OBJ) $(LDFLAGS)

install: $(PLUGIN_FILE)

$(PLUGIN_FILE): $(TARGET)
	@echo CP $(shell basename $(TARGET))
	@sudo cp $(TARGET) $(PLUGIN_FILE)

clean:
	@echo RM $(shell basename $(TARGET)) $(BUILD)
	@rm -rf $(TARGET) $(BUILD)

