SRC_DIR = .
INC_DIR = .
TMP_DIR = tmp

DAEMON = daemon


#CC = riscv64-linux-musl-gcc
#CC = ~/x86_64-linux-musl-native/bin/x86_64-linux-musl-gcc
CC = gcc

C_FILES = $(wildcard $(SRC_DIR)/*.c)
C_OBJS  = $(patsubst $(SRC_DIR)/%.c,$(TMP_DIR)/%.o,$(C_FILES))

LD_FLAGS  =  -lrt 

INC_FLAGS = -I$(INC_DIR)
C_FLAGS   = $(INC_FLAGS) -g -Wall -std=c99 

.PHONY: all
all: $(TMP_DIR) $(DAEMON)

$(TMP_DIR):
	-@mkdir -p $(TMP_DIR)

$(DAEMON):$(C_OBJS)
	$(CC) $(C_FLAGS) $(C_OBJS) -o $(DAEMON) $(LD_FLAGS)

$(TMP_DIR)/%.o:$(SRC_DIR)/%.c
	$(CC) $(C_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	-@rm -r $(TMP_DIR)
	-@rm $(DAEMON)