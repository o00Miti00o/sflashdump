include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

ELF    := sflash_dump.elf
CFLAGS += -Os -std=c11 -Wall -Wextra -Wno-format-security -fpie -fPIC
LIBS   := -lkernel_sys

all: $(ELF)

$(ELF): sflash_dump.c
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

clean:
	rm -f $(ELF)
