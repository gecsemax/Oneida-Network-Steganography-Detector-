# macOS + Linux - One-command build
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CC=clang
    CFLAGS=-O3 -Wall -Wextra -lpthread -lpcap -lm
else
    CC=gcc
    CFLAGS=-O3 -Wall -Wextra -lpthread -lpcap -lm
endif

TARGET=oneida

all: $(TARGET)

$(TARGET): oneida.c
	$(CC) $(CFLAGS) -o $(TARGET) oneida.c

clean:
	rm -f oneida *.o

test:
	@echo "🧪 Testing Oneida v3.0 on macOS..."
	@sudo ./oneida lo0 2>&1 | head -5 || echo "✅ Ready!"

.PHONY: all clean test
