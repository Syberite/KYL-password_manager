
CC = gcc


CFLAGS = -Wall -Werror


LIBS = -lcurl -lcrypto

TARGET = KYL


SRCS = src/main.c


OBJS = $(SRCS:.c=.o)


all: $(TARGET)


$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all cleanC = gcc
	

