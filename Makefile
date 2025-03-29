CC = gcc
CFLAGS = -g -O2 -DDEBUG -fPIC
LIBS = -lcrypto -lssl
SRCS = src/ima_verify.c src/ima_utils.c src/tpm_utils.c
OBJS = build/ima_verify.o build/ima_utils.o build/tpm_utils.o
TARGET = build/libima.so

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) -shared -o $(TARGET) $(OBJS) $(LIBS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

# Create the build directory only when needed
build:
	mkdir -p build

clean:
	rm -f $(OBJS) $(TARGET) 
	rmdir build