include Makefile.version

CC=gcc
LDFLAGS=`pkg-config --libs libpcap`
CFLAGS=-Wall -g `pkg-config --cflags libpcap`

OBJ=\
	src/main.o \
	src/utils.o \
	src/dns.o \
	src/http.o

TARGET=dpi


.SUFFIXES:
.PHONY: all clean test
.PRECIOUS: %.c %.h
.SUFFIXES:

all: $(TARGET)


clean:
	rm -f $(OBJ) $(TARGET)

test: $(TARGET)
#	./$< test.pcap
	@echo "not implemented yet"

$(TARGET): $(OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
