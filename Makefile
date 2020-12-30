include Makefile.version

CC=gcc
LDFLAGS=`pkg-config --libs libpcap`
CFLAGS=-Wall `pkg-config --cflags libpcap` \
		-g
OBJ=\
	src/main.o \
	src/utils.o \
	src/dns.o

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
