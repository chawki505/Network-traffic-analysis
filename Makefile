include Makefile.version

CC=gcc
LDFLAGS=`pkg-config --libs libpcap` -fsanitize=undefined
CFLAGS=-Wall `pkg-config --cflags libpcap` \
		-D YEAR=$(ANNEE) -D VERSION=$(VERSION) \
		-g -fsanitize=undefined
OBJ=\
	src/main.o \
	src/utils.o

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
