all: hex2dec dec2hex lower upper jwt


CFLAGS += \
	-Wall \
	-Werror
LDFLAGS += \
	-lcrypto \
	-lclog

%.o: %.c %.h
	$(CC) -c $(CFLAGS) -o $@ $<


hex2dec: hex2dec.c input.o
	$(CC) $(CFLAGS) -o hex2dec $^


dec2hex: dec2hex.c input.o
	$(CC) $(CFLAGS) -o dec2hex $^


lower: lower.c input.o
	$(CC) $(CFLAGS) -o lower $^


upper: upper.c input.o
	$(CC) $(CFLAGS) -o upper $^


jwt: jwt.c input.o
	$(CC) $(CFLAGS) -o $@ $^ $(CFLAGS) $(LDFLAGS)


.PHONY: clean
clean:
	-rm *.o
	-rm hex2dec
	-rm dec2hex
	-rm lower
	-rm upper
	-rm jwt
