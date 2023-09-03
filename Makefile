all: hex2dec dec2hex lower upper jwt


%.o: %.c %.h
	$(CC) -c -o $@ $<


hex2dec: hex2dec.c input.o
	$(CC) -o hex2dec $^


dec2hex: dec2hex.c input.o
	$(CC) -o dec2hex $^


lower: lower.c input.o
	$(CC) -o lower $^


upper: upper.c input.o
	$(CC) -o upper $^


jwt: jwt.c input.o
	$(CC) -o $@ $^


.PHONY: clean
clean:
	-rm *.o
	-rm hex2dec
	-rm dec2hex
	-rm lower
	-rm upper
	-rm jwt
