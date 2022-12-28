all: hex2dec dec2hex lower


%.o: %.c %.h
	$(CC) -c -o $@ $<


hex2dec: hex2dec.c input.o
	$(CC) -o hex2dec $^


dec2hex: dec2hex.c input.o
	$(CC) -o dec2hex $^


lower: lower.c input.o
	$(CC) -o lower $^


.PHONY: clean
clean:
	-rm *.o
	-rm hex2dec
	-rm dec2hex
	-rm lower


.PHONY: install
install:
	cp hex2dec $(ROOTFS)/usr/bin
	cp dec2hex $(ROOTFS)/usr/bin
	cp lower $(ROOTFS)/usr/bin


.PHONY: uninstall
uninstall:
	-rm $(ROOTFS)/usr/bin/hex2dec
	-rm $(ROOTFS)/usr/bin/dec2hex
	-rm $(ROOTFS)/usr/bin/lower
