OBJECT	=	sniffer
SRC		=	main.c print-arp.c print-ether.c print-http.c print-icmp.c print-ip.c print-rarp.c print-tcp.c print-udp.c
DYLIB	=	/usr/lib/libpcap.A.dylib

make:sniffer.h
	gcc $(DYLIB) -o $(OBJECT) $(SRC)

clean:
	rm $(OBJECT)
