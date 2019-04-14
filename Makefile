all : send_arp

send_arp : main.o request.o
		g++ -g -o send_arp main.o request.o -lpcap

main.o : main.cpp send_arp.h
		g++ -g -c -o main.o main.cpp

getmac.o : request.cpp send_arp.h
		g++ -g -c -o request.o request.cpp

clean :
		rm -f send_arp
		rm -f *.o

