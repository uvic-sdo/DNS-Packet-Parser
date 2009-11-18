all: sniff

sniff: sniff.c structures.h print.c print.h
	gcc -o sniff -Wall -lpcap -g sniff.c print.c structures.h -O


sniff2: sniff.c structures.h
	gcc -o sniff -std=c99 -Wall -lpcap -g sniff.c structures.h -O
