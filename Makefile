prep:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap
