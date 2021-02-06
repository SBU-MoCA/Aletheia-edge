view:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap -DOUTPUT_VIEWER -o aletheia-viewer
live:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap -DLIVE_SAE -o aletheia-edge-live
offline:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap -DLIVE_SAE -o aletheia-edge-file

