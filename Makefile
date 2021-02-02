output_viewer:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap -DOUTPUT_VIEWER -o aletheia-viewer
LIVE_SAE:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap -DLIVE_SAE -o aletheia-edge-live
FILE_SAE:
	gcc -c *.c -o radio.o
	g++ *.cpp *.o -lpcap -DLIVE_SAE -o aletheia-edge-file

