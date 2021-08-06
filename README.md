# Aletheia-edge

## Introduction
Aletheia is a tool built for distributed low-end robust wireless R&D platforms (e.g., raspberry pis, jetson, etc.). Aletheia enables its users to offline/live selectively log data of interest on low-end robust hardware for wireless research/development.

## Platforms Tested
1. ARM platforms (pi3/pi4/pi2/jetson)
2. x86 and x64 linux Desktop/laptops

## Chipsets (Dongles) Validated
1. AR9271 (Alfa AWUS036NHA)
2. Atheros TL-WN722N
3. Ralink RT5372 (EASTECH Ralink RT5370)
4. Realtek RTL8192CU (APMIX 300Mbps Realtek Rtl8192Cu and Mini Realtek RTL8188CU)

## Getting Started

### Requirements
- gcc
- g++
- libpcap-dev
- Boost library

### Live Capture (Please ensure you are running in sudo mode - for monitor mode)

- It is prefer to set radio to monitor mode using the following commands:
```
sudo ifconfig devname down 
sudo iwconfig devname mode monitor
sudo ifconfig devname up
```
where 'devname' is the device's **interface name** and can be obtained by running command 
```
iw dev
```
After copying appropriate device's interface name, place it in ADF.txt.

- Please ensure name of the device is correctly placed in ADF.txt before running and building the code.
- Please copy appropriate sample ADF text file (for AR9271 please use ar9207-monitor.txt for this beginning) by naming file ADF.txt

To build Aletheia-edge binary and use live-capture mode, please run the following commands:
```
make live
./aletheia-edge-live
```

Leave it running for some time then send signal 'ctrl+C' to process to terminate. The process terminates once it receives a packet after the signal immediately.

### File Capture (skip if already done live capture instead)
To process already captured log and generate output.txt with selective filtering. Ensure captured log is in the same directory and named log.pcap, then run the following commands:
```
make file
./aletheia-edge-file
```

### View Output of filtered log (ensure file permissions are set correctly)
To view log in console to verify its correctness, please run the following commands to build and run the code:
```
make view
./aletheia-viewer
```

output of captured data is printed on console terminal.

## Attribute Definition File (ADF)

Attribute Definition File consists of 4 main parts: device name, General Attribute (GA), Conditional Attribute (CA), and radiotap attributes (RT).

### labels allowed within ADF:
1. *devname* = Device name (string)
2. *attribute-type*= attribute type (string) -- can be GA, RT, or CA
    - For GA and CA:
      - *label* = label of attribute (string)
      - *key* = character to assosciate with attribute (char) 
      - *output-format* = representation format (can be hex, string, int)
      - *size* = size of field for attribute (string converted to integer)
      - *group*= how many bytes should tool group in representation (e.g., group sequence number by 2 bytes) (string converted to integer)
      - *location*= start location of attribute within frame (string converted to integer)
      - *delimiter*= seperator between group of bytes (e.g., ':' for mac-addrress and '.' for IPV4 addresses, etc.)
      - Only for CA (Conditional attributes)
      - *condition-key*= key of previously defined attribute
      - *value condition should meet* (string converted to byte 0-255) <- repeated x number of times equal to size*grouping of attribute condition must meet
      - For RT:
        - *val*= bit of defined radiotap field user is interested in (please refer to http://www.radiotap.org/fields/defined) for full list
        - NOTE: for bit 1 user has to add masking for flags(e.g., val=1=2) adds interest in radiotap bit 2 (RX_FLAGS) with masking of 0x02 to extract only preamble value
     
## Contact Us

For any questions or issues with the system, please contact mohammed.elbadry@stonybrook.edu

## Reference

[[PDF]](https://www.petermilder.com/assets/pdf/papers/21icc-aletheia.pdf) Please cite work work while using the system, thank you!

Elbadry, Mohammed, Fan Ye, Peter Milder “Aletheia: A Lightweight Tool for WiFi Medium Analysis on The Edge”, IEEE International Conference on Communications (ICC'21).

## TO DO: 

1. add GZIP compression to log live to compress data further.
