# Aletheia-edge

## Getting Started

Aletheia on the edge relies on using Attribute Definition File which details all information of interest to the user to extract. Aletheia supports two extraction ways: live or from pre-stored pcap file. To use live SAE, please define #LIVE_SAE in main file, for pcap file, please define #FILE_SAE and have pcap file stored in the same directory with name log.pcap

After selecting appropriate usage, please run the following commands to start the code:
```
make
./aletheia-edge
```

## Attribute Definition File (ADF)

Attribute Definition File consists of 4 main parts: device name, General Attribute (GA), Conditional Attribute (CA), and radiotap attributes (RT).

### labels allowed within ADF:
1. *devname* = Device name (string)
2. *attribute-type*= attribute type (string) -- can be GA, RT, or CA
    - for GA and CA:
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
    - for RT:
     - *val*= bit of defined radiotap field user is interested in (please refer to http://www.radiotap.org/fields/defined) for full list
     - NOTE: for bit 1 user has to add masking for flags(e.g., val=1=2) adds interest in radiotap bit 2 (RX_FLAGS) with masking of 0x02 to extract only preamble value
     
## Contact Us

For any questions or issues with the system, please contact mohammed.elbadry@stonybrook.edu
