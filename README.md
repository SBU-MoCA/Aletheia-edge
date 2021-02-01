#Aletheia-edge

## Getting Started

Aletheia on the edge relies on using Attribute Definition File which details all information of interest to the user to extract. Aletheia supports two extraction ways: live or from pre-stored pcap file. To use live SAE, please define #LIVE_SAE in main file, for pcap file, please define #FILE_SAE and have pcap file stored in the same directory with name log.pcap

## Attribute Definition File (ADF)

Attribute Definition File consists of 4 main parts: device name, General Attribute (GA), Conditional Attribute (CA), and radiotap attributes (RT).

### labels allowed in Attribute definition File:
1. *devname* = Device name (string)
2. *attribute-type*= attribute type (string) -- can be GA, RT, or CA
    _for GA and CA:
     _*label* = label of attribute (string)
     _*key* = character to assosciate with attribute (char) 
     _*output-format* = representation format (can be hex, string, int)
     _*size* = size of field for attribute (string converted to integer)
     _*group*= how many bytes should tool group in representation (e.g., group sequence number by 2 bytes) (string converted to integer)
     _*location*= start location of attribute within frame (string converted to integer)
     _*delimiter*= seperator between group of bytes (e.g., ':' for mac-addrress and '.' for IPV4 addresses, etc.)
       _Only for CA (Conditional attributes)
        _*condition-key*= key of previously defined attribute
        _*value condition should meet* (string converted to byte 0-255) <- repeated x number of times equal to size*grouping of attribute condition must meet
    _for RT:
     _*val*= bit of defined radiotap field user is interested in (please refer to http://www.radiotap.org/fields/defined) for full list
     _NOTE: for bit 1 user has to add masking for flags(e.g., val=1=2) adds interest in radiotap bit 2 (RX_FLAGS) with masking of 0x02 to extract only preamble value
     
##contact Us

For any questions or issues with the system, please contact mohammed.elbadry@stonybrook.edu
