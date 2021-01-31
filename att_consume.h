#include "radiotap_iter.h"
#include "radiotap.h"
#include "aletheia_structs.h"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
using namespace std;
class att_consume{


private:
	void output(char * data, attribute attr);

public:
	att_consume();
	virtual ~att_consume();
	void process_rt(const struct pcap_pkthdr *header,
                     const u_char * packet, vector<int> rt_attr, char flags_mask, FILE* output);
	void process_ga(const struct pcap_pkthdr *header,
                     const u_char * packet, vector<attribute>& ga_attr, FILE* output);
	void process_ca(const struct pcap_pkthdr *header,
                     const u_char * packet, vector<attribute>& ca_attr, map<char, attribute>& attr_map, FILE* output);
};
