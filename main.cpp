#include <pcap.h>
#include <csignal>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>


#define LIVE_SAE


#include "parser.h"
#if defined(LIVE_SAE) || defined(FILE_SAE)
#include "att_consume.h"
#endif

using namespace std;
Parser parser;
pcap_t *handle;

#if defined(LIVE_SAE) || defined(FILE_SAE)
att_consume attc;
#endif
FILE *output;


#ifdef OUTPUT_VIEWER
void Parser::view_output()
{
	ifstream infile;
	infile.open("output.txt");
	char line[256];
	int lc;
	char buf[300];
	long long unsigned int tsft;
	uint8_t rt;
	uint32_t size;
	char flags;
	int i;
	while (infile.getline(line, sizeof(line)))
	{
		lc = 0;
		memcpy(&size, &line[lc], 4);
		lc += 4;
		/* parse Radiotap attributes */
		for (int c : rt_attr)
		{
			if(line[lc] == '|')
			{
				lc++;
				continue;
				printf("Caught partial\n");
			}
			switch (c)
			{
				/* TSFT */
				case 0:
					memcpy(&tsft, &line[lc], 8);
					lc += 8 + 1;
					printf("TSFT: %llu\n",tsft);
				break;
				case 1:
					memcpy(&flags, &line[lc], 1);
					lc += 1 + 1;
					printf("Flags: %d\n", flags);
					break;
				case 2:				
					memcpy(&rt, &line[lc], 1);
					lc += 1 + 1;
					printf("Rate: %u\n", rt);
				break;
				default:
				break;
			}
		}
		while(line[lc] == '|')
		{
			lc++;		
		}
		for (attribute a : GA_attributes)
		{		
			cout << a.label << ": ";
			for (i = 0; i < a.size; i++)
			{
				if(i != 0)
				{
					/* print delimeter */
					printf("%c", a.delimiter);
				}
				if(strcmp(a.attribute_format.c_str(), "hex") == 0)
				{
					if(((u_char) line[lc]) & a.masking == 0x04)
					{
						printf("%02x", ((u_char) line[lc++]) & a.masking);
						return;
					}
					printf("%02x", ((u_char) line[lc++]) & a.masking);
					
				}
			}
			printf("\n");
		}
		printf("\n");
	}
}
#endif

void signalHandler (int signum)
{
	cout <<"Signal called " << endl;
	fclose(output);
	#ifdef LIVE_SAE
		pcap_close(handle);
	#endif
	exit(signum);
}

#if defined(LIVE_SAE) || defined(FILE_SAE)
void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
    static int count = 1;
    if(pkthdr->len > 2000)
    {
        /* drop corrutped frame */
        return;
    }
    attc.process_rt(pkthdr, packet, parser.rt_attr, parser.flags_mask, output);        
    attc.process_ga(pkthdr, packet, parser.GA_attributes, output);
    attc.process_ca(pkthdr, packet, parser.CA_attributes, parser.attr_map, output);
    fprintf(output, "\t\n");
}
#endif

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int i, j, k;
	parser = Parser();
	parser.Parse_ADF();
	printf("ADF PARSED\n");
	#ifdef OUTPUT_VIEWER
		parser.view_output();
	#else
		/* doing either live or file capture */
		signal(SIGINT, signalHandler);		
		output = fopen("output.txt", "w");
		cout << "Device name is: " << parser.devname.c_str() <<endl;
		cout << "RT Attributes are = " << parser.rt_attr.size() << endl;
		i = 20;
		for (int j : parser.rt_attr)
		{
			cout << j <<endl;
		}
		cout <<"GA Attributes total = " << parser.gac <<endl;
		for (i = 0; i < parser.gac; i++)
		{
			cout << "Attribute no. " << i << endl;
			cout << "name = " << parser.GA_attributes[i].label << endl;
			cout << "type = " << parser.GA_attributes[i].type << endl;
			cout << "attribute_grouping = " << parser.GA_attributes[i].attribute_grouping << endl;
			cout << "location = " << parser.GA_attributes[i].location << endl;
			cout << "size = " << parser.GA_attributes[i].size << endl;
		}

		cout <<"CA Attributes total = " << parser.cac <<endl;
		for (i = 0; i < parser.cac; i++)
		{
			cout << "Attribute no. " << i << endl;
			cout << "name = " << parser.CA_attributes[i].label << endl;
			cout << "type = " << parser.CA_attributes[i].type << endl;
			cout << "attribute_grouping = " << parser.CA_attributes[i].attribute_grouping << endl;
			cout << "location = " << parser.CA_attributes[i].location << endl;		
			cout << "size = " << parser.CA_attributes[i].size << endl;
			cout << "Conditions total = " << parser.CA_attributes[i].conditions_keys.size() << endl;
			j  = 0;
			while (j < parser.CA_attributes[i].conditions_keys.size())
			{
				cout << parser.CA_attributes[i].conditions_keys[j] << " = ";
				k = 0;
				while (k < parser.CA_attributes[i].vals[j].size())
				{
					printf("%d",parser.CA_attributes[i].vals[j][k++]);
				}			
				j++;
				cout << endl;
			}
		}
		#if defined(LIVE_SAE)
			/* Open the session in promiscuous mode */
			handle = pcap_open_live(parser.devname.c_str(), BUFSIZ, 1, 1000, errbuf);
			if (handle == NULL) 
			{
				cout << "Couldn't open device" << parser.devname << endl;
				return(2);
			}
			pcap_loop(handle, -1, my_callback,NULL);
		#elif defined(FILE_SAE)
			handle = pcap_open_offline("log.pcap", errbuf);
			if (handle == NULL) 
			{
				cout << "Couldn't open device" << parser.devname << endl;
				return(2);
			}
			pcap_loop(handle, -1, my_callback, NULL);
		#endif
	#endif
	return(0);
}
