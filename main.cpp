/*
* Copyright (c) 2021, Mohammed Elbadry
*
*
* This file is part of Aletheia (Medium Analysis Tool on Edge)
*
* Aletheia is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 
* 4.0 International License.
* 
* You should have received a copy of the license along with this
* work. If not, see <http://creativecommons.org/licenses/by-nc-sa/4.0/>.
* 
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE. 
* 
*/

#include <pcap.h>
#include <csignal>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
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
ofstream output;
bool stop = false;

/**
 * @brief      View Output of output.txt
 */
#ifdef OUTPUT_VIEWER
void Parser::view_output()
{
  ifstream infile("output.bin", ios::binary);  
  unsigned char *line;
  char buf[2000];
  int lc;
  char bf[3];
  int count;
  long long unsigned int tsft;
  vector<unsigned char> buffer;
  int buf_cnt;
  uint8_t rt;
  uint32_t size;
  uint32_t index;
  char flags;
  char key;
  attribute attr;
  int i;

  do
  {
    infile.read(buf, 20);
    count = infile.gcount();
    buffer.insert(buffer.end(), buf, buf + count);
    buf_cnt = 0;
    while (buf_cnt < buffer.size())
    {
      if(buffer[buf_cnt] == '\t' && buffer[buf_cnt+1] == '\n')
      {
        buf_cnt++;
        break;
      }
      buf_cnt++;
    }
    if (buf_cnt != buffer.size() && !infile.eof())
    {
      lc = 0;
      line = &buffer[0];
    }
    else
    {
      continue;
    }
    memcpy(&size, &line[lc], 4);
    lc += 4;
    cout << "Size: " << size << endl;
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
        case 19:
          memcpy(&bf, &line[lc], 3);
          printf("MCS vals are %d, %d, and %d\n", bf[0], bf[1], bf[2]);
        break;
        default:
        break;
      }
    }

    while(line[lc] == '|')
    {
      printf("HERE\n");
      lc++;   
    }

    /* for GA attributes */
    for (attribute a : GA_attributes)
    {
      printf("%s:", a.label.c_str());
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
        else if (strcmp(a.attribute_format.c_str(), "int") == 0)
        {
          int cnt = 0;
          int cc = 0;
          while (cc < a.attribute_grouping)
          {
            cc++;
            cnt = cnt << 8  + ((u_char) line[lc++]);
          }
          printf("%d", cnt);
        }
      }
      printf("\n");
    }

    /* For CA attributes */
    lc++;
    while(lc < buf_cnt)
    {
      key = line[lc++];      
      if (parser.attr_map.find(key) == parser.attr_map.end())
        continue;
      attr = parser.attr_map[key];
      printf("%s:", attr.label.c_str());
      
      for (i = 0; i < attr.size; i++)
      {
        if(i != 0)
        {
          printf("%c", attr.delimiter);
        }
        if(strcmp(attr.attribute_format.c_str(), "hex") == 0)
        {
          printf("%02x", ((u_char) line[lc++]) & attr.masking);          
        }
        else if (strcmp(attr.attribute_format.c_str(), "int") == 0)
        {
          int cnt = 0;
          int cc = 0;
          cnt = ((u_char) line[lc + i]);
          printf("%d", cnt);
        }
      }
      printf("\n");    
      //lc += parser.attr_map[key].attribute_grouping * parser.attr_map[key].size;    
    }

    printf("\n");
    buffer.erase(buffer.begin(), buffer.begin() + buf_cnt + 1);
  } while(infile);
  infile.close();
}
#endif

/**
 * @brief      Signal handler to be called when user terminates data collection
 *             to close file before terminating
 *
 * @param[in]  signum  The signal
 */
void signalHandler (int signum)
{
  cout <<"Signal called " << endl;
  //fclose(output);
  stop = true;
  
  //exit(signum);
}

/**
 * @brief      Callback to be called to parse and packet passed
 *
 * @param      bits     bits of information (unused)
 * @param[in]  pkthdr   The pkthdr
 * @param[in]  packet   The packet
 */
#if defined(LIVE_SAE) || defined(FILE_SAE)
void my_callback(u_char *bits, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  static int count = 1;  
  struct ieee80211_radiotap_header* rt_hdr;
  struct ieee80211_radiotap_header* rt;
  struct ieee80211_radiotap_iterator iterator;  
  int ret;
  int offset = 0;

  rt = (struct ieee80211_radiotap_header*) packet;
  /* Drop frames malformed above 2000 bytes */
  if (pkthdr->len > 2000)
  {
      /* drop corrutped frame */
      return;
  }

  /* write down size of frame */
  output.write(reinterpret_cast<const char*>(&pkthdr->len), 4);

  /* check if frame has radiotap headers before LP/network headers */
  rt_hdr = (struct ieee80211_radiotap_header*) packet;
  ret = ieee80211_radiotap_iterator_init(&iterator, rt_hdr, pkthdr->len, NULL);

  /* If frame has radiotap headers, set offset and process radiotap fields in ADF */
  if (ret != -EINVAL)
  {    
    attc.process_rt(pkthdr, packet, parser.rt_attr, parser.flags_mask, iterator, output);
    offset = rt_hdr->it_len;
  }
    
  attc.process_ga(pkthdr, packet, parser.GA_attributes, offset, output);
  attc.process_ca(pkthdr, packet, parser.CA_attributes, parser.attr_map, offset, output);
  output.write("\t\n", 2);
  if (stop)
  {
    printf("Closing\n");
    output.close();
    pcap_close(handle);
    exit(0);
  }
    /*fprintf(output, "\t\n");*/
}
#endif

/**
 * @brief      Main Function to start Aletheia Edge Code
 *
 * @param[in]  argc  The count of arguments
 * @param      argv  The arguments array
 *
 * @return     0 on success
 * 
 */
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
    output = ofstream("output.bin", ios::out | ios::binary);

    /* display information parsed from ADF */
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
      cout << "OPENING LOGE" <<endl;
      handle = pcap_open_offline("log.pcap", errbuf);
      pcap_loop(handle, 0, my_callback, NULL);
    #endif
  #endif
  printf("DONE\n");
  return(0);
}
