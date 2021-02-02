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

#include "att_consume.h"


/**
 * @brief      Constructs a new instance.
 */
att_consume::att_consume()
{
 
}

/**
 * @brief      Destroys the object.
 */
att_consume::~att_consume()
{

}
/**
 * @brief      Extract Conditional Attributes (CA) defined by user 
 *
 * @param[in]  header    The header
 * @param[in]  packet    The packet
 * @param      ca_attr   The CA list
 * @param      attr_map  Map to map CA to list of conditions
 * @param      output    The output file to store extracted attributes
 */
void att_consume::process_ca(const struct pcap_pkthdr *header,
 const u_char * packet, vector<attribute>& ca_attr, map<char, attribute>& attr_map, FILE* output)
{
  int i = 0;
  int j = 0;
  int k = 0; 
  attribute tmp_attr, attr_it, attr_cond;
  char key;
  int pass;
  char tmp_char;
  struct ieee80211_radiotap_header* rt;
  rt = (struct ieee80211_radiotap_header*) packet;
  const u_char *ptr = packet + rt->it_len;
    /* Iterate over all conditional attributes */
  while (i < ca_attr.size())
  {
    attr_it = ca_attr[i];
        /* if attribute location is beyond length of frame, skip checking conditions */
    if ((attr_it.size * attr_it.attribute_grouping) + attr_it.location > header->len)
    {
      continue;
    }
    pass = 1;
    j = 0;
        /* iterate over all conditions per conditional attribute */
    while (j < attr_it.conditions_keys.size())
    {
      key = attr_it.conditions_keys[j];
      attr_cond = attr_map[key];
      k = 0;
            /* compare byte by byte per condition */
      while (k < attr_cond.size * attr_cond.attribute_grouping)
      {
        tmp_char = *(ptr + attr_cond.location + k) & attr_cond.masking;
                //printf("Comparing %d with %d", tmp_char, attr_it.vals[j][k]);              
        if (tmp_char != attr_it.vals[j][k])
        {
          pass = 0;
          break;
        }
        k++;
      }
      if (pass != 1)
        break;
      j++;
    }
        /* all conditions for CA to be written have passed */
    if (pass == 1)
    {
            //printf("Condition passed! \n");
            fprintf(output, "%c",ca_attr[i].key);/* key indicating CA condition has been recorded */
      fwrite(ptr + ca_attr[i].location, ca_attr[i].attribute_grouping, ca_attr[i].size, output);
    }
    i++;
  }

}

/**
 * @brief      Extract General Attributes (GA) defined by user
 *
 * @param[in]  header   The header
 * @param[in]  packet   The packet
 * @param[in]  ga_attr  The GA list
 * @param[in]  output   The output
 */
void att_consume::process_ga(const struct pcap_pkthdr *header,const u_char * packet, vector<attribute>& ga_attr, FILE* output)
{
  int i;
  struct ieee80211_radiotap_header* rt;
  char buffer[200];
  rt = (struct ieee80211_radiotap_header*) packet;
  const u_char *ptr = packet + rt->it_len;
  for (attribute a : ga_attr)
  {
    fwrite(ptr + a.location, a.attribute_grouping, a.size, output);        
  }
}

/**
 * @brief      Extract Radiotap Attributes (RT) defined by user
 *
 * @param[in]  header      The header
 * @param[in]  packet      The packet
 * @param[in]  rt_attr     The radiotap attribute list to extract
 * @param[in]  flags_mask  mask for radiotap flags.
 * @param[in]  output      The output
 */
void att_consume::process_rt(const struct pcap_pkthdr *header,
 const u_char * packet, vector<int> rt_attr, char flags_mask, FILE* output)
{
  struct ieee80211_radiotap_iterator iterator;
  struct ieee80211_radiotap_header* rt_hdr;
  int ret;
  int tmp;
  uint8_t rt;
  char tmp_char;
  int rtc = 0;
  char buffer[200];
  rt_hdr = (struct ieee80211_radiotap_header*) packet;
  ret = ieee80211_radiotap_iterator_init(&iterator, rt_hdr, header->len, NULL);
  fwrite(&header->len, 4, 1, output);

  while (!ret) 
  {
    ret = ieee80211_radiotap_iterator_next(&iterator);
    tmp = iterator.this_arg_index;
    if (ret)
     break;
   if (find(begin(rt_attr), end(rt_attr), tmp) == end(rt_attr))
     continue;

   while (rt_attr[rtc] < iterator.this_arg_index)
   {
    rtc++;
    fprintf(output, "|");
  }

        /* TODO: add rest of headers */
  switch (iterator.this_arg_index) 
  {
    case IEEE80211_RADIOTAP_TSFT:
                fwrite(iterator.this_arg, 1, 8, output); /* TSFT is 64 bits */
    break;
    case IEEE80211_RADIOTAP_FLAGS:
    tmp_char = *iterator.this_arg & flags_mask; 
                fwrite(&tmp_char, 1, 1, output); /* flags is 8 bits */
    break;
    case IEEE80211_RADIOTAP_RATE:
            	rt = (uint8_t) *iterator.this_arg; /* in 500kbps */
                fwrite(iterator.this_arg, 1, 1, output); /* Rate is 8 bits */
    break;
    case IEEE80211_RADIOTAP_MCS:
                fwrite(iterator.this_arg, 1, 3, output); /* MCS is 24 bits */
    break;
    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                fwrite(iterator.this_arg, 1, 1, output); /* DBM ANTSIGNAL is 8 bits */
    break;
    case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                fwrite(iterator.this_arg, 1, 1, output); /* DBM ANTSIGNAL is 8 bits */
    break;
    default:
    break;

  }
  rtc++;
  fprintf(output, "|");  
}
while (rtc++ < rt_attr.size())
{
  fprintf(output, "|");
}	
}