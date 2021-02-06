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
void att_consume::process_ca(const struct pcap_pkthdr *header, const u_char * packet, vector<attribute>& ca_attr, map<char, attribute>& attr_map, int offset, ofstream& output)
{
  int i = 0;
  int j = 0;
  int k = 0; 
  attribute tmp_attr, attr_it, attr_cond;
  char key;
  int pass;
  int ret;
  char tmp_char;  
 
  const u_char *ptr = packet + offset;
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
        /* If condition is not met */
        if (tmp_char != attr_it.vals[j][k])
        {
          pass = 0;
          break;
        }
        /* condition met, move to next condition and check */
        k++;
      }

      if (pass != 1)
      {
        break;
      }
      j++;
    }
    //fprintf(output, "\n");

    /* all conditions for CA to be written have passed */
    if (pass == 1)
    {
      //fwrite(&ca_attr[i].key, 1, 1, output);
      output.write(&ca_attr[i].key, 1);
      output.write(reinterpret_cast<const char*>(ptr + ca_attr[i].location), ca_attr[i].attribute_grouping * ca_attr[i].size);
      //fwrite(ptr + ca_attr[i].location, ca_attr[i].attribute_grouping, ca_attr[i].size, output);
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
void att_consume::process_ga(const struct pcap_pkthdr *header,
  const u_char * packet, vector<attribute>& ga_attr, int offset, ofstream& output)
{
  int i;
  char buffer[200];  
  const u_char *ptr = packet + offset;
  
  for (attribute a : ga_attr)
  {
    //fwrite(ptr + a.location, a.attribute_grouping, a.size, output);
    output.write(reinterpret_cast<const char*>(ptr + a.location), a.attribute_grouping * a.size);
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
 const u_char * packet, vector<int> rt_attr, char flags_mask, struct ieee80211_radiotap_iterator& iterator, ofstream& output)
{
 
  int ret;
  int tmp;
  uint8_t rt;
  char tmp_char;
  int rtc = 0;
  char buffer[200];
  do
  {
    ret = ieee80211_radiotap_iterator_next(&iterator);
    tmp = iterator.this_arg_index;
    /* if value is not requested in ADF, skip it */
    if (find(begin(rt_attr), end(rt_attr), tmp) == end(rt_attr))
    {
     continue;
    }

    /* if requested radiotap header was not available add delimiter and move on */
    while (rt_attr[rtc] < iterator.this_arg_index)
    {
      rtc++;
      output.write("|", 1);
      //fprintf(output, "|");
    } 

    switch (iterator.this_arg_index) 
    {
      case IEEE80211_RADIOTAP_TSFT:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 8); /* TSFT is 64 bits */
        break;
      case IEEE80211_RADIOTAP_FLAGS:
        tmp_char = *iterator.this_arg & flags_mask; 
        output.write(reinterpret_cast<const char*>(&tmp_char), 1); /* flags is 8 bits */
        break;
      case IEEE80211_RADIOTAP_RATE:
        rt = (uint8_t) *iterator.this_arg; /* in 500kbps */
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1); /* Rate is 8 bits */
        break;
      case IEEE80211_RADIOTAP_CHANNEL:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 4); /* channel is 32 bits  u16 freq, u16 flags*/
        break;      
        case IEEE80211_RADIOTAP_FHSS:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 2); /* FHSS is 16 bits u8 hop set, u8 hop pattern*/      
        break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 2); /* Lock Quality is 16 bits */
        break;
      case IEEE80211_RADIOTAP_TX_ATTENUATION:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 2); /* TX attentuation is 16 bits */
        break;
      case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 2); /* TX db attentuation is 16 bits */
        break;
      case IEEE80211_RADIOTAP_DBM_TX_POWER:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1); /* TX dbm power is 8 bits */
        break;
      case IEEE80211_RADIOTAP_ANTENNA:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1); /* Antenna is 8 bits */
        break;    
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1); /* DBM ANTSIGNAL is 8 bits */
        break;      
      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1);  /* DBM ANTNOISE is 8 bits */
        break;
      case IEEE80211_RADIOTAP_RX_FLAGS:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 2); /* RX flags is 16 bits */
        break;
      case IEEE80211_RADIOTAP_TX_FLAGS:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 2); /* TX flags is 16 bits */
        break;
      case IEEE80211_RADIOTAP_RTS_RETRIES:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1); /* RTS retries is 8 bits */
        break;
      case IEEE80211_RADIOTAP_DATA_RETRIES:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 1); /* Data retries is 8 bits */
        break;
      case IEEE80211_RADIOTAP_MCS:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 3); /* MCS is 24 bits u8 known, u8 flags, u8 mcs */
        break;
      case IEEE80211_RADIOTAP_AMPDU_STATUS:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 8); /* AMPDU status is 64 bits, u32 reference, u16 flag, u8 delimiter, u8 reserved */
        break;
      case IEEE80211_RADIOTAP_VHT:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 12); /* VHT is 96 bits u16 known, u8 band, u8 mcs_ncss[4], u8 coding, u8 group_id, u16 partial_aid */
        break;
      case IEEE80211_RADIOTAP_TIMESTAMP:
        output.write(reinterpret_cast<const char*>(iterator.this_arg), 12); /* timestamp is 96 bits u64 timestamp, u16 accuracy, u8 unit/position, u8 flags */
        break;
      default:
        break;
    }
    rtc++;
    //fprintf(output, "|");
    output.write("|", 1);
  }
  while (!ret);

  while (rtc++ < rt_attr.size())
  {
    //fprintf(output, "|");
    output.write("|", 1);
  }
}
