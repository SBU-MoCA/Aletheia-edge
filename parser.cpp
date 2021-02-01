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

#include "parser.h"

/**
 * @brief      Constructs a new instance.
 */
Parser::Parser()
{

}

/**
 * @brief      Destroys the object.
 */
Parser::~Parser()
{

}

/**
 * @brief      Parse Attribute Definition File (ADF) which contains all
 *             attributes user is interested in extracting
 * @code{.unparsed}
 * open file
 * While file has new line to read:
 *  If line does not contain '='
 *    skip parsing the line
 *  End If
 *  tokenize line
 *  If line label is for device
 *    assign value to device name
 *  Else If line label is for attribute
 *    If val of attribute is GA
 *      Read parameters line by line and assign them to struct till ';' is met
 *    Else If val of attribute is CA
 *      Read parameters line by line and assign them to struct (with condition(s)) till ';' is met
 *    Else if val of attribute is RT
 *      Read parameters line by line and assign them to list till ';' is met
 *    End If
 *  End If 
 * End While
 * 
 */
void Parser::Parse_ADF()
{
  ifstream infile;
  char line[256];
  char *label;
  char *val;
  int counter;
  gac = 0; /*GA attributes counter */
  cac = 0;
  char key;
  string tmp_str;
  attribute *tmp_attr;
  char* tmp_buf;
  infile.open("ADF.txt");

  while (infile.getline(line, sizeof(line)))
  {
    if(string(line).find('=') == string::npos)
      continue;
    label = strtok(line, "=\t");
    val = strtok(NULL, "=\t\n");

    if (strcmp(label, "dev") == 0)
    {
      devname = string(val);
    }
    if (strcmp(label, "attribute-type") == 0)
    {
      if (strcmp(val, "GA") == 0)
      {
        GA_attributes.push_back(attribute());
        GA_attributes[gac].masking = 0xFFFF;
        while(infile.getline(line, sizeof(line)))
        {
          if (string(line).find(';') != string::npos)
          {
                        /* end of attribute definition */
            attr_map[key] = GA_attributes[gac];
            gac++;
            break;
          }
          if (string(line).find('=') == string::npos)
            continue;
          label = strtok(line, " =\t");
          val = strtok(NULL, "=\n");                
          if (strcmp(label, "key") == 0)
          {
            key = val[0];
            GA_attributes[gac].key = key;                        
          }
          else if (strcmp(label, "label") == 0)
          {
            tmp_str = string(val);
            GA_attributes[gac].label = tmp_str;
          }
          else if(strcmp(label, "masking") == 0)
          {
            GA_attributes[gac].masking = atoi(val);
          }
          else if (strcmp(label, "type") == 0)
          {
            GA_attributes[gac].type = string(val);
          }
          else if (strcmp(label, "group") == 0)
          {
            GA_attributes[gac].attribute_grouping = atoi(val);
          }
          else if(strcmp(label, "output-format") == 0)
          {
            GA_attributes[gac].attribute_format = string(val);
          }
          else if (strcmp(label, "location") == 0)
          {
            GA_attributes[gac].location = atoi(val);
          }
          else if (strcmp(label, "size") == 0)
          {
            GA_attributes[gac].size = atoi(val);
          }
          else if(strcmp(label, "delimiter") == 0)
          {
            GA_attributes[gac].delimiter = val[0];
          }
        }
      }
      else if (strcmp(val, "CA") == 0)
      {
        CA_attributes.push_back(attribute());
        CA_attributes[cac].masking = 0xFFFF;
        while(infile.getline(line, sizeof(line)))
        {
          if (string(line).find(';') != string::npos)
          {
                        /* end of attribute definition */
            key = CA_attributes[cac].key;
            attr_map[key] = CA_attributes[cac]; 
            cac++;
            break;
          }
          if (string(line).find('=') == string::npos)
            continue;

          label = strtok(line, " =\t");
          val = strtok(NULL, "=\n");
          if (strcmp(label, "key") == 0)
          {
            key = val[0];
            CA_attributes[cac].key = key;                    
          }
          else if (strcmp(label, "label") == 0)
          {
            CA_attributes[cac].label = string(val);
          }
          else if (strcmp(label, "masking") == 0)
          {
            CA_attributes[cac].masking = atoi(val);
          }
          else if (strcmp(label, "type") == 0)
          {
            CA_attributes[cac].type = string(val);
          }
          else if (strcmp(label, "group") == 0)
          {
            CA_attributes[cac].attribute_grouping = atoi(val);
          }
          else if (strcmp(label, "output-format") == 0)
          {
            CA_attributes[cac].attribute_format = string(val);
          }
          else if (strcmp(label, "location") == 0)
          {
            CA_attributes[cac].location = atoi(val);
          }
          else if (strcmp(label, "size") == 0)
          {
            CA_attributes[cac].size = atoi(val);
          }
          else if (strcmp(label, "delimiter") == 0)
          {
            CA_attributes[cac].delimiter = val[0];
          }
          else if (strcmp(label, "condition-key") == 0)
          {
            key = val[0];
            CA_attributes[cac].conditions_keys.push_back(key);
            int i = 0;
            if (attr_map.count(key))
            {
              vector<char> tmp;
              tmp_attr = &attr_map[key];
              tmp_buf = new char[tmp_attr->attribute_grouping * tmp_attr->size];
              while(i < tmp_attr->size * tmp_attr->attribute_grouping && infile.getline(line, sizeof(line)))
              {
                val = strtok(line, "\t\n");
                if (atoi(val) < 0 || atoi(val) > 255)
                {
                  cout << "ERROR, value is of uint_8 byte representation" << endl;                        
                }
                else
                {
                  tmp.push_back(atoi(val));  
                }                            
                i++;
              }
              CA_attributes[cac].vals.push_back(tmp);                        
            }
            else
            {
              cout << "ERROR: Cannot find condition-label, please ensure condition label is added before being used in ADF" << endl;
            }
          }
        }           
      }
      else if (strcmp(val, "RT") == 0)
      {
        while(infile.getline(line, sizeof(line)))
        {
          if(string(line).find(';') != string::npos)
          {
                        /* end of attribute definition */
            break;
          }
          if(string(line).find('=') == string::npos)
            continue;
          label = strtok(line, " =\t");
          val = strtok(NULL, "=\n");            
          rt_attr.push_back(atoi(val));
          if (atoi(val) == IEEE80211_RADIOTAP_FLAGS_INDEX)
          {
            val = strtok(NULL, "=\n");
            flags_mask = atoi(val);
          }
        }
      }
      else
      {
        cout << "ERROR, Unkown attribute type, please check ADF file" << endl;
      }
    }
  }
}
