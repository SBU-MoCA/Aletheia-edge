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
