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

#include "aletheia_structs.h"



class Parser{
private:
  int IEEE80211_RADIOTAP_FLAGS_INDEX = 1;

public:
	Parser();
	virtual ~Parser();
	#ifdef OUTPUT_VIEWER
	void view_output();
	#endif

	vector <attribute> GA_attributes; /* General attributes list */
	vector <attribute> CA_attributes; /* Conditional attributes list */
	map<char, attribute> attr_map;    /* map of attribute based on key */
	vector<int> rt_attr;              /* radiotap attributes list */
	char flags_mask;                  /* masking for radiotap of flags */
	string devname;                   /* device name string */
	int gac;                          /* General attributes counter */
	int cac;                          /* Conditional attributes counter */
	void Parse_ADF();
};