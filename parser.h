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

	vector <attribute> GA_attributes;
	vector <attribute> CA_attributes;
	map<char, attribute> attr_map;
	vector<int> rt_attr;
	char flags_mask;
	string devname;
	int gac;
	int cac;
	void Parse_ADF();
};