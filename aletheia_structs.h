#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <map>

using namespace std;
namespace io = boost::iostreams;

#ifndef ALETHSTRUCT_H_
#define ALETHSTRUCT_H_
struct attribute{
	string label;
	string type;
	string attribute_format;
	int attribute_grouping;
	int location;
	int size;
	int masking;
	char delimiter;
	char key;
	vector<char> conditions_keys;
	vector<vector<char>> vals;
};
#endif