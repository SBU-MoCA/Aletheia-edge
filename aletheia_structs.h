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