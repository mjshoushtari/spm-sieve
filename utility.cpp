// This file contains misc utility functions
#include <memory>
#include <boost/tokenizer.hpp>
using namespace boost;
using namespace std;

// replacement make_unique, similar to make_shared in STL, till it is implemented in stl
    template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}

// emulates UNIX basename command
string StripPath(const string &path)
{
    size_t found = path.find_last_of("/");
    return path.substr(found+1);
}

// strip whitespace from left and right of the string
string strip(const string &str, string delimiters)
{
    int first = str.find_first_not_of( delimiters );
    int last  = str.find_last_not_of ( delimiters );

    return str.substr( first, last - first + 1);
}

// emulates python split, split a string on a separator
vector<string> split(const string &line, string delimiters)
{
    char_separator<char> sep(delimiters.c_str());
    tokenizer <char_separator<char>> tokens(line, sep);

    vector<string> tmp;
    for (auto x: tokens)
        tmp.push_back(x);
    return tmp;
}

