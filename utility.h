#ifndef _UTILITY_H
#define _UTILITY_H
#include <memory>
// This file contains misc utility functions

// replacement make_unique, similar to make_shared in STL, till it is implemented in stl
    template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args );
//
// emulates UNIX basename command
string StripPath(const string &path);

static string whitespaces {" \t\f\v\n\r"};

// strip whitespace from left and right of the string
string strip(const string &str, string delimiter=whitespaces);

// emulates python split, split a string on a separator
vector<string> split(const string &line, string delimiters=whitespaces);
#endif
