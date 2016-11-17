#include <iostream>
#include <sstream>
#include <fstream>
#include "pin.H"
#include "pin_isa.H"
#include "utility.h"

// Each stack frame reads as follows:
// ip in function at source:linenum
struct StackFrame {
    ADDRINT ip;
    ADDRINT function;
    string function_name;
    string filename;
    string image;
    int linenum;

    StackFrame(ADDRINT _ip) :
        ip(_ip), function(_ip), function_name(""), filename(""), image(""), linenum(0)
    { }

    void fill_dwarf_info()
    {
        PIN_LockClient();
        PIN_GetSourceLocation(ip, NULL, &linenum, &filename);
        image = IMG_Name(IMG_FindByAddress(ip));
        PIN_UnlockClient();

        if(filename =="") {
            filename = "UNKNOWN";
            linenum = 0;
        }

        function_name = RTN_FindNameByAddress(ip);
        if (function_name == "")
            function_name = "[Unknown Routine]";
    }
};

vector<StackFrame> callstack;

///////////////////////// Analysis Functions //////////////////////////////////

const string Target2RtnName(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);

    if (name == "")
        return string("[Unknown routine]");
    else
        return string(name);
}

bool string_has_anyof_keywords(string s, vector<string> keywords) { 
    for (auto k: keywords) if( s.find(k) != string::npos) return true;
    return false;
}

bool source_line_has_array_assignment(string s)
{
    // keywords for hints if a source has memory allocation and pointer assignment
    vector<string> keywords(4);
    keywords[0] = "malloc";
    keywords[1] = "calloc";
    keywords[2] = "new";
    keywords[3] = "posix_mem_align";

    // if the line has a mem allocation keyword and an assigment operator return true
    if ( string_has_anyof_keywords(s, keywords) && s.find("=") != string::npos )
        return true;
    else
        return false;
}

// symbol is the lhs expression of an assignment
string find_symbol(string line)
{
    vector<string> tmp = split(line, "=");
    return strip(tmp[0]);
}

// return the line at a specific line number from a file
string return_source_line(string filename, int lineno)
{
    string line;
    int counter = 0;
    ifstream fin (filename.c_str());
    if (lineno == 0) return "";

    while(fin.good()) {
        getline(fin, line);
        ++counter;
        if(counter == lineno)
            return strip(line);
    }
    return "";
}

// return array symbol @ imagename being allocated memory in the call stack below malloc
string MAID_get_array_symbol()
{
    for( auto it = callstack.rbegin(); it < callstack.rend(); ++it) {

        it->fill_dwarf_info();

        string line = return_source_line(it->filename, it->linenum);
        if (source_line_has_array_assignment(line))
            // symbol and the imagename at that frame
            return find_symbol(line) + " @ " + StripPath(it->image);
    }
    return "";
}

void MAID_print_callstack(ostream &outf)
{
    for( auto it = callstack.rbegin(); it < callstack.rend(); ++it) {

        it->fill_dwarf_info();

        outf << (void*) it->ip << " in " << it->function_name << "(" << StripPath(it->image) << ")" 
            << " at " <<  it->filename << ":" << it->linenum << " SRC: "
            << return_source_line(it->filename, it->linenum) << endl;
            //<< get_source_string_from_ip(it->ip) << endl;
    }
}

void A_ProcessCall(ADDRINT ip, ADDRINT target, ADDRINT sp, string func_name)
{
    // Update the ip of the caller
    if(callstack.size())
        callstack.back().ip = ip;

    // Push the callee on the stack with its starting address as the ip
    callstack.push_back(StackFrame(target));
    
    //cout << "Called " << Target2RtnName(target) << endl;
}

void A_ProcessReturn(ADDRINT ip, ADDRINT target, ADDRINT sp)
{
    // pop the call stack
    callstack.pop_back();
    //cout << "Return" << endl;
}

///////////////////////// Instrumentation functions ///////////////////////////

static BOOL IsPLT(TRACE trace)
{
    RTN rtn = TRACE_Rtn(trace);

    // All .plt thunks have a valid RTN
    if (!RTN_Valid(rtn))
        return FALSE;

    if (".plt" == SEC_Name(RTN_Sec(rtn)))
        return TRUE;
    return FALSE;
}

// Instruments control transfer functions to maintain call stack info
    void
MAID_Instrument_calls(TRACE trace, INS tail)
{
    //INS tail = BBL_InsTail(bbl);
    if( INS_IsCall(tail) && !IsPLT(trace)) {
        INS_InsertPredicatedCall(tail, IPOINT_BEFORE,
                (AFUNPTR)A_ProcessCall,
                IARG_INST_PTR,
                IARG_BRANCH_TARGET_ADDR,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
    }

    if( INS_IsRet(tail) ) {
        INS_InsertPredicatedCall(tail, IPOINT_BEFORE,
                (AFUNPTR)A_ProcessReturn,
                IARG_INST_PTR,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
    }
}

