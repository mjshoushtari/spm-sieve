#ifndef _MAID_H_
#define _MAID_H_

string MAID_get_array_symbol();

void MAID_print_callstack(ostream& outf);

void MAID_Instrument_calls(TRACE trace, INS tail);

#endif
