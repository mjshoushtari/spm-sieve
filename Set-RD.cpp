//
//  This pin tool calculates a binary log of the reuse distance
//  between accesses to the same cache block.
//
//  A cache block is defined to be 64 bytes.
//
//  The reuse distance is defined to be the number of unique blocks 
//  touched in the interval between use and reuse.
//

#include <iostream>
#include <string>
#include <assert.h>
using namespace std;
#include <iomanip>
#include <fstream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <math.h>
#include "pin.H"
#include "../InstLib/instlib.H"
#include "Set-RD.h"

using namespace INSTLIB;

// Contains knobs to filter out things to instrument
FILTER filter;

#if defined(__GNUC__)
#  if defined(__APPLE__)
#    define ALIGN_LOCK __attribute__ ((aligned(16))) /* apple only supports 16B alignment */
#  else
#    define ALIGN_LOCK __attribute__ ((aligned(64)))
#  endif
#else
# define ALIGN_LOCK __declspec(align(64))
#endif

INT32 FilterUsage()
{
    cerr <<
        ":: FILTER OPTIONS :: \n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

CONTROL control(false, "controller_");

INT SetRD::process_memory_access(VOID *ip, UINT64 addr, INT64 rdsize)
{
   UINT index = getIndex(addr);
   assert(index < numSets);

   return sets[index]->ProcessMemoryAccess(ip, addr, rdsize);
}

VOID SetRD::printHistogram(string str, std::ofstream &of)
{
   for(UINT s = 0; s < numSets; s++)
      sets[s]->PrintHistogram(str, &of);
}

VOID SetRD::FinalReport(std::ofstream &of)
{
   for(UINT s = 0; s < numSets; s++) {
      char t[8];
      sprintf(t,"Set_%u",s);
      sets[s]->FinalReport("Fini", &of);
   }
}

UINT64 SetRD::calculateMisses(UINT rdBucket)
{
   UINT64 misses = 0;
   for(UINT s = 0; s < numSets; s++)
      misses += sets[s]->calculateMisses(rdBucket);

   return misses;
}

UINT64 SetRD::getNumMemoryAccesses(void)
{
   UINT64 accesses = 0;
   for(UINT s = 0; s < numSets; s++)
      accesses += sets[s]->getNumMemoryAccesses();

   return accesses;
}
