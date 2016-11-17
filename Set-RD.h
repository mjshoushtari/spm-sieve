#ifndef _SET_RD_H
#define _SET_RD_H

#include <iostream>
#include <string>

#include "RD.h"

using namespace std;
// SET BASED RD Class
class SetRD {
   UINT BLOCK_SIZE;
   UINT numSets;
   vector<ReuseDistance *> sets;

   UINT64 indexMask;
   UINT getIndex(UINT64 addr)
   {
      return ((addr >> BLOCK_SIZE) & indexMask);
   }
public:
   SetRD(UINT ns = 1, UINT bs = 6) : BLOCK_SIZE(bs), numSets(ns), sets(ns), indexMask(0)
   {
      for(UINT s = 0; s < log2(ns); s ++)
         indexMask |= 1ULL << s;
      for(UINT s = 0; s < ns; s ++)
         sets[s] = new ReuseDistance(BLOCK_SIZE, NULL, "SET_" + std::to_string(s));
   }

   INT process_memory_access(VOID *ip, UINT64 addr, INT64 rdsize);
   UINT64 calculateMisses(UINT rdBucket);
   VOID printHistogram(string str, std::ofstream &of);
   VOID FinalReport(std::ofstream &of);
   UINT64 getNumMemoryAccesses(void);
};

#endif
