#ifndef _REUSE_DISTANCE_H
#define _REUSE_DISTANCE_H
#include <set>

using namespace INSTLIB;
#define MAX_RD_BUCKETS 32

extern ICOUNT icount;
ADDRINT inline get_inscount() { return icount.Count(); }
VOID inline activate_inscount() { icount.Activate(); }

// TODO: replace with the variable being externed here
struct entry {
   entry* hash_ptr;              // Forward ptr in hash table linked lists.
   entry* LRU_fptr;              // Forward ptr in LRU-chain.
   entry* LRU_bptr;              // Backward ptr in LRU-chain.
   INT64  level;                 // Particular binary log index level.
   double avg_dist;              // Average reuse distance.
   UINT64 min_dist;              // Minimum reuse distance.
   UINT64 max_dist;              // Maximum reuse distance.
   UINT32 num_reuses;            // Number of reuses.
   UINT32 chunk_usage;           // What chunks are used within a cache line?
   INT32  access_size;           // Read/Write size (how many bytes?)
   UINT64 tag;                   // Tag of the cache line.
};

class ReuseDistance {
private:
   UINT32 tag_shift;

   string ident;                    // Name of the RD Module

   entry** hash_table;             // Actual hash table of ptrs.
   UINT64 ht_idx_mask;             // Mask to get hash table index.
   entry** bhist_position;         // Binary Log positions in LRU-chain.
   UINT bheidx;                    // Last level in LRU-chain.
   entry* endbob;                  // Entry at end of LRU-chain.
   entry* free_list;               // Working list of free elements.
   entry* LRU_chain;               // LRU-chain of all unique lines.


   uint64_t start_inst_count;      // Instruction analysis started at.
   uint64_t sicount;               // Sanity Interval Count.
   uint64_t sinterval;             // Instructions between sanity checks.
   uint64_t total_reorder_distance;
   uint64_t numb_reorders;

   vector<entry *> toBeFreed;       // List of entries to be cleaned-up
 
   entry* get_new_entry();
   VOID update_bhist_positions(UINT64 tlevel);
   VOID perform_sanity_check(uint64_t cnt);

public:
   UINT64 total_unique_lines;      // Total number of unique lines.
   UINT64 num_memory_accesses;     // Total number of memory accesses

   UINT64* reuse_histo;            // Binary log histo of reuse distance.
   std::ofstream *isfile;


   ReuseDistance(UINT32 block = 6, std::ofstream *outFile = NULL, string name = "");
   INT ProcessMemoryAccess(VOID *ip, UINT64 addr, INT64 rdsize);

   UINT64 calculateMisses(UINT64 rdBucket)
   {
      UINT64 misses = 0;
      for(UINT m = rdBucket + 1; m < MAX_RD_BUCKETS; m++)
         misses += reuse_histo[m]; // capacity misses

      return misses;
   }
   UINT64 getNumMemoryAccesses(void) { return num_memory_accesses;}

   VOID PrintHistogram(string str, std::ofstream *of = NULL);
   VOID FinalReport(string reason, std::ofstream *of);
   ~ReuseDistance();
};

#endif
