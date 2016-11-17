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
#include <set>
#include "pin.H"
#include "../InstLib/instlib.H"
#include "RD.h"


// This will be sufficient to map upto 16GB of program memory
#define SATURATE_RD(RD)	((RD < MAX_RD_BUCKETS) ? RD : MAX_RD_BUCKETS - 1)

#if defined(__GNUC__)
#  if defined(__APPLE__)
#    define ALIGN_LOCK __attribute__ ((aligned(16))) /* apple only supports 16B alignment */
#  else
#    define ALIGN_LOCK __attribute__ ((aligned(64)))
#  endif
#else
# define ALIGN_LOCK __declspec(align(64))
#endif

// Some macros
#define Min(a, b)  ((a) < (b))? (a) : (b)
#define Max(a, b)  ((a) > (b))? (a) : (b)

// Define the data-structures needed for reuse distance calculation.
//
#define HASH_TABLE_SIZE 1024*1024

//
//  This function returns a new element to add into the LRU-chain.
//
entry* ReuseDistance::get_new_entry()
{
  entry* it;
//
// First check to see if the free list is empty and if so refresh it.
//
  if (free_list == NULL) {
    for (UINT i=0; i<100; i++) {
      entry* new_one = new entry;
      toBeFreed.push_back(new_one);
      new_one->hash_ptr = free_list;
      free_list = new_one;
    }
  }
//
//  Remove an entry from the free list and return it.
//
  it = free_list;
  free_list = it->hash_ptr;
  it->hash_ptr = NULL;
  it->LRU_fptr = NULL;
  it->LRU_bptr = NULL;
  it->level = -1;
  it->tag = 0;
  return it;
} // entry* get_new_entry() {

ReuseDistance::~ReuseDistance()
{
   for(UINT i = 0; i < toBeFreed.size(); i++)
      delete toBeFreed[i];
   
#if 0
   // free up free list
   while(free_list) {
      entry* toDel = free_list;
      free_list = free_list->hash_ptr;
      delete toDel;
   }

   // free up hash table
   for (UINT i=0; i<HASH_TABLE_SIZE; i++)
      while(hash_table[i]) {
         entry* toDel = hash_table[i];
         hash_table[i] = hash_table[i]->hash_ptr;
         delete toDel;
      }

   // free up bhist
   for (UINT i=0; i<64; i++)
      while(bhist_position[i]) {
         entry* toDel = bhist_position[i];
         bhist_position[i] = bhist_position[i]->LRU_fptr;
         delete toDel;
      }
#endif

   delete hash_table;
   delete bhist_position;
   delete reuse_histo;

}

//
//Initialize program statistics and program control structures.
//
ReuseDistance::ReuseDistance(UINT32 block, std::ofstream *outFile, string name) : tag_shift(block), ident(name), toBeFreed(), isfile(outFile)
{
  start_inst_count = get_inscount();

  hash_table = new entry*[HASH_TABLE_SIZE];
  ht_idx_mask = HASH_TABLE_SIZE - 1;
  for (UINT i=0; i<HASH_TABLE_SIZE; i++) {
    hash_table[i] = NULL;               // Initialize all ptrs to NULL.
  }

  bhist_position = new entry*[64];      // At most 2^63 unique lines!
  for (UINT i=0; i<64; i++) {
    bhist_position[i] = NULL;
  }

  free_list = NULL;
  endbob = get_new_entry();
  endbob->level = -999;
  bhist_position[1] = endbob;
  bhist_position[0] = get_new_entry();
  bhist_position[0]->level = -1;
  bhist_position[0]->LRU_fptr = endbob;
  bhist_position[1]->LRU_bptr = bhist_position[0];
  bheidx = 1;

  reuse_histo = new UINT64[MAX_RD_BUCKETS];
  for (UINT i=0; i<MAX_RD_BUCKETS; i++) {
    reuse_histo[i] = 0;                 // Initialize bins to zero count.
  }

  LRU_chain = bhist_position[0];
  total_unique_lines = 0;
  num_memory_accesses = 0;

  total_reorder_distance = 0;
  numb_reorders = 0;
  sicount = 1;
} // VOID RD_Init_Statistics() {

//
//  Calculate binary log of number. 
//
UINT
Ilog(uint64_t arg)
{
    UINT i=0;
    uint64_t a=arg;
    if (a == 0) return 0;
    while(a)
    {
        i++;
        a = a >> 1;
    }
    return i-1;
}
//
//  This routine cleans up any movement of the binary-log position
//  pointers in the LRU-chain.  A new entry has been placed at the MRU
//  position of the LRU-chain and at least the first level now has one
//  too many entries.
//
//  This routine is passed the first level not to change the binary-log
//  position pointers.  For hits this is the level the hit occurred at.
//  For new entries this is the level of the last unique line in the
//  chain.
//
//  Clean-up also includes changing the level number of any line moved
//  from one level to another.
//
VOID ReuseDistance::update_bhist_positions(UINT64 tlevel)
{
  if (tlevel == 0) return;              // Moving MRU to MRU is no change.
  for (UINT i=0; i<tlevel; i++) {
//
//  Check if working on last level (row) and whether a new level needs
//  to be added to the LRU-chain?  The present last level has a set of
//  unused entries hanging off of it followed by endbob at the tail.
//  The number of entries needs to be doubled to represent the number
//  of entries in the next level and the next binary log pointer must
//  point to endbob to start.
//
//cerr << "made it to bhist_positions point one for level: " << i 
//     << " and tlevel: " << tlevel << endl;
//  Alternative could be (i > 0) and also (...->level > 0)
    if ((i == (tlevel-1)) &&
        (bhist_position[i]->level < 0) &&
        (bhist_position[i]->LRU_bptr->level >= 0)) {
//cerr << "made it to bhist_positions point two for level: " << i 
//     << " and tlevel: " << tlevel << endl;
      bhist_position[i+1] = bhist_position[i]->LRU_fptr;
      entry* bptr = NULL;
      UINT number_to_add = (UINT)(1<<(i-1));
      if (number_to_add == 1) number_to_add = 0;
      for (UINT j=0; j<number_to_add; j++) {
        bptr = get_new_entry();
        bptr->LRU_fptr = bhist_position[i+1];
        bptr->LRU_fptr->LRU_bptr = bptr;
        bhist_position[i+1] = bptr;
      }
      bptr = bhist_position[i];
      bhist_position[i] = bhist_position[i]->LRU_bptr;
      bptr->LRU_fptr = bhist_position[i+1];
      bhist_position[i+1]->LRU_bptr = bptr;
      bhist_position[i+1] = endbob;
      bheidx++;
    } else {
//
//  Just move the binary log position pntr back up in the LRU-chain and
//  the new member of the next level is a unique line change the level.
//
      if (bhist_position[i]->level == i) {
        bhist_position[i]->level = i+1;
      }
      bhist_position[i] = bhist_position[i]->LRU_bptr;
    }
  }

// cout << endl;
// entry* wptr = LRU_chain;
// while (wptr->level >= 0 && wptr->level <= 3) {
//   cout << hex << wptr->tag << dec << "(" << wptr->level << ") ";
//   wptr = wptr->LRU_fptr;
// }
// cout << endl;
//  for (UINT i=0; i<=bheidx; i++) {
//    cerr << hex << bhist_position[i]->tag << dec << "("
//         << bhist_position[i]->level << ")";
//  }
//  cerr << endl;
}

//
//  This routine processes a new access.
//
//  It determines the position on the LRU-chain and histograms the 
//  reuse distance in a binary-log indexed histogram.
//
INT ReuseDistance::ProcessMemoryAccess(VOID *ip, UINT64 addr, INT64 rdsize)
{
  num_memory_accesses++;

  INT retRD = -1;
  UINT64 tag = addr >> tag_shift;
  UINT addr_in_line = addr & ((1<<tag_shift) - 1);
  UINT hidx = tag & ht_idx_mask;
  bool first_time = false;              // Flag if this is unique/cold.
  entry* wptr = NULL;                   // walking ptr looking for entry.

//
//  Check if address is in LRU-chain.  If not then leave first_time
//  flag as false.  If so, then make sure entry is at head of hash
//  list and leave pointer to it in wptr.
//

  if (hash_table[hidx] == NULL) {
    first_time = true;
  } else {
    wptr = hash_table[hidx];
    if (wptr->tag == tag) {
    } else {
      bool found_it = false;
      while (wptr->hash_ptr != NULL) {
        if (wptr->hash_ptr->tag == tag) {
          found_it = true;
          entry* found_entry = wptr->hash_ptr;
          wptr->hash_ptr = wptr->hash_ptr->hash_ptr;
          found_entry->hash_ptr = hash_table[hidx];
          hash_table[hidx] = found_entry;
          wptr = hash_table[hidx];
          break;
        } else {
          wptr = wptr->hash_ptr;
        }
      } // while (wptr->hash_ptr != NULL) 
      if (!found_it) first_time = true;
    }
  }
//
//  For all unique lines need to place at head of hash list and also at
//  head of LRU-chain and move all binary log pointers back one.
//
//cerr << "made it to point two with tag: " << hex << tag << dec 
//     << " and first_time flag: " << first_time << endl;
  if (first_time) {
    entry* new_entry = get_new_entry();
    new_entry->tag = tag;
    new_entry->hash_ptr = hash_table[hidx];
    hash_table[hidx] = new_entry;
    new_entry->LRU_fptr = LRU_chain;
    LRU_chain->LRU_bptr = new_entry;
    new_entry->LRU_bptr = NULL;
    new_entry->level = 0;
    new_entry->avg_dist = 0;
    new_entry->min_dist = (UINT64) -1;
    new_entry->max_dist = 0;
    new_entry->num_reuses = 0;
    new_entry->chunk_usage = 1<<(addr_in_line/8);
    if (rdsize <= 64) {
      new_entry->access_size = rdsize;
    } else {
      new_entry->access_size = -1;
    }
    LRU_chain = new_entry;
    total_unique_lines++;


//
//  Clean up the binary-hist positions for entire chain.
//
    update_bhist_positions(bheidx+1);
  } else {                              // was a hit in chain.
//
//  For all hits in LRU-chain, need to update reuse_histo with 
//  binary log of distance down the chain (main point of this program).
//
    UINT reuse_level = wptr->level;
    reuse_histo[SATURATE_RD(reuse_level)]++;
    wptr->num_reuses++;

    retRD = reuse_level;


    // Update info about reuse distance for this line
    UINT64 dist;
    switch (reuse_level) {
    case 0: dist = 0; break;
    case 1: dist = 1; break;
    default: dist = ((1<<reuse_level) + (1<<(reuse_level-1)))/2 - 1;
    }
    wptr->min_dist = Min(wptr->min_dist, dist);
    wptr->max_dist = Max(wptr->max_dist, dist);
    wptr->avg_dist = (wptr->avg_dist * (wptr->num_reuses - 1) + (double) dist)
      / wptr->num_reuses;

    // Update info about chunk usage and access size for this line
    wptr->chunk_usage |= 1<<(addr_in_line/8);
    // If there are multiple access sizes within the same cache line,
    // then we don't consider it as a streaming access. This is not
    // strictly true, but for purposes of workload characterization
    // for CiM, this is good enough.
    if (wptr->access_size != rdsize) {
      wptr->access_size = -1;
    }

//
//  Move entry to MRU position of LRU-chain if not there already.
//
//cerr << "made it to point twoB with tag: " << hex << tag << dec 
//     << " and hit was at level: " << wptr->level << endl;
//cerr << " and hit at level: " << wptr->level;
    if (wptr != LRU_chain) {
//
//  Check if entry hit is at end of row then move row pointer backward.
//
      if (wptr == bhist_position[wptr->level]) {
        bhist_position[wptr->level] = wptr->LRU_bptr;
      }
//
//  First remove from present position in LRU-chain.
//
      if (wptr->LRU_bptr != NULL) {
        wptr->LRU_bptr->LRU_fptr = wptr->LRU_fptr;  // remove in fwd dir.
      }
      if (wptr->LRU_fptr != NULL) {
        wptr->LRU_fptr->LRU_bptr = wptr->LRU_bptr;  // remove in bwd dir.
      }
//cerr << "made it to point twoC with tag: " << hex << tag << dec << endl;
//
//  Move to MRU position of LRU-chain.
//
      wptr->LRU_fptr = LRU_chain;
      wptr->LRU_fptr->LRU_bptr = wptr;
      wptr->LRU_bptr = NULL;
      wptr->level = 0;
      LRU_chain = wptr;
    } // if (wptr != LRU_chain) {
//
//  Clean up the binary-hist positions up to level of hit.
//
    total_reorder_distance += reuse_level;
    numb_reorders++;
    update_bhist_positions(reuse_level);
  }
//cerr << "made it to point three with tag: " << hex << tag << dec << endl;

  return retRD;
//cerr << endl;
} // INT RD_process_memory_access(VOID *ip, UINT64 addr, INT64 rdsize) {

//
//  This routine checks that the LRU-chain is in proper organization
//  to allow the process to work.
//
VOID ReuseDistance::perform_sanity_check(uint64_t cnt) {
  entry* wptr = LRU_chain;
  bool is_at_end = false;             // Initialize to not good.
  bool is_broken = false;
  uint64_t present_level = 0;
  uint64_t count = 0;
  if ((wptr->level == 0) && (wptr->LRU_fptr->level == 1)) {
    wptr = wptr->LRU_fptr;
    present_level = wptr->level;
    while (wptr != NULL) {
      if (wptr->level == (int64_t)present_level) {
        count++;
      } else {
        if (count == (uint64_t)(1<<(present_level-1))) {
          count = 0;
          present_level++;
          if (wptr->level == (int64_t)present_level) {
            count++;
          } else {
            if (wptr->level < 0) {
              is_at_end = true;
              break;
            } else {
              is_broken = true;
              break;
            }
          }
        } else {
          if (wptr->level < 0) {
            is_at_end = true;
            break;
          } else {
            is_broken = true;
            break;
          }
        }
      }
      wptr = wptr->LRU_fptr;
    } // while (wptr->level > 0) {
  } // if ((wptr->level == 0) && (wptr->LRU_fptr->level == 1)) {
  if (is_broken) {
    cerr << "LRU-CHAIN is BROKEN??????" << endl;
    exit(1);
  }
  if (!is_at_end) {
    cerr << "LRU-CHAIN seems really BROKEN??????" << endl;
    wptr = LRU_chain;
    for (UINT i=0; i<4 && wptr; i++) {
      cerr << "entry: " << i << " has level of: " << wptr->level
           << " and tag of " << hex << wptr->tag << dec << endl;
      wptr = wptr->LRU_fptr;
    }
    exit(1);
  }
} // VOID perform_sanity_check(uint64_t cnt) {

VOID ReuseDistance::PrintHistogram(string str, std::ofstream *of)
{
   std::ofstream *l_of = (of == NULL) ? isfile : of;
   *l_of << "Binary Log Histogram of Reuse Distance Module : " << ident << " " << str << endl;
   *l_of << "BLH: ";
   for (UINT i=0; i<MAX_RD_BUCKETS; i++)
      *l_of << reuse_histo[i] << ", ";
   *l_of << endl;
}

//
//  This program creates an output report in file indicated by -o Knob.
//
VOID ReuseDistance::FinalReport(string reason, std::ofstream *of)
{
  perform_sanity_check(sicount);

  std::ofstream *l_of = (of == NULL) ? isfile : of;
  *l_of << endl;
  *l_of << "####### FINAL RD STATISTICS AT END OF EXECUTION : " << ident << " #######\n";
  *l_of << "Instrumentation started at instruction count: " << start_inst_count << endl;
  *l_of << "Final Event occurred: " << reason << " at instruction count: " << get_inscount() << endl;
  *l_of << endl;
  *l_of << endl;
  *l_of << "Total number of memory accesses: " << num_memory_accesses << endl;
  *l_of << "Total Unique Lines Studied: " << total_unique_lines << endl;

  PrintHistogram("", of);
}
