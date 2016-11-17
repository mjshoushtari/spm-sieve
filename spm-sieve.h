#ifndef _SPM_SIEVE_H
#define _SPM_SIEVE_H

#include "pin.H"
#include <iostream>
#include <fstream>
#include <assert.h>
#include <utility>
#include <map>
#include <set>
#include <algorithm>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../InstLib/instlib.H"
#include "Set-RD.h"

#include "maid.h"
#include "utility.h"

//#define ENABLE_DEBUG_PRINT
#ifdef ENABLE_DEBUG_PRINT
#define DEBUG_PRINT(X)	cerr << X
#else
#define DEBUG_PRINT(X)
#endif

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#define MALLOC "malloc"
#define CALLOC "calloc"
#define FREE "free"
#define POSIX_MEMALIGN "posix_memalign"
#define NON_DYNAMIC "static"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

// TODO: create temp dir to store results for each run
// TODO: add MLC size knob in config file
// TODO: print all knob values into some file

// Common FLags

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
        "o", "spm-sieve.out", "specify output file name");

// TODO: rename to malloc-stack-trace; change the output file name 
KNOB<BOOL> KnobEnableMAID(KNOB_MODE_WRITEONCE, "pintool",
        "maid", "0", "control maid run");

KNOB<BOOL> KnobObjectProfile(KNOB_MODE_WRITEONCE, "pintool",
        "obj-prof", "1", "print object profile in a file");

KNOB<UINT64> KnobStartIcount(KNOB_MODE_WRITEONCE, "pintool",
        "start-icount", "0", "Specify start icount avoid startup phase");

KNOB<UINT64> KnobEndIcount(KNOB_MODE_WRITEONCE, "pintool",
        "end-icount", "99999999999999", "Specify end icount to end");

KNOB<UINT64> KnobProfileInterval(KNOB_MODE_WRITEONCE, "pintool",
        "prof-interval", "1000000000", "Dumping of Stats per Window");

// Advanced flags

KNOB<BOOL> KnobEnableRD(KNOB_MODE_WRITEONCE, "pintool",
        "rd", "1", "enable/disable the Reuse Distance calulation");

KNOB<UINT64> KnobLargeObjectSize(KNOB_MODE_WRITEONCE, "pintool",
        "large-obj-size", "1023", "Specify the minimum object size to categorize in large");

KNOB<BOOL> KnobDemarcateLargeObject(KNOB_MODE_WRITEONCE,"pintool",
                          "demark-large-obj","0","distinguish between large static and dynamic objects");

KNOB<BOOL> KnobDisplayAllObjects(KNOB_MODE_WRITEONCE,"pintool",
                          "display-all-obj","0","Display detailed stats for all objects");

KNOB<UINT64> KnobBlockSize(KNOB_MODE_WRITEONCE,"pintool",
                          "block","6","cache block size simulated");

KNOB<UINT64> KnobL1Size(KNOB_MODE_WRITEONCE,"pintool",
                          "l1size","131072","L1 cache size simulated");

KNOB<UINT64> KnobL2Size(KNOB_MODE_WRITEONCE,"pintool",
                          "l2size","1048576","L2 cache size simulated");

KNOB<UINT64> KnobNumSets(KNOB_MODE_WRITEONCE,"pintool",
                          "sets","1","number of sets");

KNOB<BOOL> KnobStackAccesses(KNOB_MODE_WRITEONCE,"pintool",
                          "stack","0","count stack accesses");
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

UINT LOG2_CACHE_BLOCK_SIZE;
UINT LOG2_L1_SIZE;
UINT LOG2_L2_SIZE;

std::ofstream OutFile;
std::ofstream MaidFile;

bool enable_maid, enable_rd, enable_roi;
UINT64 start_icount, end_icount;
UINT64 rd_sampling_interval, profile_interval;

string libc_name = "/lib/x86_64-linux-gnu/libc.so.6";

// total no of memory accesses
UINT64 total_accesses =0;
UINT64 total_writes = 0;
UINT64 unaligned_accesses = 0;
UINT64 l1_misses, l2_misses;

// total number of blocks
UINT object_count = 0;


// OBJECT CATEGORY DEFINITION
enum OBJ_TYPE {
   LARGE_STATIC,	// CLASS-AL
   SMALL_STATIC,	// CLASS-SS
   LARGE_DYNAMIC,	// CLASS-AL
   SMALL_DYNAMIC,	// CLASS-SD
   OBJ_STACK,
   OBJ_TYPE_NUM
};

class OBJ_Cat {
public:
   set<UINT> objects;  // all object ids in this category
   UINT64 size;        // total size of this category
   SetRD *rd;  // isolated per category RD
   UINT64 accesses, misses;

   OBJ_Cat():objects(),size(0),rd(NULL), accesses(0), misses(0)
   {
      rd = new SetRD(KnobNumSets.Value(), KnobBlockSize.Value());
   }
};

// TODO: make this class compact by creating a metadata class to store the rest of non-ferquent data
// ObjectInstance class stores all the relevant information we need to maintain for an Object
class ObjectInstance {
    public:

        ADDRINT start; //starting address of the malloced block
        ADDRINT end;
        ADDRINT size; // size of the malloc
        ADDRINT callsiteIP; // IP of the call site
        ADDRINT accesses; // counts the accesses to this malloced block
        ADDRINT totAcc;    // Profiled final accesses
        ADDRINT writes; // how many accesses were writes
        string image_name; // Image name, could be extended further to include most accessing function
        string type; // malloc, calloc, posix_memalign or static
        string source; // Source location of malloc call
        long int first_access, last_access; // timestamp for first and last access of the array
        // TODO: add the below stats
        long int tsc_malloc, tsc_free; // timestamp for malloc and free calls, rather then first usage
        // TODO: deprecated
        bool valid; // set to false once the block is freed
        UINT32 id; // unique ID for each block

        // RD based fully associative cache
        UINT64 l1_misses, l2_misses;

        vector<UINT64> reuseDistance;
        float priority; // to compute array priority based on various functions

#ifdef OBJECT_ALLOC_HISTOGRAM
        /***** Access Distribution ********/
        string firstLoc;
        string lastLoc;
        map<string, UINT64> accHist;
        /**********************************/
#endif

        ObjectInstance(ADDRINT _start, ADDRINT _size, ADDRINT _callsiteIP):
            start(_start), size(_size), callsiteIP(_callsiteIP),
            accesses(0),  writes(0), type("malloc"), first_access(0), last_access(0), valid(true),
            l1_misses(0), l2_misses(0), reuseDistance(MAX_RD_BUCKETS, 0)
#ifdef ARRAY_ALLOC_HISTOGRAM
            , firstLoc(), lastLoc(), accHist()
#endif
            {
                end = start + size;
                image_name = "libdummy";
                source = "dummy.c:123";
                id = object_count;

            }
};
#endif
