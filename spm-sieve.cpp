/* 
 * This tool captures all the memory blocks (static, malloc, calloc, posix_memalign, etc.)
 * and attributes all accesses and misses to these blocks
 * This code also uses the following external files: RD.cpp for RD calculation
 * and Maid.cpp for call stack calculation
 */

#include "spm-sieve.h"

ICOUNT icount;

// GLOBAL VARIABLES START

OBJ_Cat *OBJCategory;

// Global Reuse Distance Object
SetRD *GlobalRD;

// Store all objects here
vector<ObjectInstance> Objects;

// Blocks which have been freed; stored separately to ease searching in the currently active list
vector<ObjectInstance> freedObjects;

// Passed an Object Id fetch its Category
OBJ_TYPE getObjectCategory(UINT objId)
{
   OBJ_TYPE type;
   // find which set this belongs to
   if(objId == 0)
      type = SMALL_DYNAMIC;
   else if(objId == 1)
      type = OBJ_STACK;
   else if(OBJCategory[LARGE_STATIC].objects.find(objId) != OBJCategory[LARGE_STATIC].objects.end())
      type = LARGE_STATIC;
   else if(OBJCategory[SMALL_STATIC].objects.find(objId) != OBJCategory[SMALL_STATIC].objects.end())
      type = SMALL_STATIC;
   else if(OBJCategory[LARGE_DYNAMIC].objects.find(objId) != OBJCategory[LARGE_DYNAMIC].objects.end())
      type = LARGE_DYNAMIC;
   else {
      cerr << "Unable to Find Object " << objId << "in any Object Category\n";
      exit(1);
   }

   if((type == LARGE_DYNAMIC) && (KnobDemarcateLargeObject.Value() == false))
      type = LARGE_STATIC;

   return type;
}

// Sort function template to provide simple access and default comparison function
template <typename C, typename F = less<typename C::value_type>> 
void Sort( C& c, F f = F() )  { sort(begin(c), end(c), f); }

// I want to avoid MACROS, but these MACROS seems like a good use. Any alternatives to do it in pure C++ elegantly?
// Sort container objectss of class ObjectInstance in DESCENDING ORDER for member key; could be id, start, priority, llc_misses, etc
#define SORT_OBJECTS_ON_KEY(key) stable_sort(begin(Objects), end(Objects), [] (const ObjectInstance &a, const ObjectInstance &b) {return (a.key) > (b.key);});

#define COMPUTE_PRIORITY(exp) for_each( begin(Objects), end(Objects), [] (ObjectInstance &a) {a.priority = (exp);});


// compare two malloc objects entry based on their starting address
bool compare_start_address(const ObjectInstance & lhs, const ObjectInstance & rhs) 
{
    return lhs.start < rhs.start;
}

// compare two malloc objects entry based on their first access timestamp
bool compare_first_access(const ObjectInstance & lhs, const ObjectInstance & rhs) 
{
    return lhs.first_access < rhs.first_access;
}

// TODO: cleanup this function also returns the symbol name
string dump_callstack(ADDRINT size, ADDRINT ip)
{
    if (enable_maid)
    {
        // TODO: Some Call stacks miss out on the .plt before malloc - need to investigate
        // Get the Backtrace for this malloc from MAID
        MaidFile << "START_OBJECTID_" << object_count << endl;
        MaidFile << "Malloc - Stack dump initiated " << " pc=" << (void*)ip << " size=" << size << endl;
        MAID_print_callstack(MaidFile);
        MaidFile << "END_OBJECT" << endl;

        return MAID_get_array_symbol();
    }
    return "";
}

// add an object to the global object vector if it meets the size criteria
void add_object(ADDRINT start, ADDRINT size, ADDRINT ip, string type, string libname)
{
    // check if the entry already exists, maybe malloc got called twice for some reason
    auto it = lower_bound(Objects.begin(), Objects.end(), ObjectInstance(start, 0, 0), compare_start_address);
    if ( it != Objects.end() && it->start == start ) {
        DEBUG_PRINT("PIN: Object seen multiple times ID: " << it->id << endl);
        return;
    }

    string malloc_symbol = "";
    // new block identified; call MAID to print call stack for later identification of the object
    if((size > KnobLargeObjectSize.Value()) && (type.compare(NON_DYNAMIC) != 0)) {
       malloc_symbol = dump_callstack(size, ip);
       libname = "";
    }

    if((size > KnobLargeObjectSize.Value()) || (type.compare(NON_DYNAMIC) == 0)) {
       ObjectInstance tmp = ObjectInstance(start, size, ip);
       tmp.type = type;
       // the symbol for a static array has already been added to libname string in read_static_objects()
       tmp.image_name = malloc_symbol + libname;

       Objects.insert(it, tmp);

       object_count++;
       DEBUG_PRINT("PIN: Added " << type << " Object: Size: " << dec << size 
               << " Start addr: " << hex << start << dec << endl);
    }


    if(size > KnobLargeObjectSize.Value()) {
       if(type.compare(NON_DYNAMIC) == 0) {
          OBJCategory[LARGE_STATIC].objects.insert(object_count - 1);
          OBJCategory[LARGE_STATIC].size += size;
       }
       else {
          OBJCategory[LARGE_DYNAMIC].objects.insert(object_count - 1);
          OBJCategory[LARGE_DYNAMIC].size += size;
       }
    }
    else {
       if(type.compare(NON_DYNAMIC) == 0) {
          OBJCategory[SMALL_STATIC].objects.insert(object_count - 1);
          OBJCategory[SMALL_STATIC].size += size;
       }
       // SMALL_DYNAMIC not tracked
       else {
          static UINT dyn_blk_cnt = 0;
          dyn_blk_cnt++;
          OBJCategory[SMALL_DYNAMIC].objects.insert(dyn_blk_cnt - 1);
          OBJCategory[SMALL_DYNAMIC].size += size;
       }
    }

    return;
}

// stack to match malloc to its return
vector <ADDRINT> malloc_stack;
vector <ADDRINT> calloc_stack;

// Function called before entry to malloc
VOID BeforeMalloc(CHAR * name, ADDRINT size, ADDRINT ip)
{
    // start address is not yet known, will be known after exit
    malloc_stack.push_back(size);
    DEBUG_PRINT("PIN: Before Malloc: Size: " <<  dec << size <<  " Return IP: " << hex << ip << dec << endl);
}

// function called after exit of malloc
VOID AfterMalloc(ADDRINT ret, ADDRINT ip)
{
    // Get the size of the matching malloc from the stack
    ADDRINT size = malloc_stack.back();
    malloc_stack.pop_back();

    add_object(ret, size, ip, MALLOC, "dummy");
}

// Function called before entry to calloc
VOID BeforeCalloc(CHAR * name, ADDRINT nmemb, ADDRINT membsize, ADDRINT ip)
{
    ADDRINT size = nmemb*membsize;

    // start address is not yet known, will be known after exit
    calloc_stack.push_back(size);
    DEBUG_PRINT("PIN: Before Malloc: Size: " <<  dec << size <<  " Return IP: " << hex << ip << dec << endl);
}

// function called after exit of calloc
VOID AfterCalloc(ADDRINT ret, ADDRINT ip)
{
    // Get the size of the matching calloc from the stack
    ADDRINT size = calloc_stack.back();
    calloc_stack.pop_back();

    add_object(ret, size, ip, CALLOC, "dummy");
}

vector < pair<ADDRINT, ADDRINT> > memalign_stack;

// Function called before entry to malloc
VOID BeforePosix_memalign(ADDRINT size, ADDRINT ret, ADDRINT ip)
{
    // start address is not yet known, will be known after exit
    memalign_stack.push_back(make_pair(size, ret));
    DEBUG_PRINT("PIN: Before Malloc: Size: " <<  dec << size <<  " Return IP: " << hex << ip << dec << endl);
}

// function called after exit of malloc
VOID AfterPosix_memalign(ADDRINT ip)
{
    // Get the size of the matching malloc from the stack
    ADDRINT size = memalign_stack.back().first;
    ADDRINT ret  = memalign_stack.back().second;
    // TODO: read the return value
    //ADDRINT ret  = (long int *) *((long int*)memalign_stack.back().second);
    memalign_stack.pop_back();

    string tmp = "dummy";

    add_object(ret, size, ip, POSIX_MEMALIGN, StripPath(tmp));
}

// at free, remove entry from ObjectInstance vector and insert into freed blocks
VOID BeforeFree(CHAR * name, ADDRINT addr)
{
    if (0==addr) return;
    DEBUG_PRINT("PIN: Freeing: " << hex << addr << dec << endl);
    vector<class ObjectInstance>::iterator it;

    // Find this block in objects
    it = lower_bound(Objects.begin(), Objects.end(), ObjectInstance(addr, 0, 0), compare_start_address);
    if(it == Objects.end() || it->start != addr) {
        DEBUG_PRINT("PIN: Freed block does not exist in malloc entries. Addr: " << hex << addr << dec << endl);
        return;
    }

    it->valid = false;
    DEBUG_PRINT("PIN: Freed: " << hex << addr << dec << endl);

    // copy it to a new list; will be needed later
    freedObjects.insert(freedObjects.end(), *it);

    // erase it from the Objects list
    Objects.erase(it);
}


// Read static Objects from the binary and add to the list of Objects
// Static Objects are found by looking up symbols of type OBJECT using readelf
void read_static_objects(string program_name)
{
    char buffer [L_tmpnam];
    if (!tmpnam(buffer)) exit(1);
    string tempfile = string(buffer);

    //string cmd = "readelf -s " + program_name + " | grep OBJECT | cut -d: -f 2 > " + tempfile;
    string cmd = "readelf -s " + program_name + " | grep OBJECT > " + tempfile;
    DEBUG_PRINT("PIN: Running cmd: " << cmd << endl);
    int ret = system(cmd.c_str());
    if (-1 == ret) exit(-1);

    string line;
    ifstream fin (tempfile.c_str());

    while (fin.good())
    {
        getline(fin, line);
        if (0 == line.size() ) continue;

        // "readelf -s" entries look like this
        //  Num:    Value          Size Type    Bind   Vis      Ndx Name
        //  37: 000000000071e640     4 OBJECT  GLOBAL DEFAULT   26 __svml_feature_flag

        // split string on whitespace
        vector<string> toks = split(line);

        UINT64 start = strtoul(toks[1].c_str(), 0, 16); // base = 16; start address is hex but without the 0x prefix
        UINT64 size  = strtoul(toks[2].c_str(), 0, 0);  // base = 0; size value can be hex or decimal with appropriate prefix
        string symbol_name = toks[toks.size()-1];

        // Add the static array to the list of known objects
        add_object(start, size, 0, "static", symbol_name + " @ " + StripPath(program_name));
    }

    remove(tempfile.c_str());
}

// Instrument the malloc, free and posix_memalign functions
// And find all static mem blocks in Images
VOID Image(IMG img, VOID *v)
{
    string image_name = IMG_Name(img);
    //DEBUG_PRINT("PIN: Image name " << IMG_Name(img) << endl);
    cerr << "PIN: Image name " << image_name << endl;

    // Initialize ObjectInstance entries for static blocks in the binary
    if(IMG_Type(img) != IMG_TYPE_SHAREDLIB)
       read_static_objects(image_name);

    // Instrument main for MAID
    //if (enable_maid)
        //MAID_Instrument_main(img);

    // instrument MALLOC
    RTN mallocRtn = RTN_FindByName(img, MALLOC);
    if (RTN_Valid(mallocRtn))
    {
        cerr << "PIN: FOUND Routine " << RTN_Name(mallocRtn) << endl;
        RTN_Open(mallocRtn);

        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeMalloc,
                IARG_ADDRINT, MALLOC,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  //malloc size
                IARG_ADDRINT, IARG_RETURN_IP,      // callsite return IP
                IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)AfterMalloc,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

        RTN_Close(mallocRtn);
    }

    // instrument CALLOC
    RTN callocRtn = RTN_FindByName(img, CALLOC);
    if (RTN_Valid(callocRtn))
    {
        cerr << "PIN: FOUND Routine " << RTN_Name(callocRtn) << endl;
        RTN_Open(callocRtn);

        // Instrument calloc() to print the input argument value and the return value.
        RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)BeforeCalloc,
                IARG_ADDRINT, CALLOC,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  //calloc number of members
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  //calloc size of members
                IARG_ADDRINT, IARG_RETURN_IP,      // callsite return IP
                IARG_END);
        RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)AfterCalloc,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

        RTN_Close(callocRtn);
    }

    // instrument POSIX_MEMALIGN
    RTN memalignRtn = RTN_FindByName(img, POSIX_MEMALIGN);
    if (RTN_Valid(memalignRtn))
    {
        cerr << "PIN: FOUND Routine " << RTN_Name(memalignRtn) << endl;
        RTN_Open(memalignRtn);

        // Instrument calloc() to print the input argument value and the return value.
        RTN_InsertCall(memalignRtn, IPOINT_BEFORE, (AFUNPTR)BeforePosix_memalign,
                IARG_ADDRINT, POSIX_MEMALIGN,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // posix_memalign size, 3rd arg
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // the buffer address is stored here, a pointer to a pointer
                IARG_ADDRINT, IARG_RETURN_IP,      // callsite return IP
                IARG_END);
        RTN_InsertCall(memalignRtn, IPOINT_AFTER, (AFUNPTR)AfterPosix_memalign,
                IARG_END);

        RTN_Close(memalignRtn);
    }

    // instrument FREE
    RTN freeRtn = RTN_FindByName(img, FREE);
    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)BeforeFree,
                IARG_ADDRINT, FREE,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);
        RTN_Close(freeRtn);
    }
}

/* ===================================================================== */
/* Memory Reference Instrumentation routines                             */
/* ===================================================================== */


static VOID display_object_rd_distribution(ofstream &rdFile, UINT64 iCnt, UINT log2_start_cache_size, UINT log2_end_cache_size, vector<ObjectInstance> &objects)
{
    vector<UINT64> tmpMiss(log2_end_cache_size - log2_start_cache_size + 1);	// L1 - L2 all sizes in POW 2

    /* Individual Object Statistics */
    /* $$$$$$ DISPLAY FORMAT $$$$$$ */
    rdFile << "OBJECT_ID,TS,Accesses,Size,L1 Misses, 2 * L1 Misses, ..., L2 Misses" << endl;
    for(UINT j = 0; j < objects.size(); j++) {
        if(objects[j].accesses) {
            UINT index = log2_end_cache_size - log2_start_cache_size;
            UINT64 misses = 0;
            for(UINT m = log2_end_cache_size + 1; m < MAX_RD_BUCKETS; m++)
                misses += objects[j].reuseDistance[m];
            tmpMiss[index] = misses;    // highest Sz
            index--;

            for(UINT m = log2_end_cache_size; m > log2_start_cache_size; m--) {
                misses += objects[j].reuseDistance[m];
                tmpMiss[index] = misses;	// intermediate Sz, L1
                index--;
            }

            // find which set this belongs to
            OBJ_TYPE type = getObjectCategory(objects[j].id);
            if((type == LARGE_STATIC) || (type == LARGE_DYNAMIC) || KnobDisplayAllObjects.Value()) {
               rdFile << "Object_" << objects[j].id << ", "; // ID
               rdFile << iCnt  << ", ";  // TimeStamp
               rdFile << objects[j].accesses << ", ";  // Accesses
               rdFile << objects[j].size;  // Size
               for(UINT m = 0; m < tmpMiss.size(); m++)
                   rdFile << ", " << tmpMiss[m];  // Misses at all Levels
               rdFile << endl;
            }
        }
    }

    // Print the Header
    rdFile << "\n$$$$$ Object Category Wise Distribution $$$$$\n";
    rdFile << "Category,Num_Objects,Category_Size,Accesses,L1 Misses\n";
    if(KnobDemarcateLargeObject.Value()) {
       rdFile << "LARGE_STATIC,"
              << OBJCategory[LARGE_STATIC].objects.size() << ","
              << OBJCategory[LARGE_STATIC].size << ","
              << OBJCategory[LARGE_STATIC].accesses << ","
              << OBJCategory[LARGE_STATIC].misses << endl;
       rdFile << "LARGE_DYNAMIC,"
              << OBJCategory[LARGE_DYNAMIC].objects.size() << ","
              << OBJCategory[LARGE_DYNAMIC].size << ","
              << OBJCategory[LARGE_DYNAMIC].accesses << ","
              << OBJCategory[LARGE_DYNAMIC].misses << endl;
    }
    else
       rdFile << "LARGE,"
              << (OBJCategory[LARGE_STATIC].objects.size()+OBJCategory[LARGE_DYNAMIC].objects.size()) << ","
              << (OBJCategory[LARGE_STATIC].size+OBJCategory[LARGE_DYNAMIC].size) << ","
              << OBJCategory[LARGE_STATIC].accesses << ","
              << OBJCategory[LARGE_STATIC].misses << endl;
    rdFile << "SMALL_STATIC,"
           << OBJCategory[SMALL_STATIC].objects.size() << ","
           << OBJCategory[SMALL_STATIC].size << ","
           << OBJCategory[SMALL_STATIC].accesses << ","
           << OBJCategory[SMALL_STATIC].misses << endl;
    rdFile << "SMALL_DYNAMIC,"
           << OBJCategory[SMALL_DYNAMIC].objects.size() << ","
           << OBJCategory[SMALL_DYNAMIC].size << ","
           << OBJCategory[SMALL_DYNAMIC].accesses << ","
           << OBJCategory[SMALL_DYNAMIC].misses << endl;
    rdFile << "STACK,"
           << OBJCategory[OBJ_STACK].objects.size() << ","
           << OBJCategory[OBJ_STACK].size << ","
           << OBJCategory[OBJ_STACK].accesses << ","
           << OBJCategory[OBJ_STACK].misses << endl;

    rdFile << endl;
    OBJCategory[LARGE_STATIC].rd->printHistogram("CATEGORY_LARGE_STATIC", rdFile);
    if(KnobDemarcateLargeObject.Value())
       OBJCategory[LARGE_DYNAMIC].rd->printHistogram("CATEGORY_LARGE_DYNAMIC", rdFile);
    OBJCategory[SMALL_STATIC].rd->printHistogram("CATEGORY_SMALL_STATIC", rdFile);
    OBJCategory[SMALL_DYNAMIC].rd->printHistogram("CATEGORY_SMALL_DYNAMIC", rdFile);
    OBJCategory[OBJ_STACK].rd->printHistogram("CATEGORY_STACK", rdFile);

    UINT64 misses = 0, bucket = 0;
    for(; bucket < MAX_RD_BUCKETS; bucket++) {
       misses = OBJCategory[SMALL_DYNAMIC].rd->calculateMisses(bucket);
       if(misses <= OBJCategory[SMALL_DYNAMIC].misses)
          break;
    }
    rdFile << "\nESTIMATED_PARTITION_SIZE :\n";
    UINT cacheSize = 1 << (bucket + LOG2_CACHE_BLOCK_SIZE);
    rdFile << "CATEGORY_SMALL_DYNAMIC," << cacheSize << endl;

    misses = 0, bucket = 0;
    for(; bucket < MAX_RD_BUCKETS; bucket++) {
       misses = OBJCategory[SMALL_STATIC].rd->calculateMisses(bucket);
       if(misses <= OBJCategory[SMALL_STATIC].misses)
          break;
    }
    cacheSize = 1 << (bucket + LOG2_CACHE_BLOCK_SIZE);
    rdFile << "CATEGORY_SMALL_STATIC," << cacheSize << endl;

    misses = 0, bucket = 0;
    for(; bucket < MAX_RD_BUCKETS; bucket++) {
       misses = OBJCategory[LARGE_STATIC].rd->calculateMisses(bucket);
       if(misses <= OBJCategory[LARGE_STATIC].misses)
          break;
    }
    cacheSize = 1 << (bucket + LOG2_CACHE_BLOCK_SIZE);
    rdFile << "CATEGORY_LARGE_STATIC," << cacheSize << endl;

    if(KnobDemarcateLargeObject.Value()) {
       misses = 0, bucket = 0;
       for(; bucket < MAX_RD_BUCKETS; bucket++) {
          misses = OBJCategory[LARGE_DYNAMIC].rd->calculateMisses(bucket);
          if(misses <= OBJCategory[LARGE_DYNAMIC].misses)
             break;
       }
       cacheSize = 1 << (bucket + LOG2_CACHE_BLOCK_SIZE);
       rdFile << "CATEGORY_LARGE_DYNAMIC," << cacheSize << endl;
    }

    misses = 0, bucket = 0;
    for(; bucket < MAX_RD_BUCKETS; bucket++) {
       misses = OBJCategory[OBJ_STACK].rd->calculateMisses(bucket);
       if(misses <= OBJCategory[OBJ_STACK].misses)
          break;
    }
    cacheSize = 1 << (bucket + LOG2_CACHE_BLOCK_SIZE);
    rdFile << "CATEGORY_STACK," << cacheSize << endl;
}

/* This routine can be called at any point in the 
 * lifetime of program to Dump out the all relevant
 * characteristics of the whole program as well as
 * of the individual objects */
VOID Display_Global_RD_Distribution(ofstream &rdFile, UINT64 iCnt, UINT log2_start_cache_size, UINT log2_end_cache_size)
{
    log2_start_cache_size -= LOG2_CACHE_BLOCK_SIZE;
    log2_end_cache_size -= LOG2_CACHE_BLOCK_SIZE;
    assert(log2_end_cache_size >= log2_start_cache_size);

    rdFile << dec << endl << endl;
    rdFile << "$$$$$$ Object Access & Miss Distribution @ : " << iCnt << " $$$$$$\n";
    // Display for Individual Objects
    display_object_rd_distribution(rdFile, iCnt, log2_start_cache_size, log2_end_cache_size, Objects);
    if(!freedObjects.empty())
        display_object_rd_distribution(rdFile, iCnt, log2_start_cache_size, log2_end_cache_size, freedObjects);

    /* Global Statistics */
    /* $$$$$$ DISPLAY FORMAT $$$$$$ */
    rdFile << "# TOTAL BLOCKS,TS,Accesses,L1 Misses,2 * L1 Misses, ... ,L2 Misses" << endl;
    vector<UINT64> tmpMiss(log2_end_cache_size - log2_start_cache_size + 1);	// L1, ... , L2
    UINT index = log2_end_cache_size - log2_start_cache_size;
    tmpMiss[index] = GlobalRD->calculateMisses(log2_end_cache_size);	// L2 Sz
    index--;

    for(UINT m = log2_end_cache_size - 1; m > log2_start_cache_size; m--) {
       tmpMiss[index] = GlobalRD->calculateMisses(m);	// intermediate Sz
       index--;
    }

    assert(index == 0);
    tmpMiss[index] = GlobalRD->calculateMisses(log2_start_cache_size);	// L1 Sz

    // Update global vars
    l2_misses = tmpMiss.back();
    l1_misses = tmpMiss.front();


    rdFile << "TOTAL_BLOCKS, " << object_count << ", " << iCnt << ", " << total_accesses;
    for(UINT m = 0; m < tmpMiss.size(); m++)
        rdFile << ", " << tmpMiss[m];  // Misses at all Levels
    rdFile << endl;

    rdFile << dec << "$$$$$$$$$$$$$$$$$$$$$$$\n";
}

// dumps the instantaneous cache stats to a file; used for plotting timeline behavior of cache
VOID dump_cache_stats()
{
    static ofstream of;
    static bool header=false;
    static ADDRINT prev_accesses = 0;
    static ADDRINT prev_l1_misses = 0;
    static ADDRINT prev_l2_misses = 0;

    if(!header) {
        of.open(KnobOutputFile.Value() + "-cache-stats.csv");
        of << "TSC,Accesses,L1 misses,L2 misses" << endl;
        header = true;
    }

    of << get_inscount() << ","
        << total_accesses - prev_accesses << ","
        << l1_misses - prev_l1_misses << "," 
        << l2_misses - prev_l2_misses << endl;

    prev_accesses = total_accesses;
    prev_l1_misses = l1_misses;
    prev_l2_misses = l2_misses;
}

bool AccPrioFunc(const pair<string, UINT64> &a, const pair<string, UINT64> &b)
{
    return a.second > b.second;
}


#ifdef OBJECT_ALLOC_HISTOGRAM
VOID Display_Access_Histogram(ofstream &rdFile)
{
   vector<pair<string, UINT64> > sortedObjects;
   map<string, UINT64> scopeHist;

   rdFile << "-------- OBJECT ACCESS DISTRIBUTION --------\n";
   // Object Wise Distribution
   for(INT i = 0; i < Objects.size(); i++) {
      rdFile << "\n **** Object_" << Objects[i].id << " ****\n";
      rdFile << "First Location," << Objects[i].firstLoc << endl;
      rdFile << "Last Location," << Objects[i].lastLoc << endl;
      rdFile << "Num Locs," << Objects[i].accHist.size() << endl;

      sortedObjects.clear();
      for(auto it: Objects[i].accHist) {
         sortedObjects.push_back(make_pair(it.first, it.second));

         if(scopeHist.find(it.first) == scopeHist.end())
            scopeHist[it.first] = it.second;
         else
            scopeHist[it.first] += it.second;
      }

      stable_sort(sortedObjects.begin(), sortedObjects.end(), AccPrioFunc);
      rdFile << "Histogram\n";
      for(INT j = 0; j < sortedObjects.size(); j++)
         rdFile << sortedObjects[j].first << "," << sortedObjects[j].second << endl;
   }
   rdFile << endl;

}
#endif

bool arrayPrioFunc(const pair<int, double> &a, const pair<int, double> &b)
{
    return a.second > b.second;
}

/* ===================================================================== */

// Check cache line alignment for a given access
bool is_aligned_p(ADDRINT addr, INT64 len) 
{
    //cout << "Addr: " << hex << addr << dec << " Len: " << len << endl;
    return ( (addr >> LOG2_CACHE_BLOCK_SIZE) == ((addr+len-1) >> LOG2_CACHE_BLOCK_SIZE) );
}

/***********************************************************************
 *
 * Description of find_object()
 * 
 * Given the addr of a memory reference find_object() returns an iterator to the matching array 
 * or the default bucket in case the addr does not belong to one of the known objects.
 *
 * This is essentially an interval search, where the start and end of an object are its interval.
 * The vector "Objects" is sorted on the start address in ascending order.
 * The vector contains only active objects so they have non-overlapping ranges.
 * The first element of the object vector is a default bucket to capture addresses 
 * which dont fall into any known object. It has a start address of zero and a null range.
 * 
 * The input memory addr can be in one of the following cases, according to which we arrange the logic of the search:
 * 1. between zero and the start address of the first object (lowest start addr) - return default bucket
 * 2. between two object intervals - return default bucket
 * 3. after the last object's interval - return default bucket
 * 4. in the middle of an object's interval and the object is not the last object - return the object
 * 5. the start of an object - return the array
 * 6. in the middle of the last object's interval - return the last object
 *
 * We use lower_bound() to search on the sorted(ascending on start addr) vector of objects
 * The key thing to remember is that lower_bound() returns the first object 
 * whose start addr is not less than the addr of the mem reference
 * lower_bound() will return the vector's end sentinel for case 3 and 6 above
 *
 **********************************************************************/

vector<ObjectInstance>::iterator find_object(ADDRINT addr)
{
    auto it = lower_bound(Objects.begin(), Objects.end(), ObjectInstance(addr, 0, 0), compare_start_address); 

    // catch case 3 and 6 which both return objects.end(), but whereas case 6 is a match on the last element
    // case 3 does not match any objects and should return the default bucket
    if( it == Objects.end() ) {
        // check for case 6
        if (addr >= (Objects.end()-1)->start && addr < (Objects.end()-1)->end )
            return Objects.end() - 1;       
        else // case 3
            return Objects.begin();         
    }

    // adjust iterator for case 4; lower_bound returns the next array and we need to move the iterator one back
    if (it->start != addr)
        it--;

    // case 4 and 5 check that addr lies in the array's interval and return it
    if( addr >= it->start && addr < it->end )
        return it;
    // case 1 and 2, no match found, return the default bucket
    else
        return Objects.begin();
}

VOID accessUnifiedMemory(ADDRINT ip, ADDRINT addr, INT64 size, BOOL is_read, BOOL isStack)
{
    string scope_in_progress = RTN_FindNameByAddress(ip);

    // find array for the access
    vector<ObjectInstance>::iterator object;
    if(!isStack)
       object = find_object(addr);
    else
       object = Objects.begin() + 1;

    // update accesses, writes and TSC stats
    total_accesses++;
    object->accesses++;
    if (!is_read) { total_writes++; object->writes++;}

    if (0 == object->first_access)  // update access timestamp
        object->first_access = get_inscount();
    object->last_access = get_inscount();

#ifdef OBJECT_ALLOC_HISTOGRAM
    /********** Update all Scope Distribution ************/
    if(object->firstLoc.empty())
       object->firstLoc = scope_in_progress;
    object->lastLoc = scope_in_progress;
    if(object->accHist.find(scope_in_progress) == object->accHist.end())
       object->accHist[scope_in_progress] = 1;
    else
       object->accHist[scope_in_progress]++;
#endif

    // access RD and update RD stats
    if (enable_rd) {
        static INT L1_RD_BUCKET = LOG2_L1_SIZE - LOG2_CACHE_BLOCK_SIZE;
        INT rd = GlobalRD->process_memory_access((VOID *)ip, addr, size);
        if(rd >= 0)
            object->reuseDistance[rd]++;

        OBJ_TYPE type = getObjectCategory(object->id);
        OBJCategory[type].rd->process_memory_access((VOID *)ip, addr, size);
        OBJCategory[type].accesses++;
        if(rd > L1_RD_BUCKET)
           OBJCategory[type].misses++;
    }
}

// Print out the detailed object profile for analysis
VOID print_object_profile()
{
    std::ofstream outf;
    outf.open(KnobOutputFile.Value() + "-object-profile.csv");

    // print HEADER
    outf << "Num Objects,Num Instructions,Accesses,Writes,L1 Misses, L2 Misses\n";
    outf << Objects.size()  << "," 
        <<  get_inscount() << ", "<< total_accesses << "," << total_writes << ","
        << l1_misses << "," << l2_misses << endl;
    outf << endl;

    // print per object data
    outf << "Object ID,Object Start,Size(bytes),Type,Symbol@Lib,TSC First Access,TSC Last Access,Accesses,Writes,L1 Misses, L2 Misses\n";

    for(auto object : Objects) {
        outf << "OBJECT_ID_" << object.id << ",0x" << hex << object.start << "," << dec << object.size << ","
            << object.type << "," << object.image_name << ","
            << object.first_access << "," << object.last_access << "," << object.accesses << "," << object.writes << ","
            << object.l1_misses << "," << object.l2_misses << endl; 
    }
}

// return size of the access from addr till the end of the current cacheline
UINT get_cur_access_size(ADDRINT addr, UINT size)
{
    static UINT LINE_OFFSET_MASK = (1UL << KnobBlockSize.Value()) - 1;

    return MIN((size), (64 - (addr & (LINE_OFFSET_MASK))));
}

// return no of cachelines needed for this access beginning at addr and size long
UINT get_num_cachelines_for_access(ADDRINT addr, UINT size)
{
    static UINT CACHE_BLOCK_SIZE = KnobBlockSize.Value();
    return (((addr + size - 1) >> CACHE_BLOCK_SIZE) - (addr >> CACHE_BLOCK_SIZE)) + 1;
}

/******************************************************************
 * This routine is the instrumentation routine called with the
 * length of the access
*******************************************************************/
VOID process_memory_access(VOID * ip, VOID *addr, INT64 size, BOOL isRead, BOOL isStack)
{
    ADDRINT a_addr = (ADDRINT)addr;
    // An unaligned access can access multiple cachelines, find out how many
    // and access caches for each of those cachelines
    UINT numcl = get_num_cachelines_for_access(a_addr, size);

    ADDRINT remaining_size = size;
    UINT cur_access_size;

    for (UINT i = 0; i< numcl; i++) {
        cur_access_size = get_cur_access_size(a_addr, remaining_size);    // find size of bytes accessed in this cacheline
        accessUnifiedMemory((ADDRINT)ip, a_addr, cur_access_size, isRead, isStack);
        a_addr += cur_access_size;                                        // advance addr to the next cacheline
        remaining_size -= cur_access_size;                              // reduce size of the access
    }
}

/**********************************************************************
 * Is called for every instruction and instruments reads and writes
***********************************************************************/
VOID InstrumentMemAccesses(INS ins)
{
    // instruments loads using a predicated call, i.e.
    // the call happens iff the load will be actually executed
    // (this does not matter for ia32 but arm and ipf have predicated instructions)

    if (INS_IsMemoryRead(ins)) {
      if (INS_IsStackRead(ins)) {
        if(KnobStackAccesses.Value())
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)process_memory_access,
            IARG_INST_PTR,
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL,
            1,
            IARG_BOOL,
            1,
            IARG_END);
      } else {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)process_memory_access,
            IARG_INST_PTR,
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL,
            1,
            IARG_BOOL,
            0,
            IARG_END);
      }
    }

    // instruments loads using a predicated call, i.e.
    // the call happens iff the load will be actually executed
    // (this does not matter for ia32 but arm and ipf have predicated instructions)
    if (INS_HasMemoryRead2(ins)) {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)process_memory_access,
            IARG_INST_PTR,
            IARG_MEMORYREAD_EA,
            IARG_MEMORYREAD_SIZE,
            IARG_BOOL,
            1,
            IARG_BOOL,
            0,
            IARG_END);
    }


    // instruments stores using a predicated call, i.e.
    // the call happens iff the store will be actually executed
    if (INS_IsMemoryWrite(ins)) {
      if (INS_IsStackWrite(ins)) {
        if(KnobStackAccesses.Value())
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)process_memory_access,
            IARG_INST_PTR,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_BOOL,
            0,
            IARG_BOOL,
            1,
            IARG_END);
      } else {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)process_memory_access,
            IARG_INST_PTR,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_BOOL,
            0,
            IARG_BOOL,
            0,
            IARG_END);
      }
    }
} // END Instruction

/********************************************************
 * This function will be called for each TRACE by PIN
*********************************************************/
VOID Trace(TRACE trace, VOID * val)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
           InstrumentMemAccesses(ins);
        }
    }
}

VOID Detach_callback(VOID *v)
{

    // Join the malloc and free blocks
    Objects.insert(Objects.end(), freedObjects.begin(), freedObjects.end());

    // Sort on first_access since that will give a unique ordering
    // All sorts should be stable_sort after this point
    // We have a unique order on the objects in the field ID
    SORT_OBJECTS_ON_KEY(id);

    freedObjects.clear();

    if (enable_maid)
        MaidFile.close();

    if (enable_rd) {
       Display_Global_RD_Distribution(OutFile, get_inscount(), LOG2_L1_SIZE, LOG2_L2_SIZE);
       // dump cache stats timeline in a csv file for later analysis
       dump_cache_stats();
#ifdef OBJECT_ALLOC_HISTOGRAM
       Display_Access_Histogram(OutFile);
#endif
    }

    if (KnobObjectProfile.Value())
        print_object_profile();
}

VOID Fini(INT32 code, VOID *v)
{
    Detach_callback(v);
}

/* ===================================================================== */
/* Initialize config, caches, etc.                                       */
/* ===================================================================== */

void InitSPM_Sieve()
{
    activate_inscount();

    // Write to a file since cout and cerr maybe closed by the application
    OutFile.open(KnobOutputFile.Value().c_str());
    OutFile << hex;
    OutFile.setf(ios::showbase);

    // Skip Instruction count
    start_icount = KnobStartIcount.Value();
    end_icount   = KnobEndIcount.Value();
    LOG2_CACHE_BLOCK_SIZE = KnobBlockSize.Value();
    LOG2_L1_SIZE = log2(KnobL1Size.Value());
    LOG2_L2_SIZE = log2(KnobL2Size.Value());

    enable_rd = KnobEnableRD.Value();
    if(enable_rd)
       GlobalRD = new SetRD(KnobNumSets.Value(), KnobBlockSize.Value());

    // Open "maid.out" file
    enable_maid = KnobEnableMAID.Value();
    if (enable_maid) {
        MaidFile.open("maid.out");
        cerr << "Maid Enabled : Disabling RD Profiling\n";
        enable_rd = false;
    }

    // Initialize the bucket entry for unidentified/small blocks
    Objects.push_back(ObjectInstance(0, 0, 0));
    (Objects.end()-1)->type = "default";
    object_count++; // dummy increment to block count to keep ID's happy

    // Add stack
    Objects.push_back(ObjectInstance(1, 0, 0));
    (Objects.end()-1)->type = "stack";
    object_count++; // dummy increment to block count to keep ID's happy

    OBJCategory = new OBJ_Cat[OBJ_TYPE_NUM];

    OutFile << dec << "*********** SPM-SIEVE Initialization Done ***********\n";
    cerr << "*********** SPM-SIEVE Initialization Done ***********\n";
    OutFile << "Cache Line Size : " << (1 << LOG2_CACHE_BLOCK_SIZE) << endl;
    cerr << "Cache Line Size : " << (1 << LOG2_CACHE_BLOCK_SIZE) << endl;
    OutFile << "L1 Cache Size : " << KnobL1Size.Value() << endl;
    cerr << "L1 Cache Size : " << KnobL1Size.Value() << endl;
    OutFile << "L2 Cache Size : " << KnobL2Size.Value() << endl;
    cerr << "L2 Cache Size : " << KnobL2Size.Value() << endl;
}

INT32 Usage()
{
    cerr << "This tool profiles an application and estimates object category partition " << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) ) return Usage();

    // initialize SPM-Sieve
    InitSPM_Sieve();

    if (!enable_maid)
       TRACE_AddInstrumentFunction(Trace, 0);
    IMG_AddInstrumentFunction(Image, 0);

    PIN_AddFiniFunction(Fini, 0);
    PIN_AddDetachFunction(Detach_callback, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
