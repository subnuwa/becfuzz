#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <cstddef>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include "config.h"

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

#include <map>
#include <sstream>
#include <climits>
#include <set>
using namespace std;

#include "instConfig.h"
// DyninstAPI includes
#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"


using namespace Dyninst;

//cmd line options
char *originalBinary;
char *instrumentedBinary;
bool verbose = false;
set<string> instrumentLibraries;
set<string> runtimeLibraries;
char* branch_dir = NULL;  //Output dir of examined branches
char* tracer_dir = NULL; //some addresses will be read from tracer
Category bin_cate = BIN_NONE; // category of the binary: crash/tracer/oracle
bool mainExit=false; //true when it's the first time running tracer
bool isOracle = false; //rosen
bool isTracer = false;
//bool isCrash = false;
bool isTrimmer = false; //rosen


//addresses
multimap <unsigned long, unsigned long> indcall_addrs;
multimap <unsigned long, unsigned long> indjump_addrs; //deduplicate indirect pairs
set <unsigned long> condnot_addrs;
set <unsigned long> condtaken_addrs;

// addrs of marks (for differentiating paths)
multimap <unsigned long, unsigned long> mark_indcall_addrs;
multimap <unsigned long, unsigned long> mark_indjump_addrs;
set <unsigned long> mark_condnot_addrs;
set <unsigned long> mark_condtaken_addrs;


// callback functions
BPatch_function *initAflForkServer;
BPatch_function *getIndAddrs;
BPatch_function *BBCallback;
BPatch_function *ConditionJump;
BPatch_function *ConditionMark;
BPatch_function *IndirectBranch;
BPatch_function *clearMaps;
BPatch_function *atMainExit;



const char *instLibrary = "./libBECFuzzDyninst.so";

static const char *OPT_STR = "i:o:l:veB:E:r:CTOM";
static const char *USAGE = " -i <binary> -o <binary> -l <library> -B <out-dir> -E <tracer-dir> -T\n \
    Analyse options:\n \
            -i: Input binary \n \
            -o: Output binary\n \
            -l: Linked library to instrument (repeat for more than one)\n \
            -e: exit when met main?\n \
            -r: Runtime library to instrument (path to, repeat for more than one)\n \
            -B: Output dir of examined branches (addresses)\n \
            -v: Verbose output\n \
            -E: Extended addresses from tracer\n \
    Binary type options:\n \
            -C: for the crash binary\n \
            -T: for the tracer binary\n \
            -O: for the oracle binary\n \
            -M: for the trimmer binary\n";

bool parseOptions(int argc, char **argv)
{

    int c;
    while ((c = getopt (argc, argv, OPT_STR)) != -1) {
        switch ((char) c) {
        case 'i':
            originalBinary = optarg;
            break;
        case 'o':
            instrumentedBinary = optarg;
            break;
        case 'l':
            instrumentLibraries.insert(optarg);
            break;
        case 'r':
            runtimeLibraries.insert(optarg);
            break;
        case 'e':
            mainExit = true;
            break;
        case 'B':
            branch_dir = optarg;
            break;
        case 'E':
            tracer_dir = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'C':
            bin_cate = BIN_CRASH;
            break;
        case 'T':
            bin_cate = BIN_TRACER;
            isTracer = true;
            break;
        case 'O':
            bin_cate = BIN_ORACLE;
            isOracle = true;
            break;
        case 'M':
            bin_cate = BIN_TRIMMER;
            isTrimmer = true;
            break;
        default:
            cerr << "Usage: " << argv[0] << USAGE;
            return false;
        }
    }

    if(originalBinary == NULL) {
        cerr << "Input binary is required!"<< endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(instrumentedBinary == NULL) {
        cerr << "Output binary is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(branch_dir == NULL){
        cerr << "Output directory for addresses is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    if(bin_cate == BIN_NONE){
        cerr << "For oracle/tracer/crash/trimmer (-C/-T/-O/-M) binary is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    return true;
}

//skip some functions
bool isSkipFuncs(char* funcName){
    if (string(funcName) == string("first_init") ||
        string(funcName) == string("__mach_init") ||
        string(funcName) == string("_hurd_init") ||
        string(funcName) == string("_hurd_preinit_hook") ||
        string(funcName) == string("doinit") ||
        string(funcName) == string("doinit1") ||
        string(funcName) == string("init") ||
        string(funcName) == string("init1") ||
        string(funcName) == string("_hurd_subinit") ||
        string(funcName) == string("init_dtable") ||
        string(funcName) == string("_start1") ||
        string(funcName) == string("preinit_array_start") ||
        string(funcName) == string("_init") ||
        string(funcName) == string("init") ||
        string(funcName) == string("fini") ||
        string(funcName) == string("_fini") ||
        string(funcName) == string("_hurd_stack_setup") ||
        string(funcName) == string("_hurd_startup") ||
        string(funcName) == string("register_tm_clones") ||
        string(funcName) == string("deregister_tm_clones") ||
        string(funcName) == string("frame_dummy") ||
        string(funcName) == string("__do_global_ctors_aux") ||
        string(funcName) == string("__do_global_dtors_aux") ||
        string(funcName) == string("__libc_csu_init") ||
        string(funcName) == string("__libc_csu_fini") ||
        string(funcName) == string("start") ||
        string(funcName) == string("_start") || 
        string(funcName) == string("__libc_start_main") ||
        string(funcName) == string("__gmon_start__") ||
        string(funcName) == string("__cxa_atexit") ||
        string(funcName) == string("__cxa_finalize") ||
        string(funcName) == string("__assert_fail") ||
        string(funcName) == string("_dl_start") || 
        string(funcName) == string("_dl_start_final") ||
        string(funcName) == string("_dl_sysdep_start") ||
        string(funcName) == string("dl_main") ||
        string(funcName) == string("_dl_allocate_tls_init") ||
        string(funcName) == string("_dl_start_user") ||
        string(funcName) == string("_dl_init_first") ||
        string(funcName) == string("_dl_init")) {
        return true; //skip these functions
        }
    return false;    
}


//count the number of indirect and conditaional edges
bool count_edges(){



    return true;
}




int main (int argc, char **argv){

     if(!parseOptions(argc,argv)) {
        return EXIT_FAILURE;
    }



    /* start instrumentation*/
    BPatch bpatch;
    // skip all libraries unless -l is set
    BPatch_binaryEdit *appBin = bpatch.openBinary (originalBinary, false);
    if (appBin == NULL) {
        cerr << "Failed to open binary" << endl;
        return EXIT_FAILURE;
    }

    if(!instrumentLibraries.empty()){
        for(auto lbit = instrumentLibraries.begin(); lbit != instrumentLibraries.end(); lbit++){
            if (!appBin->loadLibrary ((*lbit).c_str())) {
                cerr << "Failed to open instrumentation library " << *lbit << endl;
                cerr << "It needs to be located in the current working directory." << endl;
                return EXIT_FAILURE;
            }
        }
    }

    BPatch_image *appImage = appBin->getImage ();

    
    vector < BPatch_function * > allFunctions;
    appImage->getProcedures(allFunctions);

    if (!appBin->loadLibrary (instLibrary)) {
        cerr << "Failed to open instrumentation library " << instLibrary << endl;
        cerr << "It needs to be located in the current working directory." << endl;
        return EXIT_FAILURE;
    }

    initAflForkServer = findFuncByName (appImage, (char *) "initAflForkServer");
    IndirectBranch = findFuncByName (appImage, (char *) "IndirectBranch");
    
    
    //indirect addresses pairs
    getIndAddrs = findFuncByName (appImage, (char *) "getIndirectAddrs");
    clearMaps = findFuncByName (appImage, (char *) "clearMultimaps");
    
    //conditional jumps
    ConditionJump = findFuncByName (appImage, (char *) "ConditionJump");
    BBCallback =  findFuncByName (appImage, (char *) "BBCallback");
    ConditionMark = findFuncByName (appImage, (char *) "ConditionMark");
    

    atMainExit = findFuncByName (appImage, (char *) "atMainExit");


    if (!initAflForkServer || !ConditionJump || !IndirectBranch || !ConditionMark
        || !getIndAddrs || !clearMaps || !BBCallback || !atMainExit) {
        cerr << "Instrumentation library lacks callbacks!" << endl;
        return EXIT_FAILURE;
    }


    /* count the number of edges for the length of hash table
    1. num_c = the number of conditional edges
    2. num_i = the number of indirect call/jump sites
    3. length of hash table = num_c + num_i
    */
   // iterate over all functions
    for (countIter = allFunctions.begin (); countIter != allFunctions.end (); ++countIter) {
        BPatch_function *countFunc = *countIter;
        char funcName[1024];
        countFunc->getName (funcName, 1024);
        if(isSkipFuncs(funcName)) continue;
        //count edges
        //TODO: get the the number of edges; use pipe to transfer the values to afl
        count_edges();     
    }


    /*
        instrument at edges
    */
   /*TODO:
   1. insert at conditional edges, and like afl
   2.  insert at indirect edges, and compare edges dynamically:
        1) the first id of an indirect edge is the number of conditional edges num_c
        2) use unorder_map to maintain [(src_addr, des_addr), id]
        3) ###each time it encounters a new edge, restart executing the target; this will
            load the unorder_map to check the id;
        OR: at the beginning of main, insert a global unorder_map to record [(src_addr, des_addr), id]
        4) at each indirect edge, when meeting a new indirect edge, write the [(src_addr, des_addr), id] 
            into a file to record them; it can be reused if fuzzing stops accidently
    */
    for (funcIter = allFunctions.begin (); funcIter != allFunctions.end (); ++funcIter) {
        BPatch_function *curFunc = *funcIter;
        char funcName[1024];
        curFunc->getName (funcName, 1024);
        if(isSkipFuncs(funcName)) continue;
        //instrument at edges
    
    }

}