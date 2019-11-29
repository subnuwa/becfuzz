#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cmath>

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

//hash table length
#define NUM_INDIRECT_TARGETS 5  // carefully
static u32 num_conditional, // the number of total conditional edges
            num_indirect,   // the number of total indirect edges
            max_map_id, // the number of all edges, including potential indirect edges
            condition_id; // assign unique id for each conditional edges


//cmd line options
char *originalBinary;
char *instrumentedBinary;
bool verbose = false;
set<string> instrumentLibraries;
set<string> runtimeLibraries;
char* becfuzz_dir = NULL;  //Output dir of becfuzz results
//char* tracer_dir = NULL; //some addresses will be read from tracer
//Category bin_cate = BIN_NONE; // category of the binary: crash/tracer/oracle
//bool mainExit=false; //true when it's the first time running tracer
//bool isOracle = false; //rosen
//bool isTracer = false;
//bool isCrash = false;
//bool isTrimmer = false; //rosen


// //addresses
// multimap <u32, u32> indcall_addrs;
// multimap <u32, u32> indjump_addrs; //deduplicate indirect pairs
// set <u32> condnot_addrs;
// set <u32> condtaken_addrs;

// // addrs of marks (for differentiating paths)
// multimap <u32, u32> mark_indcall_addrs;
// multimap <u32, u32> mark_indjump_addrs;
// set <u32> mark_condnot_addrs;
// set <u32> mark_condtaken_addrs;


// callback functions
BPatch_function *ConditionJump;


// BPatch_function *initAflForkServer;
// BPatch_function *getIndAddrs;
// BPatch_function *BBCallback;
// BPatch_function *ConditionMark;
// BPatch_function *IndirectBranch;
// BPatch_function *clearMaps;
// BPatch_function *atMainExit;



const char *instLibrary = "./libBECFuzzDyninst.so";

static const char *OPT_STR = "i:o:l:vb:E:r:";
static const char *USAGE = " -i <binary> -o <binary> -b <becfuzz-dir> -l <linked-library> -r <runtime-library>\n \
    Analyse options:\n \
            -i: Input binary \n \
            -o: Output binary\n \
            -l: Linked library to instrument (repeat for more than one)\n \
            -r: Runtime library to instrument (path to, repeat for more than one)\n \
            -b: Output dir of becfuzz results\n \
            -v: Verbose output\n";

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
        case 'b':
            becfuzz_dir = optarg;
            break;
        case 'v':
            verbose = true;
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

    if(becfuzz_dir == NULL){
        cerr << "Output directory for addresses is required!" << endl;
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }

    // if(bin_cate == BIN_NONE){
    //     cerr << "For oracle/tracer/crash/trimmer (-C/-T/-O/-M) binary is required!" << endl;
    //     cerr << "Usage: " << argv[0] << USAGE;
    //     return false;
    // }

    return true;
}

BPatch_function *findFuncByName (BPatch_image * appImage, char *funcName)
{
    BPatch_Vector < BPatch_function * >funcs;

    if (NULL == appImage->findFunction (funcName, funcs) || !funcs.size ()
        || NULL == funcs[0]) {
        cerr << "Failed to find " << funcName << " function." << endl;
        return NULL;
    }

    return funcs[0];
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
bool count_edges(BPatch_binaryEdit * appBin, BPatch_image *appImage, 
                    vector < BPatch_function * >::iterator funcIter, char* funcName){
    BPatch_function *curFunc = *funcIter;
    BPatch_flowGraph *appCFG = curFunc->getCFG ();

    BPatch_Set < BPatch_basicBlock * > allBlocks;
    if (!appCFG->getAllBasicBlocks (allBlocks)) {
        cerr << "Failed to find basic blocks for function " << funcName << endl;
        return false;
    } else if (allBlocks.size () == 0) {
        cerr << "No basic blocks for function " << funcName << endl;
        return false;
    }

    set < BPatch_basicBlock *>::iterator bb_iter;
    for (bb_iter = allBlocks.begin (); bb_iter != allBlocks.end (); bb_iter++){
        BPatch_basicBlock * block = *bb_iter;
        vector<pair<Dyninst::InstructionAPI::Instruction, Dyninst::Address> > insns;
        block->getInstructions(insns);

        //Dyninst::Address addr = insns.back().second;  //addr: equal to offset when it's binary rewrite
        Dyninst::InstructionAPI::Instruction insn = insns.back().first; 
        //Dyninst::InstructionAPI::Operation op = insn.getOperation();
        Dyninst::InstructionAPI::InsnCategory category = insn.getCategory();
        //Dyninst::InstructionAPI::Expression::Ptr expt = insn.getControlFlowTarget();

        //conditional jumps
        vector<BPatch_edge *> outgoingEdge;
        (*bb_iter)->getOutgoingEdges(outgoingEdge);
        vector<BPatch_edge *>::iterator edge_iter;

        for(edge_iter = outgoingEdge.begin(); edge_iter != outgoingEdge.end(); ++edge_iter) {
            //count conditional
            if ((*edge_iter)->getType() == CondJumpTaken){
                num_conditional++;
            }
            else if ((*edge_iter)->getType() == CondJumpNottaken){
                  num_conditional++;
            }        
            
        }

        //indirect edges
        for(Dyninst::InstructionAPI::Instruction::cftConstIter iter = insn.cft_begin(); iter != insn.cft_end(); ++iter) {
            if(iter->isIndirect) {
                
                if(category == Dyninst::InstructionAPI::c_CallInsn) {//indirect call
                    num_indirect++;
                }
                
                else if(category == Dyninst::InstructionAPI::c_BranchInsn) {//indirect jump
                     num_indirect++;              
                }
 
            }
        }
    }

    
}

// instrument at conditional edges
bool instrumentCondition(BPatch_binaryEdit * appBin, BPatch_function * instFunc, BPatch_point * instrumentPoint, 
         Dyninst::Address block_addr, u32 cond_id){
    vector<BPatch_snippet *> cond_args;
    BPatch_constExpr CondID(cond_id);
    cond_args.push_back(&CondID);

    BPatch_funcCallExpr instCondExpr(*instFunc, cond_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instCondExpr, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << block_addr << endl;
            return false;
        }
    return true;         

}


//instrument at edges
bool edgeInstrument(BPatch_binaryEdit * appBin, BPatch_image *appImage, 
                    vector < BPatch_function * >::iterator funcIter, char* funcName, fs::path num_edge_file){
    BPatch_function *curFunc = *funcIter;
    BPatch_flowGraph *appCFG = curFunc->getCFG ();

    BPatch_Set < BPatch_basicBlock * > allBlocks;
    if (!appCFG->getAllBasicBlocks (allBlocks)) {
        cerr << "Failed to find basic blocks for function " << funcName << endl;
        return false;
    } else if (allBlocks.size () == 0) {
        cerr << "No basic blocks for function " << funcName << endl;
        return false;
    }

    set < BPatch_basicBlock *>::iterator bb_iter;
    for (bb_iter = allBlocks.begin (); bb_iter != allBlocks.end (); bb_iter++){
        BPatch_basicBlock * block = *bb_iter;
        vector<pair<Dyninst::InstructionAPI::Instruction, Dyninst::Address> > insns;
        block->getInstructions(insns);

        Dyninst::Address addr = insns.back().second;  //addr: equal to offset when it's binary rewrite
        Dyninst::InstructionAPI::Instruction insn = insns.back().first; 
        //Dyninst::InstructionAPI::Operation op = insn.getOperation();
        Dyninst::InstructionAPI::InsnCategory category = insn.getCategory();
        //Dyninst::InstructionAPI::Expression::Ptr expt = insn.getControlFlowTarget();

        //conditional jumps
        vector<BPatch_edge *> outgoingEdge;
        (*bb_iter)->getOutgoingEdges(outgoingEdge);
        vector<BPatch_edge *>::iterator edge_iter;

        for(edge_iter = outgoingEdge.begin(); edge_iter != outgoingEdge.end(); ++edge_iter) {
            
            if ((*edge_iter)->getType() == CondJumpTaken){
                instrumentCondition(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, condition_id);
                condition_id++;
            }
            else if ((*edge_iter)->getType() == CondJumpNottaken){
                instrumentCondition(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, condition_id);
                condition_id++;
            }        
            
        }

        //indirect edges
        for(Dyninst::InstructionAPI::Instruction::cftConstIter iter = insn.cft_begin(); iter != insn.cft_end(); ++iter) {
            if(iter->isIndirect) {
                
                if(category == Dyninst::InstructionAPI::c_CallInsn) {//indirect call
                    vector<BPatch_point *> callPoints;
                    appImage->findPoints(addr, callPoints); //use callPoints[0] as the instrument point

                }
                
                else if(category == Dyninst::InstructionAPI::c_BranchInsn) {//indirect jump
                                
                }
 
            }
        }
    }


}


int main (int argc, char **argv){

     if(!parseOptions(argc,argv)) {
        return EXIT_FAILURE;
    }

    fs::path out_dir (reinterpret_cast<const char*>(becfuzz_dir)); // files for becfuzz results
    fs::path num_file = out_dir / NUM_EDGE_FILE; // out_dir: becfuzz outputs

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
   // iterate over all functions to count edges
    num_conditional = 0;
    num_indirect = 0;
    max_map_id = 0;
    for (auto countIter = allFunctions.begin (); countIter != allFunctions.end (); ++countIter) {
        BPatch_function *countFunc = *countIter;
        char funcName[1024];
        countFunc->getName (funcName, 1024);
        
        if(isSkipFuncs(funcName)) continue;
        //count edges
        if(!count_edges(appBin, appImage, countIter, funcName)) 
                            cout << "Empty function" << funcName << endl;      
    }

    // fuzzer gets the number of edges by saved file
    
    u32 num_tpm = num_conditional + num_indirect * NUM_INDIRECT_TARGETS;
    u16 num_exp = (u16)ceil( log(num_tpm) / log(2) );
    // be general with the shared memory
    if(num_exp < MAP_SIZE_POW2) num_exp = MAP_SIZE_POW2;
    max_map_id = (1 << num_exp);
    
    ofstream numedges;
    numedges.open (num_file.c_str(), ios::out | ios::app | ios::binary); //write file
    if(numedges.is_open()){
        numedges << num_conditional << " " << max_map_id << endl; 
    }
    numedges.close();    
    //TODO: fuzzer gets the values through pipe (or shared memory?)


    /*
        instrument at edges
    */
   /*TODO:
   1. insert at conditional edges, like afl
   2.  insert at indirect edges, and compare edges dynamically:
        1) the first id of an indirect edge is the number of conditional edges num_c
        2) use unorder_map to maintain [(src_addr, des_addr), id]
        3) ###each time it encounters a new edge, restart executing the target; this will
            load the unorder_map to check the id;
        OR: at the beginning of main, insert a global unorder_map to record [(src_addr, des_addr), id]
        4) at each indirect edge, when meeting a new indirect edge, write the [(src_addr, des_addr), id] 
            into a file to record them; it can be reused if fuzzing stops accidently
    */
    vector < BPatch_function * >::iterator funcIter;
    for (funcIter = allFunctions.begin (); funcIter != allFunctions.end (); ++funcIter) {
        BPatch_function *curFunc = *funcIter;
        char funcName[1024];
        curFunc->getName (funcName, 1024);
        if(isSkipFuncs(funcName)) continue;
        //instrument at edges
        if(!edgeInstrument(appBin, appImage, funcIter, funcName, num_file)) return EXIT_FAILURE; 

    }

}