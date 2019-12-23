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

static u32 num_conditional, // the number of total conditional edges
            num_indirect,   // the number of total indirect edges
            max_map_size, // the number of all edges, including potential indirect edges
            condition_id; // assign unique id for each conditional edges


//cmd line options
char *originalBinary;
char *instrumentedBinary;
bool verbose = false;
set<string> instrumentLibraries;
set<string> runtimeLibraries;
char* becfuzz_dir = NULL;  //Output dir of becfuzz results


// call back functions
BPatch_function *ConditionJump;
BPatch_function *IndirectEdges;
BPatch_function *initAflForkServer;



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
        cerr << "Output directory for becfuzz is required!" << endl;
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
        Dyninst::InstructionAPI::Operation op = insn.getOperation();
        Dyninst::InstructionAPI::InsnCategory category = insn.getCategory();
        Dyninst::InstructionAPI::Expression::Ptr expt = insn.getControlFlowTarget();

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
    return true;
    
}

// instrument at conditional edges, like afl
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


/*
num_all_edges: the number of all edges
num_condition_edges: the number of all conditional edges
ind_addr_file: path to the file that contains (src_addr des_addr id)
*/
bool instrumentIndirect(BPatch_binaryEdit * appBin, BPatch_function * instFunc, 
                BPatch_point * instrumentPoint, Dyninst::Address src_addr, u32 num_all_edges, u32 num_condition_edges,
                fs::path ind_addr_file){
    vector<BPatch_snippet *> ind_args;

    BPatch_constExpr srcOffset((u64)src_addr);
    ind_args.push_back(&srcOffset);
    ind_args.push_back(new BPatch_dynamicTargetExpr());//target offset
    BPatch_constExpr AllEdges(num_all_edges);
    ind_args.push_back(&AllEdges);
    BPatch_constExpr CondEdges(num_condition_edges);
    ind_args.push_back(&CondEdges);
    BPatch_constExpr AddrIDFile(ind_addr_file.c_str());
    ind_args.push_back(&AddrIDFile);


    BPatch_funcCallExpr instIndirect(*instFunc, ind_args);

    BPatchSnippetHandle *handle =
            appBin->insertSnippet(instIndirect, *instrumentPoint, BPatch_callBefore, BPatch_firstSnippet);
    
    if (!handle) {
            cerr << "Failed to insert instrumention in basic block at offset 0x" << hex << src_addr << endl;
            return false;
        }
    return true;

}


/*instrument at edges
    addr_id_file: path to the file that contains (src_addr des_addr id)
*/
bool edgeInstrument(BPatch_binaryEdit * appBin, BPatch_image *appImage, 
                    vector < BPatch_function * >::iterator funcIter, char* funcName, 
                    fs::path addr_id_file){
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
        Dyninst::InstructionAPI::Operation op = insn.getOperation();
        Dyninst::InstructionAPI::InsnCategory category = insn.getCategory();
        Dyninst::InstructionAPI::Expression::Ptr expt = insn.getControlFlowTarget();

        //conditional jumps
        vector<BPatch_edge *> outgoingEdge;
        (*bb_iter)->getOutgoingEdges(outgoingEdge);
        vector<BPatch_edge *>::iterator edge_iter;

        for(edge_iter = outgoingEdge.begin(); edge_iter != outgoingEdge.end(); ++edge_iter) {
            
            if ((*edge_iter)->getType() == CondJumpTaken){
                instrumentCondition(appBin, ConditionJump, (*edge_iter)->getPoint(), addr, condition_id);
                condition_id++;  //assign a new id fot the next conditional edge
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
                    appImage->findPoints(addr, callPoints);
                    
                    instrumentIndirect(appBin, IndirectEdges, callPoints[0], addr, max_map_size, num_conditional, addr_id_file);
                    // vector<BPatch_point *>::iterator callPt_iter;
                    // for(callPt_iter = callPoints.begin(); callPt_iter != callPoints.end(); ++callPt_iter) {
                        
                    //     instrumentIndirect(appBin, IndirectEdges, *callPt_iter, addr, max_map_size, num_conditional, addr_id_file);                       
                    // }
                    
                }
                
                else if(category == Dyninst::InstructionAPI::c_BranchInsn) {//indirect jump
                    vector<BPatch_point *> jmpPoints;
                    appImage->findPoints(addr, jmpPoints);
                    
                    instrumentIndirect(appBin, IndirectEdges, jmpPoints[0], addr, max_map_size, num_conditional, addr_id_file);
                    // vector<BPatch_point *>::iterator jmpPt_iter;
                    // for(jmpPt_iter = jmpPoints.begin(); jmpPt_iter != jmpPoints.end(); ++jmpPt_iter) {
                    //     instrumentIndirect(appBin, IndirectEdges, *jmpPt_iter, addr, max_map_size, num_conditional, addr_id_file);
                    // }
                }
                // 
                // else if(category == Dyninst::InstructionAPI::c_ReturnInsn) {
                //     vector<BPatch_point *> retPoints;
                //     appImage->findPoints(addr, retPoints);

                //     vector<BPatch_point *>::iterator retPt_iter;
                //     for(retPt_iter = retPoints.begin(); retPt_iter != retPoints.end(); ++retPt_iter) {
                //          instrumentIndirect(appBin, IndirectEdges, *retPt_iter, addr, max_map_size, num_conditional, addr_id_file);
                //     }
                // }
 
            }
        }
    }
    return true;
}

/* insert forkserver at the beginning of main
    funcInit: function to be instrumented, i.e., main

*/

bool insertForkServer(BPatch_binaryEdit * appBin, BPatch_function * instIncFunc,
                         BPatch_function *funcInit, u32 num_cond_edges, fs::path ind_addr_file)
{

    /* Find the instrumentation points */
    vector < BPatch_point * >*funcEntry = funcInit->findPoint (BPatch_entry);

    if (NULL == funcEntry) {
        cerr << "Failed to find entry for function. " <<  endl;
        return false;
    }

    //cout << "Inserting init callback." << endl;
    BPatch_Vector < BPatch_snippet * >instArgs; 
    BPatch_constExpr NumCond(num_cond_edges);
    instArgs.push_back(&NumCond);
    BPatch_constExpr AddrIDFile(ind_addr_file.c_str());
    instArgs.push_back(&AddrIDFile);

    BPatch_funcCallExpr instIncExpr(*instIncFunc, instArgs);

    /* Insert the snippet at function entry */
    BPatchSnippetHandle *handle =
        appBin->insertSnippet (instIncExpr, *funcEntry, BPatch_callBefore, BPatch_firstSnippet);
    if (!handle) {
        cerr << "Failed to insert init callback." << endl;
        return false;
    }
    return true;
}

int main (int argc, char **argv){

     if(!parseOptions(argc,argv)) {
        return EXIT_FAILURE;
    }

    fs::path out_dir (reinterpret_cast<const char*>(becfuzz_dir)); // files for becfuzz results
    fs::path num_file = out_dir / NUM_EDGE_FILE; // out_dir: becfuzz outputs; max edges
    fs::path addrs_ids_file = out_dir / INDIRECT_ADDR_ID; //indirect edge addrs and ids

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
    //IndirectBranch = findFuncByName (appImage, (char *) "IndirectBranch");
    
    //indirect addresses pairs
    //getIndAddrs = findFuncByName (appImage, (char *) "getIndirectAddrs");
    //clearMaps = findFuncByName (appImage, (char *) "clearMultimaps");
    
    //conditional jumps
    ConditionJump = findFuncByName (appImage, (char *) "ConditionJump");
    IndirectEdges = findFuncByName (appImage, (char *) "IndirectEdges");
    //BBCallback =  findFuncByName (appImage, (char *) "BBCallback");
    //ConditionMark = findFuncByName (appImage, (char *) "ConditionMark");
    
    //atMainExit = findFuncByName (appImage, (char *) "atMainExit");


    if (!initAflForkServer || !ConditionJump || !IndirectEdges) {
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
    max_map_size = 0;
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
    max_map_size = (1 << num_exp);
    
    ofstream numedges;
    numedges.open (num_file.c_str(), ios::out | ios::app | ios::binary); //write file
    if(numedges.is_open()){
        numedges << num_conditional << " " << max_map_size << endl; 
        //numedges << num_indirect << endl;
    }
    numedges.close();    
    //TODO: fuzzer gets the values through pipe (or shared memory?)?


   /* instrument edges
   1. insert at conditional edges, like afl
   2.  insert at indirect edges, and compare edges dynamically:
        1) the first id of an indirect edge is the number of conditional edges num_c
        2) use map to maintain [(src_addr, des_addr), id]
        3) at the beginning of main, insert a global map to load [(src_addr, des_addr), id]
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
        //if(!edgeInstrument(appBin, appImage, funcIter, funcName, addr_id_file)) return EXIT_FAILURE;
        edgeInstrument(appBin, appImage, funcIter, funcName, addrs_ids_file);

    }

    BPatch_function *funcToPatch = NULL;
    BPatch_Vector<BPatch_function*> funcs;
    
    appImage->findFunction("main",funcs);
    if(!funcs.size()) {
        cerr << "Couldn't locate main, check your binary. "<< endl;
        return EXIT_FAILURE;
    }
    // there should really be only one
    funcToPatch = funcs[0];

    if(!insertForkServer (appBin, initAflForkServer, funcToPatch, num_conditional, addrs_ids_file)){
        cerr << "Could not insert init callback at main." << endl;
        return EXIT_FAILURE;
    }

    if(verbose){
        cout << "Saving the instrumented binary to " << instrumentedBinary << "..." << endl;
    }
    // save the instrumented binary
    if (!appBin->writeFile (instrumentedBinary)) {
        cerr << "Failed to write output file: " << instrumentedBinary << endl;
        return EXIT_FAILURE;
    }

    if(verbose){
        cout << "All done! Happy fuzzing!" << endl;
    }

    return EXIT_SUCCESS;


}