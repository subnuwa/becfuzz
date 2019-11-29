/* TODO
    1. at the beginning of fork(), read unorder_map [(src_addr, des_addr), id] and assign them to each indirect site
    2. at each instrumentation of indirect edge, use a global variable to indicate whether to read the [(src_addr, des_addr), id] from global or not




*/

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>
#include <algorithm>
#include "config.h"
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>

#include <stdio.h> 
#include <stdlib.h> 

#include <map>
#include "instConfig.h"

#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
using namespace std;


static u8* trace_bits;
static s32 shm_id;                    /* ID of the SHM region             */
//static unsigned short prev_id;
//examined indirect edges and their ids, [(src_addr, des_addr), id]
std::map <std::pair<u64, u64>, u32> indirect_ids;
std::multimap <u64, u64> indirect_addrs;

static u32 cur_max_id; // the current id of indirect edges



/* 
    max_conditional: the largest number of conditional edges
    indirect_file: this file is used when afl wants to re-run the target and use previous results;
                    it contains three number in a row: (src_addr des_addr id)
*/
void initAflForkServer(u32 max_conditional, const char* indirect_file)
{
    /*recover indirect ids*/
    struct stat inbuff;
    u64 ind_src, ind_des;
    u32 addr_id;
    // the max id of indirect edges while starting fuzzing
    cur_max_id = max_conditional - 1; // the max id of conditional edges

    if (stat(indirect_file, &inbuff) == 0){ // file  exists
        ifstream indirect_io (indirect_file); //read file
        if (indirect_io.is_open()){
            while(indirect_io >> ind_src >> ind_des >> addr_id){
                indirect_addrs.insert(make_pair(ind_src, ind_des));
                indirect_ids.insert(make_pair(make_pair(ind_src, ind_des), addr_id));
                if (addr_id > cur_max_id) cur_max_id = addr_id;
            }
            indirect_io.close();
        }

    } 

    /* start fork */
    int temp_data;
    pid_t fork_pid;

    /* Set up the SHM bitmap. */
    char *shm_env_var = getenv(SHM_ENV_VAR);
    if(!shm_env_var) {
        printf("Error getting shm\n");
        return;
    }
    shm_id = atoi(shm_env_var);
    trace_bits = (u8*)shmat(shm_id, NULL, 0);
    if(trace_bits == (u8*)-1) {
        perror("shmat");
        return;
    }

    // enter fork() server thyme!
    //int n;
    if( write(FORKSRV_FD+1, &temp_data, 4) !=4 ) {
        perror("Error writting fork server\n");
        return;
    }
    /* All right, let's await orders... */
    while(1) {
        
        int stMsgLen = read(FORKSRV_FD, &temp_data, 4);
        if(stMsgLen != 4) {
            /* we use a status message length 2 to terminate the fork server. */
            if(stMsgLen == 2){
                exit(EXIT_SUCCESS);
            }
				
            printf("Error reading fork server %x\n",temp_data);
            return;
        }
        /* Parent - Fork off worker process that actually runs the benchmark. */
        fork_pid = fork();
        if(fork_pid < 0) {
            printf("Error on fork()\n");
            return;
        }
        /* Child worker - Close descriptors and return (runs the benchmark). */
        if(fork_pid == 0) {
            close(FORKSRV_FD);
            close(FORKSRV_FD+1);
            return;
        } 
        
        /* Parent - Inform controller that we started a new run. */
		if (write(FORKSRV_FD + 1, &fork_pid, 4) != 4) {
    		perror("Fork server write(pid) failed");
			exit(EXIT_FAILURE);
  		}

        /* Parent - Sleep until child/worker finishes. */
		if (waitpid(fork_pid, &temp_data, 2) < 0) {//2: WUNTRACED
    		perror("Fork server waitpid() failed"); 
			exit(EXIT_FAILURE);
  		}

        /* Parent - Inform controller that run finished. 
            * write status (temp_data) of waitpid() to the pipe
        */
		if (write(FORKSRV_FD + 1, &temp_data, 4) != 4) {
    		perror("Fork server write(temp_data) failed");
			exit(EXIT_FAILURE);
  		}
  		/* Jump back to beginning of this loop and repeat. */


    }

}


/* callback function for instrumenting conditional edges*/
void ConditionJump(u32 cond_id){
    if(trace_bits) {
        trace_bits[cond_id]++;
    }
}

/* 
max_map_size: the max number of edges
max_conditional: the largest number of conditional edges
addr_file: path to the file that contains (src_addr  des_addr  id)

TODO: 1. read indirect_ids if first execution;
      2. save (src_addr, des_addr) if new
  */
void IndirectEdges(u64 src_addr, u64 des_addr, u32 max_map_size, u32 max_conditional, const char* addr_file){
    //std::map <std::pair<u64, u64>, u32> indirect_local_ids;

    bool exist_flag = false;
    //read assigned ids from indirect_ids only if it's the first execution
    if (indirect_addrs.count(src_addr)){
        auto all_src = indirect_addrs.equal_range(src_addr);
        std::multimap <u64, u64>::iterator ite_addr;
        for (ite_addr=all_src.first; ite_addr!=all_src.second; ++ite_addr){
            if (des_addr == (*ite_addr).second){
                exist_flag = true; //exist
                break;
            } 
        }
    }

    if (exist_flag){ // already exist
        std::map<std::pair<u64, u64>, u32>::iterator itdl = indirect_ids.find(make_pair(src_addr, des_addr));
        if (itdl != indirect_ids.end()){
            if(trace_bits) {
                trace_bits[(*itdl).second]++;
            }
        }
    }
    else{ // indirect edge does not exist; find a new indirect edge
        //add it to indirect_addrs and indirect_ids
        indirect_addrs.insert(make_pair(src_addr, des_addr));
        // in case some instrumentations are before forkserver
        if (cur_max_id < (max_conditional-1)) cur_max_id = max_conditional-1;
        //assign a new id for the edge
        cur_max_id++;
        if (cur_max_id >= max_map_size) cur_max_id = max_map_size - 1; //don't overflow


        indirect_ids.insert(make_pair(make_pair(src_addr, des_addr), cur_max_id));
        if(trace_bits) {
            trace_bits[cur_max_id]++;
        }
        //save new edge into a file, for recovering fuzzing
        ofstream indaddrs;
        indaddrs.open (addr_file, ios::out | ios::app | ios::binary); //write file
        if(indaddrs.is_open()){
            indaddrs << src_addr << " " << des_addr << " " << cur_max_id<< endl; 
        }
        
    }
}