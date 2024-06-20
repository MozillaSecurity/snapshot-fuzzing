
#include <stdio.h>
#include <stdint.h>
#include "nyx.h"
#include <string.h>
#include <assert.h>
#include <stdbool.h>



int main(int argc, char** argv){

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }

  if(argc == 3){

    req_data_bulk_t* stream_data_ctrl = (req_data_bulk_t*)mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset((void*)stream_data_ctrl, 0, 0x1000);
    for(int i = 0; i < 479; i++){
      stream_data_ctrl->addresses[i] = (uintptr_t)mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if(stream_data_ctrl->addresses[i] == (uint64_t)-1){
        hprintf("Error: Cannot allocate page number %d\n", i);
        return 1;
      }
      memset((void*)stream_data_ctrl->addresses[i], 0, 0x1000);
      stream_data_ctrl->num_addresses++;
    }

    strncpy(stream_data_ctrl->file_name, argv[1], 256);
    
    FILE* f = NULL;


    uint64_t bytes = 0;
    uint64_t total = 0;
    bool recv_data = true;

    do{
      bytes = kAFL_hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA_BULK, (uintptr_t)stream_data_ctrl);

      if(bytes == 0xFFFFFFFFFFFFFFFFUL){
        hprintf("HYPERVISOR: ERROR\n");
        break;
      }

      total += bytes;

      //hprintf("Total %d\n", bytes);

      if(f == NULL){
        f = fopen(argv[2], "w+");
      }

      if(bytes != (479*0x1000)){
        recv_data = false;
      }

      for(int i = 0; i < stream_data_ctrl->num_addresses; i++){
        if(bytes >= 0x1000){
          fwrite((void*)stream_data_ctrl->addresses[i], 1, 0x1000, f);
          bytes -= 0x1000;
        }
        else{
          fwrite((void*)stream_data_ctrl->addresses[i], 1, bytes, f);
          bytes = 0;
          break;
        }
      }

    } while(recv_data);

    hprintf("%ld bytes received from hypervisor! (%s)\n", total, argv[1]);

    if(f){
      fclose(f);
      return 0;
    }
    return -1;

  }
  printf("Usage: <hget> <file> <out>\n");
  return 0;
}