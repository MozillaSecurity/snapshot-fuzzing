
#include <stdio.h>
#include <stdint.h>
#include "nyx.h"
#include <string.h>
#include <inttypes.h>

int main(int argc, char** argv){

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }

  if(argc == 3){
    void* stream_data = mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    FILE* f = NULL;


    uint64_t bytes = 0;
    uint64_t total = 0;

    do{
      strcpy(stream_data, argv[1]);
      bytes = kAFL_hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA, (uintptr_t)stream_data);

      if(bytes == 0xFFFFFFFFFFFFFFFFUL){
        hprintf("HYPERVISOR: ERROR\n");
        break;
      }

      if(f == NULL){
        f = fopen(argv[2], "w+");
      }

      fwrite(stream_data, 1, bytes, f);

      total += bytes;

    } while(bytes);

    hprintf("%"PRId64" bytes received from hypervisor! (%s)\n", total, argv[1]);

    if(f){
      fclose(f);
      return 0;
    }
    return -1;

  }
  printf("Usage: <hget> <file> <out>\n");
  return 0;
}
