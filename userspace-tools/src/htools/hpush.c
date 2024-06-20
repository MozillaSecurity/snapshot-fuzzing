
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <libxdc.h>
#include <string.h>
#include <libgen.h>
#include <string.h>

#include "nyx.h"


#define round_up(x, y) (((x) + (y) - 1) & ~((y) - 1))

void *mapfile(char *fn, uint64_t *size)
{
	int fd = open(fn, O_RDONLY);
	if (fd < 0)
		return NULL;
	struct stat st;
	void *map = (void *)-1L;
	if (fstat(fd, &st) >= 0) {
		*size = (uint64_t)st.st_size;
		map = mmap(NULL, round_up(*size, sysconf(_SC_PAGESIZE)),
			   PROT_READ|PROT_WRITE,
			   MAP_PRIVATE, fd, 0);
	}
	close(fd);


  if(map){
		void* copy = malloc(*size);
		memcpy(copy, map, st.st_size);
		munmap(map, round_up(*size, sysconf(_SC_PAGESIZE)));
		return copy;
	}
  return NULL;
}

static void dump_payload(void* buffer, size_t len, const char* filename){
    static bool init = false;
    static kafl_dump_file_t file_obj = {0};

    //printf("%s -> ptr: %p size: %lx - %s\n", __func__, buffer, len, filename);

    if (!init){
        file_obj.file_name_str_ptr = (uintptr_t)filename;
        file_obj.append = 0;
        file_obj.bytes = 0;
        kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
        init=true;
    }

    file_obj.append = 1;
    file_obj.bytes = len;
    file_obj.data_ptr = (uintptr_t)buffer;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
}

int main(int argc, char** argv){
  char buf[256];

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }

  if(argc != 2){
    hprintf("Usage: <hpush> <file>\n");
    return 1;
  }

  uint64_t size = 0;
  void* ptr = mapfile(argv[1], &size);

  if(ptr && size){
    dump_payload(ptr, size, basename(argv[1]));
  }
  else{
    hprintf("FILE NOT FOUND!\n");
  }

  return 0;
}