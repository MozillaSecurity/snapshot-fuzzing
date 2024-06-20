/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <time.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>

#include "nyx.h"
#include "crash_handler.h"
#include "config.h"
#include "stats.h"

#define PAYLOAD_SIZE (0x100000) // Maximum testcase size that AFL++ supports

extern void __assert(const char* func, const char* file, int line,
                     const char* failedexpr);
#define INTERPRETER_ASSERT(x)                     \
  do {                                            \
    if (x) {                                      \
    } else {                                      \
      __assert(__func__, __FILE__, __LINE__, #x); \
    }                                             \
  } while (0)
#define ASSERT(x) INTERPRETER_ASSERT(x)

__attribute__((weak)) extern unsigned int __afl_final_loc;
unsigned int* __afl_final_loc_ptr = &__afl_final_loc;

__attribute__((weak)) extern uint8_t* __afl_area_ptr;

__attribute__((weak)) extern uint32_t __afl_dictionary_len;
uint32_t* __afl_dictionary_len_ptr = &__afl_dictionary_len;

__attribute__((weak)) extern uint8_t* __afl_dictionary;
uint8_t** __afl_dictionary_ptr = &__afl_dictionary;

#ifdef REPRODUCER
uint8_t global_payload_buffer[PAYLOAD_SIZE];
#else
uint8_t* global_payload_buffer = NULL;
#endif

// We currently don't support running without AddressSanitizer but we might
// in the future.
bool asan_executable = true;

uint32_t internal_get_raw_fuzz_data(void* data, uint32_t len) {
  uint8_t* payload_buffer = global_payload_buffer;
  uint8_t* payload_begin = payload_buffer + 4;
  uint32_t payload_size = *(uint32_t*)payload_buffer;
  uint32_t retlen = payload_size > len ? len : payload_size;
  memcpy(data, payload_begin, retlen);
  return retlen;
}

uint32_t internal_get_next_fuzz_data(void* data, uint32_t len) {
  static uint8_t* payload_pos = NULL;

  uint8_t* payload_buffer = global_payload_buffer;

  if (payload_pos == NULL) {
    payload_pos = payload_buffer + 4;
#ifdef FUZZ_DEBUG
    hprintf(
        "DEBUG: internal_get_next_fuzz_data: Initializing payload_pos to %p\n",
        payload_pos);
#endif
  }

  uint8_t* payload_begin = payload_buffer + 4;

  uint32_t payload_size = *(uint32_t*)payload_buffer;

#ifdef FUZZ_DEBUG
  hprintf("DEBUG: internal_get_next_fuzz_data: payload_begin %p size %u\n",
          payload_begin, payload_size);
#endif

  if (payload_pos + 3 >= payload_begin + payload_size) {
    // Need at least 3 bytes remaining
    return 0xFFFFFFFF;
  }

  uint16_t next_chunk_size = *(uint16_t*)(payload_pos)&0x7ff;
  payload_pos += sizeof(uint16_t);

#ifdef FUZZ_DEBUG
  hprintf("DEBUG: internal_get_next_fuzz_data: next_chunk_size %u len %u\n",
          next_chunk_size, len);
#endif

  next_chunk_size = next_chunk_size > len ? len : next_chunk_size;

  size_t remaining = payload_begin + payload_size - payload_pos;

  next_chunk_size = next_chunk_size > remaining ? remaining : next_chunk_size;

#ifdef FUZZ_DEBUG
  hprintf("DEBUG: internal_get_next_fuzz_data: remaining %u\n", remaining);
#endif

  memcpy(data, payload_pos, next_chunk_size);
  payload_pos += next_chunk_size;

  return next_chunk_size;
}

void* trace_buffer = NULL;
void* pcmap_buffer = NULL;
size_t pcmap_buffer_size = 0;

int _mlock(void* dst, size_t size) { return syscall(SYS_mlock, dst, size); }

int _munlock(void* dst, size_t size) { return syscall(SYS_munlock, dst, size); }

int _mlockall(int flags) { return syscall(SYS_mlockall, flags); }

pid_t _fork(void) { return syscall(SYS_fork); }

void init_trace_buffers() {
  static bool done = false;

  if (!done) {
    host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

    if (host_config.host_magic != NYX_HOST_MAGIC) {
      hprintf(
          "Error: NYX_HOST_MAGIC not found in host configuration - You are "
          "probably using an outdated version of QEMU-Nyx...");
      kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }

    if (host_config.host_version != NYX_HOST_VERSION) {
      hprintf(
          "Error: NYX_HOST_VERSION not found in host configuration - You are "
          "probably using an outdated version of QEMU-Nyx...");
      kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }

    hprintf("[*] %s: host_config.bitmap_size: 0x%x\n", __func__,
            host_config.bitmap_size);
    hprintf("[*] %s: host_config.ijon_bitmap_size: 0x%x\n", __func__,
            host_config.ijon_bitmap_size);
    hprintf("[*] %s: host_config.payload_buffer_size: 0x%x\n", __func__,
            host_config.payload_buffer_size);

    char* map_size = getenv("AFL_MAP_SIZE");
    uint32_t bitmap_size = host_config.bitmap_size;
    if (map_size) {
      bitmap_size = atoi(map_size);
    }

    trace_buffer = mmap((void*)NULL, bitmap_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(trace_buffer, 0xff, bitmap_size);
    mlock(trace_buffer, bitmap_size);

    hprintf("[*] %s: trace_buffer = %p\n", __func__, trace_buffer);

    if (!!getenv("MOZ_FUZZ_COVERAGE")) {
      pcmap_buffer_size = bitmap_size * sizeof(void*);
      pcmap_buffer =
          mmap((void*)NULL, pcmap_buffer_size, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
      memset(pcmap_buffer, 0x00, pcmap_buffer_size);
      mlock(pcmap_buffer, pcmap_buffer_size);

      hprintf("[*] %s: pcmap_buffer = %p\n", __func__, pcmap_buffer);
    }

    done = true;
  }
}

void capabilites_configuration(bool timeout_detection, bool agent_tracing,
                               bool ijon_tracing) {
  static bool done = false;

  if (!done) {
    hprintf("[*] %s: agent_tracing: %d\n", __func__, agent_tracing);
    agent_config_t agent_config = {0};

    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;

    agent_config.agent_timeout_detection = (uint8_t)timeout_detection;
    agent_config.agent_tracing = (uint8_t)agent_tracing;

    agent_config.agent_ijon_tracing = 0;
    agent_config.ijon_trace_buffer_vaddr = (uintptr_t)NULL;

    /* AFL++ LTO support */
    if (__afl_final_loc_ptr) {
      unsigned int map_size = __afl_final_loc == 0 ? 65536 : __afl_final_loc;
      hprintf("[capablities] overwriting bitmap_size: 0x%x\n", map_size);
      agent_config.coverage_bitmap_size = map_size;
    }

    hprintf("[capablities] trace_buffer: %p __afl_area_ptr: %p \n",
            trace_buffer, __afl_area_ptr);

    agent_config.trace_buffer_vaddr = (uint64_t)trace_buffer;
    agent_config.agent_non_reload_mode = 0;

    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
    done = true;
  }
}

void dump_mappings(void) {
  char filename[256];

  char* buffer = malloc(0x1000);

  kafl_dump_file_t file_obj = {0};

  file_obj.file_name_str_ptr = (uint64_t) "proc_maps.txt";
  file_obj.append = 0;
  file_obj.bytes = 0;
  kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t)(&file_obj));
  file_obj.append = 1;

  snprintf(filename, 256, "/proc/%d/maps", getpid());

  FILE* f = fopen(filename, "r");
  uint32_t len = 0;
  while (1) {
    len = fread(buffer, 1, 0x1000, f);
    if (!len) {
      break;
    } else {
      file_obj.bytes = len;
      file_obj.data_ptr = (uint64_t)buffer;
      kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t)(&file_obj));
    }
  }
  fclose(f);
}

static void check_afl_auto_dict() {
  /* copy AFL autodict over to host */
  if (__afl_dictionary_len_ptr && __afl_dictionary_ptr) {
    if (__afl_dictionary_len && __afl_dictionary) {
      _mlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
      kafl_dump_file_t file_obj = {0};
      file_obj.file_name_str_ptr = (uintptr_t) "afl_autodict.txt";
      file_obj.append = 1;
      file_obj.bytes = __afl_dictionary_len;
      file_obj.data_ptr = (uintptr_t)__afl_dictionary;
      kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));
      _munlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
    }
  }
}

void nyx_init_start(void) {
  static bool already_called = false;
  ASSERT(!already_called);
  already_called = true;

  dump_mappings();
  check_afl_auto_dict();

#if defined(REDIRECT_STDERR_TO_HPRINTF) || defined(REDIRECT_STDOUT_TO_HPRINTF)
  char buf[HPRINTF_MAX_SIZE];
#endif
  printf("nyx_init_start\n");

  remove("/tmp/target_executable");

  struct rlimit r;
  int fd, fd2 = 0;
  int pipefd[2];
  int ret = pipe(pipefd);

#ifndef REPRODUCER

#  ifdef REDIRECT_STDERR_TO_HPRINTF
  int pipe_stderr_hprintf[2];
  ret = pipe(pipe_stderr_hprintf);
#  endif
#  ifdef REDIRECT_STDOUT_TO_HPRINTF
  int pipe_stdout_hprintf[2];
  ret = pipe(pipe_stdout_hprintf);
#  endif

#endif

  struct iovec iov;
  int pid;
  int status = 0;
  int res = 0;
  int i;

  uint64_t memlimit_200 = 200;
  r.rlim_max = (rlim_t)(memlimit_200 << 20);
  r.rlim_cur = (rlim_t)(memlimit_200 << 20);

#ifndef REPRODUCER
  /* check via env var if we should disable stdout/stderr -> might be useful for
   * debug purposes */
  dup2(open("/dev/null", O_WRONLY), STDOUT_FILENO);
  dup2(open("/dev/null", O_WRONLY), STDERR_FILENO);

  kAFL_payload* payload_buffer = mmap((void*)NULL, PAYLOAD_SIZE, PROT_READ,
                                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  _mlock(payload_buffer, (size_t)PAYLOAD_SIZE);
  global_payload_buffer = (uint8_t*)payload_buffer;

  kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

  hprintf("payload_buffer at %p\n", payload_buffer);

  kAFL_ranges* range_buffer = mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  memset(range_buffer, 0xff, 0x1000);
  kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (uintptr_t)range_buffer);

  for (i = 0; i < 4; i++) {
    hprintf("Range %d Enabled: %x\t(%" PRIx64 "-%" PRIx64 ")\n", i,
            (uint8_t)range_buffer->enabled[i], range_buffer->ip[i],
            range_buffer->size[i]);
  }

#  if defined(__i386__)
  kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#  elif defined(__x86_64__)
  kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#  endif

#endif

  if (!asan_executable) {
    setrlimit(RLIMIT_AS, &r);
  }

  hprintf("============================YOOOOO\n\n\n\n\n");

  uint8_t mlock_enabled = 1;

  hprintf("asan_executable -> %d\n", asan_executable);

  if (!asan_executable) {
    if (_mlockall(MCL_CURRENT)) {
      hprintf("mlockall(MCL_CURRENT) failed!\n");
      kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
    }
  }

  setHandler(fault_handler);

  hprintf("========================================================\n");

  while (1) {
    if (!asan_executable) {
      if (mlock_enabled) {
        setHandler(fault_handler);
        if (_mlockall(MCL_CURRENT)) {
          hprintf("mlockall(MCL_CURRENT) failed!\n");
          kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
        }
      }
    }

    kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

#ifdef REPRODUCER
    memset(global_payload_buffer, 0, PAYLOAD_SIZE);
    FILE* TFILE = fopen(getenv("MOZ_FUZZ_TESTFILE"), "r");
    if (!TFILE) {
      fprintf(stderr, "Can't open specified file: %s\n",
              getenv("MOZ_FUZZ_TESTFILE"));
      exit(1);
    }
    fread(global_payload_buffer, 1, PAYLOAD_SIZE, TFILE);
#endif

#ifdef REDIRECT_STDERR_TO_HPRINTF
    dup2(pipe_stderr_hprintf[1], STDERR_FILENO);
    close(pipe_stderr_hprintf[0]);
#endif
#ifdef REDIRECT_STDOUT_TO_HPRINTF
    dup2(pipe_stdout_hprintf[1], STDOUT_FILENO);
    close(pipe_stdout_hprintf[0]);
#endif
    return;
  }
}

bool file_exists(char* filename) {
  struct stat buffer;
  return (stat(filename, &buffer) == 0);
}

bool get_parent_process(int argc, char** ubp_av) {
  bool is_parent_process = false;
  for (int i = 0; i < argc; i++) {
    if (!strcmp(ubp_av[i], "-parentBuildID")) {
      is_parent_process = true;
    }
  }

  is_parent_process = true;

  if (is_parent_process && !file_exists("/tmp/firefox_fuzzing_lock")) {
    close(open("/tmp/firefox_fuzzing_lock", O_CREAT | O_WRONLY, 777));
    return true;
  }
  return false;
}

/* verify that we only monitor our non-sandboxed parent process */
bool nyx_firefox_is_parent = false;

char* getenv(const char* name) {
  char* (*_getenv)(const char* name) = dlsym(RTLD_NEXT, "getenv");

  if (nyx_firefox_is_parent && !strcmp(name, "__AFL_SHM_ID")) {
    hprintf("[*] %s: AFL instrumentation requesting __AFL_SHM_ID\n", __func__);
    return "5134680";
  }

  if (nyx_firefox_is_parent && !strcmp(name, "__AFL_PCMAP_SHM_ID")) {
    hprintf("[*] %s: AFL instrumentation requesting __AFL_PCMAP_SHM_ID\n",
            __func__);
    return "5134681";
  }

  return _getenv(name);
}

void* shmat(int shmid, const void* shmaddr, int shmflg) {
  if (nyx_firefox_is_parent && shmid == 5134680) {
    init_trace_buffers();
    capabilites_configuration(false, true, false);

    hprintf("[%d] AFL BITMAP IS at: %p\n", getpid(), trace_buffer);
    return trace_buffer;
  }

  if (nyx_firefox_is_parent && shmid == 5134681) {
    return pcmap_buffer;
  }

  void* (*_shmat)(int shmid, const void* shmaddr, int shmflg) =
      dlsym(RTLD_NEXT, "shmat");
  return _shmat(shmid, shmaddr, shmflg);
}

int __libc_start_main(int (*main)(int, char**, char**), int argc, char** ubp_av,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void(*stack_end)) {
  int (*original__libc_start_main)(int (*main)(int, char**, char**), int argc,
                                   char** ubp_av, void (*init)(void),
                                   void (*fini)(void), void (*rtld_fini)(void),
                                   void(*stack_end));

  original__libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");

  nyx_firefox_is_parent = get_parent_process(argc, ubp_av);

  if (nyx_firefox_is_parent) {
    init_crash_handling();
    init_trace_buffers();
    capabilites_configuration(false, true, true);

    hprintf("[*] Parent: %d\n", getpid());
  } else {
    hprintf("[*] New child: %d\n", getpid());
    setpriority(PRIO_PROCESS, 0, 10);
  }

  return original__libc_start_main(main, argc, ubp_av, init, fini, rtld_fini,
                                   stack_end);
}
