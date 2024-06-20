/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define _GNU_SOURCE

#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <execinfo.h>
#include <stdbool.h>

#include "nyx.h"
#include "crash_handler.h"

char* log_content = NULL;
static bool ready = false;

extern bool nyx_firefox_is_parent;
extern bool asan_executable;

void init_crash_handling(void) {
  if (!log_content) {
    log_content = malloc(LOG_CONTENT_SIZE);
    memset(log_content, 0x00, LOG_CONTENT_SIZE);
  }
  ready = true;
}

void fault_handler(int signo, siginfo_t* info, void* extra) {
  ucontext_t* context = (ucontext_t*)extra;
  uint64_t reason = 0x8000000000000000ULL |
                    context->uc_mcontext.gregs[REG_RIP] |
                    ((uint64_t)info->si_signo << 47);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
}

void setHandler(void (*handler)(int, siginfo_t*, void*)) {
  struct sigaction action;
  action.sa_flags = SA_SIGINFO;
  action.sa_sigaction = handler;

  int (*new_sigaction)(int signum, const struct sigaction* act,
                       struct sigaction* oldact);
  new_sigaction = dlsym(RTLD_NEXT, "sigaction");

  if (!asan_executable) {
    if (new_sigaction(SIGFPE, &action, NULL) == -1) {
      hprintf("sigfpe: sigaction");
      _exit(1);
    }
    if (new_sigaction(SIGILL, &action, NULL) == -1) {
      hprintf("sigill: sigaction");
      _exit(1);
    }

    if (new_sigaction(SIGSEGV, &action, NULL) == -1) {
      hprintf("sigsegv: sigaction");
      _exit(1);
    }

    if (new_sigaction(SIGBUS, &action, NULL) == -1) {
      hprintf("sigbus: sigaction");
      _exit(1);
    }
    if (new_sigaction(SIGABRT, &action, NULL) == -1) {
      hprintf("sigabrt: sigaction");
      _exit(1);
    }
    if (new_sigaction(SIGIOT, &action, NULL) == -1) {
      hprintf("sigiot: sigaction");
      _exit(1);
    }
    if (new_sigaction(SIGTRAP, &action, NULL) == -1) {
      hprintf("sigiot: sigaction");
      _exit(1);
    }
    if (new_sigaction(SIGSYS, &action, NULL) == -1) {
      hprintf("sigsys: sigaction");
      _exit(1);
    }
    hprintf("ALL SIGNAL HANDLERS ARE HOOKED!\n");
    // kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
  }
}

int sigaction(int signum, const struct sigaction* act,
              struct sigaction* oldact) {
  int (*new_sigaction)(int signum, const struct sigaction* act,
                       struct sigaction* oldact);
  new_sigaction = dlsym(RTLD_NEXT, "sigaction");

  int ret_val = new_sigaction(signum, act, oldact);

  if (ready) {
    setHandler(fault_handler);
  }

  return ret_val;
}

void handle_asan(void) {
  char* log_file_path = NULL;
  char* log_content = NULL;

  if (!nyx_firefox_is_parent) {
    while (1) {
      sleep(1);
    }
  }

  asprintf(&log_file_path, "/tmp/data.log.%d", getpid());

  FILE* f = fopen(log_file_path, "r");

  if (f) {
    log_content = malloc(LOG_CONTENT_SIZE);
    memset(log_content, 0x00, LOG_CONTENT_SIZE);
    fread(log_content, LOG_CONTENT_SIZE - 1, 1, f);
    fclose(f);

    if (nyx_firefox_is_parent) {
      kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
    } else {
      hprintf("[*] crash found in child process! %s\n", log_content);
      while (1) {
        sleep(1);
      }
      kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
  } else {
    hprintf("ERROR: Cannot locate log_file at %s!?\n", log_file_path);
  }
}

void __assert(const char* func, const char* file, int line,
              const char* failedexpr) {
  sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %s\n",
          func, file, line, failedexpr);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
}

void _abort(void) {
  handle_asan();
  sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n",
          __builtin_return_address(0));
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}

void abort(void) {
  handle_asan();
  sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n",
          __builtin_return_address(0));
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}

void __abort(void) {
  handle_asan();
  sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n",
          __builtin_return_address(0));
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}

void __assert_fail(const char* __assertion, const char* __file,
                   unsigned int __line, const char* __function) {
  sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %s\n",
          __function, __file, __line, __assertion);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
}

void __assert_perror_fail(int __errnum, const char* __file, unsigned int __line,
                          const char* __function) {
  sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %d\n",
          __function, __file, __line, __errnum);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
}
