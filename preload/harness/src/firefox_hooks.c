/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "config.h"
#include "nyx.h"

/* required to support kafl_panic hypercalls */
extern char* log_content;

__attribute__((noreturn)) void firefox_handler_MOZ_CRASH(const char* aFilename,
                                                         int aLine) {
#ifndef CATCH_MOZ_CRASH
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif
  hprintf("MOZ_CRASH catched! (%d - %s)\n", aLine, aFilename);
  sprintf(log_content, "MOZ_CRASH catched! (%d - %s)\n", aLine, aFilename);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}

__attribute__((noreturn)) void firefox_handler_MOZ_ASSERT(const char* aFilename,
                                                          int aLine,
                                                          const char* aReason) {
#ifndef CATCH_MOZ_ASSERT
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif
  hprintf("MOZ_ASSERT catched! (%s - %d - %s)\n", aReason, aLine, aFilename);
  sprintf(log_content, "MOZ_ASSERT catched! (%s - %d - %s)\n", aReason, aLine,
          aFilename);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}

__attribute__((noreturn)) void firefox_handler_MOZ_RELEASE_ASSERT(
    const char* aFilename, int aLine, const char* aReason) {
#ifndef CATCH_MOZ_RELEASE_ASSERT
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif
  hprintf("MOZ_RELEASE_ASSERT catched! (%s - %d - %s)\n", aReason, aLine,
          aFilename);
  sprintf(log_content, "MOZ_RELEASE_ASSERT catched! (%s - %d - %s)\n", aReason,
          aLine, aFilename);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}

__attribute__((noreturn)) void firefox_handler_MOZ_DIAGNOSTIC_ASSERT(
    const char* aFilename, int aLine, const char* aReason) {
#ifndef CATCH_MOZ_DIAGNOSTIC_ASSERT
  kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif
  hprintf("MOZ_DIAGNOSTIC_ASSERT catched! (%s - %d - %s)\n", aReason, aLine,
          aFilename);
  sprintf(log_content, "MOZ_DIAGNOSTIC_ASSERT catched! (%s - %d - %s)\n",
          aReason, aLine, aFilename);
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uint64_t)log_content);
  while (1) {
  }
}
