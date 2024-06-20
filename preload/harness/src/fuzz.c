/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <errno.h>

#include "fuzz.h"
#include "config.h"
#include "stats.h"
#include "afl_glue.h"

#include "nyx.h"

#define PR_SET_NAME 15 /* Set process name */
#define PR_GET_NAME 16 /* Get process name */

extern bool nyx_firefox_is_parent;
extern bool nyx_started;

int prctl(int option, unsigned long arg2, unsigned long arg3,
          unsigned long arg4, unsigned long arg5) {
  static int (*__prctl)(int option, unsigned long arg2, unsigned long arg3,
                        unsigned long arg4, unsigned long arg5) = NULL;

  if (!nyx_started && option == PR_SET_NAME) {
    if (nyx_firefox_is_parent) {
      hprintf("[*] %s: enabling AFL tracing on parent thread: %s\n", __func__,
              (char*)arg2);
      init_afl();
      enable_afl_tracing_safe();
    }

    // hprintf("PR_SET_NAME: %s by PID: %d TID: %d\n", (char*) arg2, getpid(),
    // gettid());
  }

  if (__prctl == NULL) {
    __prctl = dlsym(RTLD_NEXT, "prctl");
  }

  return __prctl(option, arg2, arg3, arg4, arg5);
}
