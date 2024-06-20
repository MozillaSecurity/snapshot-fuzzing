/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <assert.h>
#include "afl_glue.h"
#include "nyx.h"

void no_op() {}

void (*enable_afl_tracing_ptr)(void) = no_op;
void (*disable_afl_tracing_ptr)(void) = no_op;
void (*init_afl_tracing_ptr)(void) = no_op;

void init_afl(void) {
  return;

  static int once = 0;
  if (once == 0) {
    assert(1337 == *((uint64_t*)0x100018));
    enable_afl_tracing_ptr = *((void (**)(void))0x100000);
    disable_afl_tracing_ptr = *((void (**)(void))0x100008);
    init_afl_tracing_ptr = *((void (**)(void))0x100010);

    hprintf("[*] enable_afl_tracing_fptr at: %p\n", enable_afl_tracing_ptr);
    hprintf("[*] disable_afl_tracing_fptr at: %p\n", disable_afl_tracing_ptr);
    hprintf("[*] init_afl_tracing_ptr at: %p\n", init_afl_tracing_ptr);

    once = 1;
  }
}

void enable_afl_tracing_safe(void) {
  assert(enable_afl_tracing_ptr);
  enable_afl_tracing_ptr();
}

void disable_afl_tracing_safe(void) {
  assert(disable_afl_tracing_ptr);
  disable_afl_tracing_ptr();
}

void init_afl_tracing_safe(void) {
  assert(init_afl_tracing_ptr);
  init_afl_tracing_ptr();
}
