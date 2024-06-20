/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdint.h>

typedef struct afl_module_info_t afl_module_info_t;

struct afl_module_info_t {
  // A unique id starting with 0
  uint32_t id;

  // Name and base address of the module
  char* name;
  uintptr_t base_address;

  // PC Guard start/stop
  uint32_t* start;
  uint32_t* stop;

  // PC Table begin/end
  uintptr_t* pcs_beg;
  uintptr_t* pcs_end;

  uint8_t mapped;

  afl_module_info_t* next;
};

char* get_afl_modinfo_string();
