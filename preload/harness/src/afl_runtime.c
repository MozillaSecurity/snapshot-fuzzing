/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "nyx.h"
#include "afl_runtime.h"

// Maximum path length on Linux
#define PATH_MAX 4096

// Maximum length of an uint32_t as string
#define START_STOP_MAX 10

__attribute__((weak)) extern afl_module_info_t* __afl_module_info;

char* get_afl_modinfo_string() {
  if (!&__afl_module_info) {
    return NULL;
  }

  uint32_t cnt = 0;
  afl_module_info_t* start = __afl_module_info;

  hprintf("start is %p\n", start);

  while (start) {
    ++cnt;
    start = start->next;
  }

  if (!cnt) return NULL;

  // Allocate per entry enough space for:
  //
  //   1. One path
  //   2. Two pcguard start/stop offsets
  //   3. Two spaces and a trailing newline
  //
  // This is a very conservative allocation so we can just YOLO the rest.
  size_t bufsize = (PATH_MAX + START_STOP_MAX * 2 + 2 + 1) * cnt + 1;
  char* buf = malloc(bufsize);
  char* cur = buf;

  if (!buf) return NULL;

  start = __afl_module_info;

  while (start) {
    size_t namelen = strlen(start->name);

    memcpy(cur, start->name, namelen);
    cur += namelen;
    *cur = ' ';
    cur += 1;
    cur += sprintf(cur, "%u %u", *start->start, *start->stop);
    *cur = '\n';
    cur += 1;

    start = start->next;
  }

  *cur = '\0';

  return buf;
}
