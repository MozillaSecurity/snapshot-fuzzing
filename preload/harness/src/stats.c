/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include "nyx.h"
#include "stats.h"

stats_t* fuzz_stats = NULL;

#define FUZZ_STATS_SIZE 0x1000

void init_stats() {
  fuzz_stats = (void*)mmap(NULL, FUZZ_STATS_SIZE, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if ((void*)fuzz_stats == (void*)-1) {
    kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT,
                   (uint64_t) "parent: fuzz_stats mmap failed!\n");
  }

  hprintf("[*] %s: mmap returned %p\n", __func__, fuzz_stats);
  memset((void*)fuzz_stats, 0, FUZZ_STATS_SIZE);
  mlock((void*)fuzz_stats, FUZZ_STATS_SIZE);

  kAFL_hypercall(HYPERCALL_KAFL_PERSIST_PAGE_PAST_SNAPSHOT,
                 (uintptr_t)fuzz_stats);
}

void emit_stats() {
  hprintf("\n");
  hprintf("*** Fuzzing Statistics ***\n");
  hprintf("Total Iterations:\t\t%" PRIu64 "\n", fuzz_stats->event_iteration);
  hprintf("Event - Timeout:\t\t%" PRIu64 "\n", fuzz_stats->event_timeout);
  hprintf("Event - Drop Peer:\t\t%" PRIu64 "\n", fuzz_stats->event_drop_peer);
  hprintf("Event - Msg Type Unknown:\t\t%" PRIu64 "\n",
          fuzz_stats->event_msgtype_unknown);
  hprintf("Event - Msg Deserialize Error:\t\t%" PRIu64 "\n",
          fuzz_stats->event_msg_deserialize_error);
  hprintf("Event - Msg Process Error:\t\t%" PRIu64 "\n",
          fuzz_stats->event_msg_process_error);
  hprintf("Event - Msg Route Error:\t\t%" PRIu64 "\n",
          fuzz_stats->event_msg_route_error);
  hprintf("Event - Msg NotAllowed Error:\t\t%" PRIu64 "\n",
          fuzz_stats->event_msg_notallowed_error);
  hprintf("Event - MOZ_CRASH:\t\t%" PRIu64 "\n", fuzz_stats->event_moz_crash);
  hprintf("Event - MOZ_ASSERT:\t\t%" PRIu64 "\n", fuzz_stats->event_moz_assert);
  hprintf("Event - MOZ_RELEASE_ASSERT:\t\t%" PRIu64 "\n",
          fuzz_stats->event_moz_release_assert);
  hprintf("Event - MOZ_DIAGNOSTIC_ASSERT:\t\t%" PRIu64 "\n",
          fuzz_stats->event_moz_diagnostic_assert);
  hprintf("*** End of Statistics ***\n");
}

void upload_file_to_host(void* buffer, size_t len, const char* filename) {
  kafl_dump_file_t file_obj = {0};

  file_obj.file_name_str_ptr = (uintptr_t)filename;
  file_obj.append = 0;
  file_obj.bytes = 0;
  kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));

  file_obj.bytes = len;
  file_obj.data_ptr = (uintptr_t)buffer;
  kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));
}

void on_iteration(uint32_t iterations) {
  if (fuzz_stats) {
    if ((fuzz_stats->event_iteration % 1000) + iterations >= 1000) {
      emit_stats();
    }

    fuzz_stats->event_iteration += iterations;
  }
}

void on_drop_peer() {
  if (fuzz_stats) fuzz_stats->event_drop_peer++;
}
void on_msgtype_unknown() {
  if (fuzz_stats) fuzz_stats->event_msgtype_unknown++;
}
void on_msg_deserialize_error() {
  if (fuzz_stats) fuzz_stats->event_msg_deserialize_error++;
}
void on_msg_process_error() {
  if (fuzz_stats) fuzz_stats->event_msg_process_error++;
}
void on_msg_route_error() {
  if (fuzz_stats) fuzz_stats->event_msg_route_error++;
}
void on_msg_notallowed_error() {
  if (fuzz_stats) fuzz_stats->event_msg_notallowed_error++;
}
void on_timeout() {
  if (fuzz_stats) fuzz_stats->event_timeout++;
}
void on_moz_crash() {
  if (fuzz_stats) fuzz_stats->event_moz_crash++;
}
void on_moz_assert() {
  if (fuzz_stats) fuzz_stats->event_moz_assert++;
}
void on_moz_release_assert() {
  if (fuzz_stats) fuzz_stats->event_moz_release_assert++;
}
void on_moz_diagnostic_assert() {
  if (fuzz_stats) fuzz_stats->event_moz_diagnostic_assert++;
}
