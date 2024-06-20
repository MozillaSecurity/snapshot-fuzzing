/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <stdint.h>

typedef struct stats_s {
  uint64_t event_iteration;
  uint64_t event_timeout;
  uint64_t event_drop_peer;
  uint64_t event_msgtype_unknown;
  uint64_t event_msg_deserialize_error;
  uint64_t event_msg_process_error;
  uint64_t event_msg_route_error;
  uint64_t event_msg_notallowed_error;
  uint64_t event_moz_crash;
  uint64_t event_moz_assert;
  uint64_t event_moz_release_assert;
  uint64_t event_moz_diagnostic_assert;
} stats_t;

extern stats_t* fuzz_stats;

void init_stats();

void on_iteration(uint32_t iterations);
void on_drop_peer();
void on_msgtype_unknown();
void on_msg_deserialize_error();
void on_msg_process_error();
void on_msg_route_error();
void on_msg_notallowed_error();

void on_timeout();
void on_moz_crash();
void on_moz_assert();
void on_moz_release_assert();
void on_moz_diagnostic_assert();

void emit_stats();
void upload_file_to_host(void* buffer, size_t len, const char* filename);
