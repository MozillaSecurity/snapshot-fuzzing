/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once
#include <stdint.h>

// Implemented in ld_preload_fuzz.c
void nyx_init_start(void);
uint32_t internal_get_next_fuzz_data(void* data, uint32_t len);
uint32_t internal_get_raw_fuzz_data(void* data, uint32_t len);

// Implemented in firefox_hooks.c
__attribute__((noreturn)) void firefox_handler_MOZ_CRASH(const char* aFilename,
                                                         int aLine);
__attribute__((noreturn)) void firefox_handler_MOZ_ASSERT(const char* aFilename,
                                                          int aLine,
                                                          const char* aReason);
__attribute__((noreturn)) void firefox_handler_MOZ_RELEASE_ASSERT(
    const char* aFilename, int aLine, const char* aReason);
__attribute__((noreturn)) void firefox_handler_MOZ_DIAGNOSTIC_ASSERT(
    const char* aFilename, int aLine, const char* aReason);
