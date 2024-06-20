/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <signal.h>

#define LOG_CONTENT_SIZE 0x10000

void fault_handler(int signo, siginfo_t* info, void* extra);
void setHandler(void (*handler)(int, siginfo_t*, void*));

void init_crash_handling(void);

// Exported so it can be used internally as well.
void __assert(const char* func, const char* file, int line,
              const char* failedexpr);
