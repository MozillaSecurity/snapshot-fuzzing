CFLAGS?=-O2 -m64 -g -Wall -Werror -Wno-unused -Wno-unused-result

SOURCES=\
  src/afl_runtime.c \
  src/firefox_hooks.c \
  src/ld_preload_fuzz.c \
  src/afl_glue.c \
  src/fuzz.c \
  src/stats.c \
  src/crash_handler.c \
  src/moz_interface.c

all: bin64/ld_preload_fuzz.so bin64/ld_preload_fuzz_no_pt.so bin64/ld_preload_fuzz_no_pt_repro.so

clean:
	$(RM) bin64/ld_preload_fuzz.so bin64/ld_preload_fuzz_no_pt.so bin64/ld_preload_fuzz_no_pt_repro.so

bin64/ld_preload_fuzz.so: $(SOURCES)
	@mkdir -p "$(@D)"
	$(CC) -shared $(CFLAGS) $(CPPFLAGS) -fPIC $^ -o $@ -ldl -Isrc -ldw -lunwind -lssl -lcrypto

bin64/ld_preload_fuzz_no_pt.so: $(SOURCES)
	@mkdir -p "$(@D)"
	$(CC) -shared $(CFLAGS) $(CPPFLAGS) -fPIC $^ -DNO_PT_NYX -o $@ -ldl -Isrc

bin64/ld_preload_fuzz_no_pt_repro.so: $(SOURCES)
	@mkdir -p "$(@D)"
	$(CC) -shared $(CFLAGS) $(CPPFLAGS) -fPIC $^ -DNO_PT_NYX -DREPRODUCER -D__NOKAFL -o $@ -ldl -Isrc

.PHONY: all clean
