CFLAGS?=-O2 -m64 -Werror -I/path/to/AFLplusplus/nyx_mode/QEMU-Nyx/libxdc/

HTOOLS=bin64/habort bin64/hcat bin64/hget bin64/hget_bulk bin64/hpush bin64/hrelease
HTOOLS_NO_PT=$(foreach tool,$(HTOOLS),$(tool)_no_pt)

all: $(HTOOLS) $(HTOOLS_NO_PT)
htools: $(HTOOLS)
htools_no_pt: $(HTOOLS_NO_PT)

# pt mode builds
bin64/h%: src/htools/h%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -I../preload/harness/src -o $@

# no-pt mode builds
bin64/h%_no_pt: src/htools/h%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNO_PT_NYX $< -I../preload/harness/src -o $@

clean:
	$(RM) $(HTOOLS) $(HTOOLS_NO_PT)

.PHONY: all clean htools htools_no_pt
