# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from argparse import ArgumentParser
from os import SEEK_CUR
from pathlib import Path
import json
import logging
import re
import struct
import sys

GCOV_TAG_FUNCTION = b"\x00\x00\x00\x01"
GCOV_TAG_BLOCKS = b"\x00\x00\x41\x01"
GCOV_TAG_ARCS = b"\x00\x00\x43\x01"
GCOV_TAG_LINES = b"\x00\x00\x45\x01"
GCOV_TAG_COUNTER_ARCS = b"\x00\x00\xa1\x01"
GCOV_TAG_OBJECT_SUMMARY = b"\x00\x00\x00\xa1"
GCOV_TAG_PROGRAM_SUMMARY = b"\x00\x00\x00\xa3"
GCOV_TAG_END = b"\x00\x00\x00\x00"

LOG = logging.getLogger(__file__)


def normalize_filename(nm):
    result = nm
    while True:
        result, changes = re.subn(r'(/|^)([^"/]+/\.\.|\.)/', r"\1", result)
        if not changes:
            break
    if result != nm:
        LOG.debug("resolved %s to %s", nm, result)
    return result


class SetEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return super().default(o)


class GCNOReader:
    def __init__(self, filename):
        self.fp = filename.open("rb")
        # magic_number
        if self.fp.read(4) != b"oncg":
            raise RuntimeError(f"File does not look like gcno: {filename}")
        self.skip(4)  # version
        self.skip(4)  # checksum

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.fp.close()
        self.fp = None

    def read_tag(self):
        tag = self.fp.read(4)
        length = self.read_int()
        return (tag, length)

    def read_int(self):
        data = self.fp.read(4)
        return struct.unpack("<I", data)[0]

    def read_string(self):
        strlen = self.read_int() * 4
        return self.fp.read(strlen).decode().rstrip("\x00")

    def iter_tags(self):
        while True:
            tag, length = self.read_tag()
            yield (tag, length)
            if tag == GCOV_TAG_END:
                break

    def skip(self, n):
        self.fp.seek(n, SEEK_CUR)


class GCNOProcessor:
    def __init__(self, prefix, target_file=None):
        self.blocks = {}
        self.prefix = prefix
        if not self.prefix.endswith("/"):
            self.prefix += "/"
        self.target_file = target_file

    def process_path(self, target):
        if target.is_dir():
            # Whole tree
            for filename in target.glob("**/*.gcno"):
                self._read_file(filename)
        else:
            # Single gcno file for debugging
            self._read_file(target)

    def dump(self, outfile):
        with outfile.open("w") as fd:
            json.dump(self.blocks, fd, indent=4, cls=SetEncoder)

    def _read_file(self, filename):
        LOG.debug("%s", filename)
        with GCNOReader(filename) as fd:
            local_blocks = {}

            blocks = []
            src_file = None
            blocks_recorded = False

            for tag, length in fd.iter_tags():
                if tag in {
                    GCOV_TAG_ARCS,
                    GCOV_TAG_COUNTER_ARCS,
                    GCOV_TAG_END,
                    GCOV_TAG_FUNCTION,
                    GCOV_TAG_OBJECT_SUMMARY,
                    GCOV_TAG_PROGRAM_SUMMARY,
                }:
                    fd.skip(length * 4)

                elif tag == GCOV_TAG_BLOCKS:
                    # Reset blocks and src file
                    blocks = [{"no": i, "lines": []} for i in range(length)]
                    src_file = None
                    fd.skip(length * 4)
                    LOG.debug("Read %d blocks", len(blocks))
                    blocks_recorded = False

                elif tag == GCOV_TAG_LINES:
                    LOG.debug("Reading GCOV_TAG_LINES")
                    block_no = fd.read_int()
                    LOG.debug("Block %d", block_no)
                    if block_no < len(blocks):
                        while True:
                            line_no = fd.read_int()
                            if line_no > 0:
                                if not src_file:
                                    LOG.error("No source file in block?")
                                    sys.exit(1)
                                if self.target_file is None or src_file.endswith(
                                    self.target_file
                                ):
                                    blocks[block_no]["lines"].append(line_no)
                            else:
                                src_file = fd.read_string()
                                if not src_file:
                                    break
                                src_file = normalize_filename(src_file)
                                src_file = src_file.replace(self.prefix, "", 1)

                                if not blocks_recorded and (
                                    self.target_file is None
                                    or src_file.endswith(self.target_file)
                                ):
                                    if src_file not in local_blocks:
                                        local_blocks[src_file] = [blocks]
                                        LOG.info(
                                            "Reading block for %s, expecting %d blocks",
                                            src_file,
                                            len(blocks),
                                        )
                                    elif src_file in local_blocks:
                                        LOG.info(
                                            "Got another src_file for %s, now expecting %d blocks",
                                            src_file,
                                            len(blocks),
                                        )
                                        local_blocks[src_file].append(blocks)

                                    # This loop actually alternates between reading lines and reading strings.
                                    # That means, it reads the same file string multiple times without actually
                                    # entering a new `GCOV_TAG_BLOCKS` section. We must avoid adding `blocks`
                                    # times or we end up duplicating a lot of lines.
                                    blocks_recorded = True

                                elif blocks_recorded:
                                    if len(blocks) != len(local_blocks[src_file][-1]):
                                        LOG.error("ERROR: Size mismatch?!")
                                        sys.exit(1)

                    else:
                        raise ValueError(f"Invalid block number: {block_no}")

                else:
                    raise ValueError(f"Invalid tag: {tag}")

        for src_file in local_blocks:
            self.blocks.setdefault(src_file, set())
            for blocks in local_blocks[src_file]:
                for x in blocks:
                    if x["lines"]:
                        self.blocks[src_file].add(tuple(x["lines"]))


def test_normalize_filename():
    assert normalize_filename("./file.h") == "file.h"
    assert normalize_filename("../file.h") == "../file.h"
    assert normalize_filename("/path/../file.h") == "/file.h"
    assert normalize_filename("path/../file.h") == "file.h"
    assert normalize_filename("path/a/b/../../file.h") == "path/file.h"
    assert normalize_filename("path/a/../b/../file.h") == "path/file.h"
    assert normalize_filename("path/./a/file.h") == "path/a/file.h"
    assert normalize_filename("path/././a/file.h") == "path/a/file.h"


def main():
    parser = ArgumentParser(prog=Path(__file__).name)
    parser.add_argument("outfile", type=Path, help="Output file.")
    parser.add_argument(
        "target", type=Path, help="Path to gcno file or directory of gcno files."
    )
    parser.add_argument("prefix", help="Strip prefix.")
    parser.add_argument(
        "target_file", nargs="?", help="Restrict results to a single source file."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose debug logging."
    )
    args = parser.parse_args()
    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if args.verbose else logging.WARN
    )

    processor = GCNOProcessor(args.prefix, args.target_file)
    processor.process_path(args.target)
    processor.dump(args.outfile)


if __name__ == "__main__":
    main()
