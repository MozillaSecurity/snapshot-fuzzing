# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from argparse import ArgumentParser
from pathlib import Path
from subprocess import run
import json
import logging
import struct
import sys

LOG = logging.getLogger(__file__)

def symbolize(addresses, mod_path):
    output = run(
        ["llvm-addr2line", "--output-style=JSON", "--inlining=true", "-C", "-e", mod_path],
        capture_output=True,
        input="\n".join(addresses),
        text=True,
    ).stdout.split("\n")

    locations = []

    for line in output:
        if not line:
            # Happens on last line usually. For empty input lines, it would output
            # a JSON formatted error instead
            continue

        result = json.loads(line)

        # Make sure we're not accidentally somehow mismatching results.
        assert(result["Address"] == addresses[len(locations)])

        # Due to inlining, we can have multiple locations here, so we return a list of lists.
        locations.append([])

        for symbol in result["Symbol"]:
            if symbol["FileName"]:
                locations[-1].append({"filename" : symbol["FileName"], "line": int(symbol["Line"])})

    return locations

def read_modinfo(file, ff_path):
    modinfo = {}
    with file.open() as fd:
        for x in fd.readlines():
            fn, start, stop = x.rsplit(" ", 2)
            fn = fn.replace("/home/user/firefox", str(ff_path.resolve()))
            modinfo[fn] = (int(start), int(stop))
    return modinfo


def read_line_clusters(file):
    line_clusters = {}
    if file.exists():
        with file.open() as fd:
            line_clusters = json.load(fd)
    else:
        LOG.warning("WARNING: lineclusters.json not found")
    return line_clusters

# Ensure we're warning about missing files only once to keep output readable.
line_cluster_warned = {}

def get_line_cluster(line_clusters, name, line):
    if name not in line_clusters:
        if line_clusters and name not in line_cluster_warned:
            LOG.warning("file not found in line clusters: %s", name)
            line_cluster_warned[name] = True
        return [line]
    for x in line_clusters[name]:
        if line in x:
            return x
    return [line]


def read_pointers(file):
    pointer_list = []
    with file.open("rb") as fd:
        while True:
            pointer_buf = fd.read(8)
            if not pointer_buf:
                break
            pointer = struct.unpack("<Q", pointer_buf)[0]
            pointer_list.append(hex(pointer + 1))
    return pointer_list


def read_bitmap(file):
    with file.open("rb") as fd:
        return fd.read()


def main():
    parser = ArgumentParser(prog=Path(__file__).name)
    parser.add_argument("dump_folder", type=Path, help="Path to workdir/dump/")
    parser.add_argument("line_clusters", type=Path, help="Path to lineclusters.json")
    parser.add_argument("build_prefix", help="Build prefix to strip from object files.")
    parser.add_argument("scm_rev", help="SCM revision to label coverage output.")
    parser.add_argument("sharedir", type=Path, help="Path to sharedir containing firefox/")
    parser.add_argument("outfile", type=Path, help="Coverage output file.")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose debug logging."
    )
    args = parser.parse_args()
    if not (args.dump_folder / "pcmap.dump").is_file():
        parser.error("given dump folder does not contain pcmap.dump")
    if not (args.dump_folder / "covmap.dump").is_file():
        parser.error("given dump folder does not contain covmap.dump")
    if not (args.dump_folder / "modinfo.txt").is_file():
        parser.error("given dump folder does not contain modinfo.txt")
    if not (args.sharedir / "firefox").is_dir():
        parser.error("sharedir should contain firefox/")
    logging.basicConfig(
        format="%(message)s", level=logging.DEBUG if args.verbose else logging.INFO
    )

    if not args.build_prefix.endswith("/"):
        args.build_prefix += "/"

    pointers = read_pointers(args.dump_folder / "pcmap.dump")
    bitmap = read_bitmap(args.dump_folder / "covmap.dump")
    modinfo = read_modinfo(args.dump_folder / "modinfo.txt", args.sharedir / "firefox")

    if len(pointers) != len(bitmap):
        LOG.error("ERROR: Length mismatch: len(pointers) != len(bitmap)")
        sys.exit(1)

    line_clusters = read_line_clusters(args.line_clusters)

    merged_locations = [""] * len(bitmap)

    unresolved = 0
    covered = 0

    for mod_path, (start_idx, stop_idx) in modinfo.items():
        addresses = []

        for idx, pointer in enumerate(pointers):
            if start_idx <= idx < stop_idx:
                if pointer == 0:
                    unresolved += 1
                    # Important to be able to match entries to original bitmap by index
                    addresses.append("")
                else:
                    addresses.append(str(pointer))
                    if bitmap[idx] > 0:
                        covered += 1

        locations = symbolize(addresses, mod_path)

        for idx, location in enumerate(locations):
            merged_locations[start_idx + idx] = location

    LOG.info("Total unresolved: %d", unresolved)
    LOG.info("Total covered: %d", covered)
    LOG.info("Total uncovered: %d", len(bitmap) - covered)

    covobj = {
        "source_files": [],
        "git": {"head": {"id": args.scm_rev}, "branch": "main"},
    }

    name2obj = {}

    for idx, locations in enumerate(merged_locations):
        # Check if this is an unresolvable location
        if not locations:
            continue

        for location in locations:
            name = location["filename"]
            line = location["line"]

            name = name.replace(args.build_prefix, "", 1)
            if name.startswith("objdir"):
                continue

            if not line:
                # Line 0 usually means this location cannot be resolved
                # to any line in source code.
                continue

            if name not in name2obj:
                source_file = {"name": name, "coverage": [None] * line}

                name2obj[name] = source_file
                covobj["source_files"].append(source_file)

            lines = get_line_cluster(line_clusters, name, line)

            for line in lines:
                while len(name2obj[name]["coverage"]) <= line:
                    name2obj[name]["coverage"].append(None)
                name2obj[name]["coverage"][line - 1] = bitmap[idx]

    with args.outfile.open("w") as fd:
        json.dump(covobj, fd)


if __name__ == "__main__":
    main()
