#!/usr/bin/env python3

from argparse import ArgumentParser
import shlex
import subprocess as sp
from tempfile import NamedTemporaryFile


CMD = 'PATH-TO-IDA/%s -c -A -L"%s" -S"%s/parse_exports.py %s" %s'

def main(args):
    outfile = args.out if args.out else "%s.pickle" % args.dll

    with NamedTemporaryFile() as f:
        ida = "idat64.exe"
        if args.bits == "32":
            ida = "idat.exe"

        sp.call(
            shlex.split(CMD % (ida, args.log, args.path, outfile, args.dll)),
            shell=False,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )

    return 0


if __name__ == "__main__":
    parser = ArgumentParser(description="Toxotidae python driver")

    parser.add_argument(
        "--dll", dest="dll", type=str, help="Path to DLL", required=True
    )
    parser.add_argument(
        "--path", dest="path", type=str, help="Path to framework", required=True
    )
    parser.add_argument(
        "--log",
        dest="log",
        type=str,
        help="Path to logfile",
        default="/tmp/analysis.log",
    )
    parser.add_argument(
        "--bits",
        dest="bits",
        type=str,
        default="64",
        help="Bits of the dll to be analyzed",
    )
    parser.add_argument("--out", dest="out", type=str, help="Path to output file")

    args = parser.parse_args()

    main(args)
