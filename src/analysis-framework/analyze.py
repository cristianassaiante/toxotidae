#!/usr/bin/env python3

from argparse import ArgumentParser
import json
import time

from static_analyzer.analysis.hooks import HooksFinder
from static_analyzer.analysis.liveness import Liveness
from static_analyzer.analysis.propagation import ParametersPropagation
from static_analyzer.analysis.stats import Stats
from static_analyzer.analysis.vulnspots import VulnSpotsFinder
from static_analyzer.arch.x86.compute_unit import X86ComputeUnit
from static_analyzer.code.dll import DLL
from static_analyzer.logger import Logger
from utils.dll_stats import (
    AnalysisStats,
    DefensiveStats,
    NonVulnerableAPIStats,
    StolenCodeStats,
    TocTouStats,
    VulnerableAPIStats,
)


def analyze(dll: DLL):
    for api in dll.apis:
        Stats.compute(api)
        ParametersPropagation.propagate(api, X86ComputeUnit)
        Liveness.liveness(api, X86ComputeUnit)
        HooksFinder.find_hooks(api, X86ComputeUnit)
        VulnSpotsFinder.find_vuln_spots(api, X86ComputeUnit)


def get_stats(dll: DLL, elapsed_time):
    analysis_stats = AnalysisStats(dll)
    defensive_stats = DefensiveStats(dll)
    toctou_stats = TocTouStats(dll)
    stolen_stats = StolenCodeStats(dll)
    vuln_stats = VulnerableAPIStats(dll)
    nonvuln_stats = NonVulnerableAPIStats(dll)

    analysis_stats.compute()
    defensive_stats.compute()
    toctou_stats.compute()
    stolen_stats.compute()
    vuln_stats.compute()
    nonvuln_stats.compute()

    out = {
        f"{dll.name}": {
            "analysis": json.loads(analysis_stats.__str__()),
            "defensive": json.loads(defensive_stats.__str__()),
            "toctou": json.loads(toctou_stats.__str__()),
            "stolencode": json.loads(stolen_stats.__str__()),
            "vuln": json.loads(vuln_stats.__str__()),
            "nonvuln": json.loads(nonvuln_stats.__str__()),
        }
    }
    out[dll.name]["analysis"]["elapsed_time"] = elapsed_time
    return out


def main(args):
    if args.debug:
        Logger.set_debug()

    dll = DLL.load(args.dll)

    start = time.time()
    analyze(dll)
    end = time.time()

    stats = get_stats(dll, end - start)

    print(json.dumps(stats, indent=4))

    if args.out:
        dll.dump(args.out)


if __name__ == "__main__":
    parser = ArgumentParser(description="Toxotidae python driver")

    parser.add_argument(
        "--dll", dest="dll", type=str, help="Path to DLL pickle file", required=True
    )
    parser.add_argument(
        "--out", dest="out", type=str, help="Path to DLL output pickle file"
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        default=False,
        help="Enable debug prints",
    )

    args = parser.parse_args()

    main(args)
