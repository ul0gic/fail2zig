#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 fail2zig maintainers
import argparse
from datetime import datetime, timezone
from ipaddress import IPv4Address
import math
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("count", type=int)
    parser.add_argument("rate", type=float)
    args = parser.parse_args()
    if not 0 <= args.count <= 131072:
        parser.error("count must fit the 131072 distinct addresses in 198.18.0.0/15")
    if not math.isfinite(args.rate) or args.rate <= 0:
        parser.error("rate must be finite and positive")
    started = time.monotonic()
    first = int(IPv4Address("198.18.0.0"))
    with open(args.path, "a", buffering=1) as output:
        for number in range(args.count):
            delay = started + number / args.rate - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
            address = IPv4Address(first + number)
            output.write(f"{stamp} Scan from: [{address}] ({address}) protocol: [TCP] port: [23] type: [Connect] IP opts: [unknown] ignored: [false] triggered: [true] noblock: [true] blocked: [false]\n")
    elapsed = time.monotonic() - started
    print(f"rig: generator done ({args.count} lines, {elapsed:.3f} s, {args.count / elapsed:.2f} lines/s)", flush=True)


if __name__ == "__main__":
    main()
