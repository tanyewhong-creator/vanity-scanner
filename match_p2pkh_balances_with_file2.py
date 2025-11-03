#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check if Bitcoin Address (P2PKH) from File 2 exists in File 1 addresses.
- File 1: balances-0-914122.csv (semicolon CSV: address;balance, 2.57 GB)
- File 2: wallet_info_output.jsonl (JSONL with "Bitcoin Address (P2PKH)", 25 GB)
- Output: matches.jsonl
Optimized for speed with multiprocessing and orjson.
"""

import csv
import orjson
import multiprocessing as mp
from itertools import islice
from pathlib import Path
import math
import os

FILE1 = r"D:\balances-0-914122.csv"
FILE2 = r"D:\wallet_info_output.jsonl"
OUT = r"D:\matches.jsonl"
UNMATCHED_LOG = r"D:\unmatched_p2pkh.txt"

def load_file1_addresses(file1_path: str) -> tuple[dict, set]:
    """Load addresses and balances from File 1 into a dict and set."""
    addr_to_balance = {}
    with open(file1_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            addr = (row.get("address") or "").strip()
            bal_raw = (row.get("balance") or "").strip()
            if not addr:
                continue
            try:
                bal = int(bal_raw) / 100_000_000  # Convert satoshis to BTC
            except ValueError:
                try:
                    bal = float(bal_raw)
                except ValueError:
                    bal = bal_raw
            addr_to_balance[addr] = bal
    return addr_to_balance, set(addr_to_balance.keys())

def preview_file(file_path: str, n: int = 5, is_jsonl: bool = False):
    """Preview first n rows of a CSV or JSONL file."""
    print(f"\n📄 First {n} rows of {file_path}:")
    if is_jsonl:
        with open(file_path, "rb") as f:
            for line in islice(f, n):
                line = line.decode("utf-8").strip()
                if not line:
                    continue
                try:
                    obj = orjson.loads(line)
                    print(obj)
                except orjson.JSONDecodeError:
                    continue
    else:
        with open(file_path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f, delimiter=";")
            for row in islice(reader, n):
                print(row)

def process_chunk(chunk_start: int, chunk_lines: int, file2_path: str, all_addresses: set, addr_to_balance: dict, output_queue: mp.Queue):
    """Process a chunk of File 2, checking for P2PKH matches."""
    matches = []
    unmatched = []
    with open(file2_path, "rb") as f:
        f.seek(chunk_start)
        for _ in range(chunk_lines):
            line = f.readline().decode("utf-8").strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
                p2pkh = (obj.get("Bitcoin Address (P2PKH)") or "").strip()
                if not p2pkh:
                    unmatched.append(f"No P2PKH field: {line}")
                    continue
                if p2pkh.startswith("1"):  # Validate P2PKH format
                    if p2pkh in all_addresses:
                        matches.append({
                            "address": p2pkh,
                            "balance": addr_to_balance[p2pkh],
                            "file2_record": obj
                        })
                    else:
                        unmatched.append(p2pkh)
                else:
                    unmatched.append(f"Non-P2PKH address: {p2pkh}")
            except orjson.JSONDecodeError:
                unmatched.append(f"Invalid JSON: {line}")
    output_queue.put((matches, unmatched))

def main():
    # Load File 1 into memory
    print("Loading balances-0-914122.csv...")
    addr_to_balance, all_addresses = load_file1_addresses(FILE1)
    print(f"Loaded {len(all_addresses)} addresses from {FILE1}")

    # Estimate lines in File 2 (~250 bytes/line, 25 GB ≈ 100M lines)
    file2_size = os.path.getsize(FILE2)
    avg_line_size = 250  # Adjust based on actual JSONL line size
    total_lines = math.ceil(file2_size / avg_line_size)
    num_processes = min(mp.cpu_count(), 6)  # Use up to 6 processes
    lines_per_chunk = math.ceil(total_lines / num_processes)

    # Get chunk boundaries
    chunk_starts = [0]
    with open(FILE2, "rb") as f:
        line_count = 0
        while line_count < total_lines:
            f.seek(avg_line_size * lines_per_chunk * len(chunk_starts))
            while f.read(1) != b"\n":
                f.seek(-2, os.SEEK_CUR)
            chunk_starts.append(f.tell())
            line_count += lines_per_chunk
        chunk_starts.append(file2_size)

    # Start processes
    print(f"Processing {FILE2} with {num_processes} processes...")
    output_queue = mp.Manager().Queue()
    processes = []
    for i in range(num_processes):
        chunk_start = chunk_starts[i]
        chunk_end = chunk_starts[i + 1] if i + 1 < len(chunk_starts) else file2_size
        # Count lines in chunk efficiently
        with open(FILE2, "rb") as f:
            f.seek(chunk_start)
            chunk_data = f.read(chunk_end - chunk_start)
            chunk_lines = len([line for line in chunk_data.split(b"\n") if line])
        if chunk_lines <= 0:
            continue
        p = mp.Process(
            target=process_chunk,
            args=(chunk_start, chunk_lines, FILE2, all_addresses, addr_to_balance, output_queue)
        )
        processes.append(p)
        p.start()

    # Collect results
    matches = []
    unmatched = []
    for _ in range(len(processes)):
        chunk_matches, chunk_unmatched = output_queue.get()
        matches.extend(chunk_matches)
        unmatched.extend(chunk_unmatched)

    # Write matches to output
    print(f"Writing {len(matches)} matches to {OUT}...")
    with open(OUT, "w", encoding="utf-8") as fout:
        for match in matches:
            fout.write(orjson.dumps(match, option=orjson.OPT_SERIALIZE_NUMPY).decode("utf-8") + "\n")

    # Log unmatched addresses for debugging
    if unmatched:
        with open(UNMATCHED_LOG, "w", encoding="utf-8") as f:
            for addr in unmatched[:1000]:  # Limit to avoid large logs
                f.write(f"{addr}\n")
        print(f"Wrote {len(unmatched)} unmatched addresses to {UNMATCHED_LOG} (first 1000)")

    print(f"\n✅ Finished. Found {len(matches)} matching P2PKH addresses. Results written to {OUT}")

    # Show previews
    preview_file(FILE1, 5)
    preview_file(FILE2, 5, is_jsonl=True)
    if matches:
        preview_file(OUT, 5, is_jsonl=True)

if __name__ == "__main__":
    main()