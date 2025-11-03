#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Multiprocessing scanner for reused ECDSA r values from Rusty-Blockparser's tx_in-XXXXX.csv
- Handles very large CSVs (100s of GB)
- Parallel processing
- Progress bar
- Checkpointing to resume after interruption
- Fixed parser: handles pushdata prefixes (e.g. OP_PUSHDATA, length bytes) before DER sigs
"""

import csv
import json
import os
import time
import logging
import multiprocessing as mp
from collections import defaultdict
from tqdm import tqdm  # pip install tqdm
import pickle

# --- Config ---
CSV_PATH = r"D:\rbp_dump\tx_in-0-914566.csv"
CHUNK_SIZE = 5_000_000   # lines per chunk
WORKERS = max(1, mp.cpu_count() - 1)
CHECKPOINT_FILE = "reused_r_checkpoint.pkl"

# --- Logging ---
logging.basicConfig(filename='scan_reused_r_from_txin_mp_resume.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def extract_r_s_from_sig(sig_hex):
    """Parse DER-encoded ECDSA signature (strip pushdata first)."""
    try:
        sig_bytes = bytes.fromhex(sig_hex)

        # Strip pushdata opcodes until DER sequence (0x30)
        while sig_bytes and sig_bytes[0] != 0x30:
            l = sig_bytes[0]
            if len(sig_bytes) > 1 and sig_bytes[1] == 0x30 and l + 1 <= len(sig_bytes):
                sig_bytes = sig_bytes[1:1+l]
                break
            else:
                sig_bytes = sig_bytes[1:]

        if not sig_bytes or sig_bytes[0] != 0x30:
            return None, None

        pos = 2
        if pos >= len(sig_bytes) or sig_bytes[pos] != 0x02:
            return None, None
        pos += 1
        r_len = sig_bytes[pos]
        pos += 1
        r = sig_bytes[pos:pos + r_len].hex()
        pos += r_len

        if pos >= len(sig_bytes) or sig_bytes[pos] != 0x02:
            return None, None
        pos += 1
        s_len = sig_bytes[pos]
        pos += 1
        s = sig_bytes[pos:pos + s_len].hex()

        return r, s
    except Exception:
        return None, None


def process_chunk(chunk, header):
    """Process a chunk of CSV lines and extract r values."""
    r_map = defaultdict(list)
    reader = csv.DictReader(chunk, fieldnames=header)
    for row in reader:
        sigscript = row.get("scriptSig") or row.get("script")
        if not sigscript:
            continue

        r, s = extract_r_s_from_sig(sigscript)
        if not r or not s:
            continue

        txid = row.get("txid") or row.get("tx_hash")
        vin = row.get("index") or row.get("input_index")
        r_map[r].append((txid, vin, s))
    return r_map


def merge_maps(map_list):
    merged = defaultdict(list)
    for part in map_list:
        for r, vals in part.items():
            merged[r].extend(vals)
    return merged


def scan_reused_r(csv_file):
    print(f"Scanning {csv_file} with {WORKERS} workers ...")
    logging.info(f"Scanning {csv_file} with {WORKERS} workers ...")

    # Resume from checkpoint if available
    if os.path.exists(CHECKPOINT_FILE):
        print("🔄 Resuming from checkpoint...")
        with open(CHECKPOINT_FILE, "rb") as f:
            start_bytes, merged = pickle.load(f)
    else:
        start_bytes, merged = 0, defaultdict(list)

    results = []
    pool = mp.Pool(WORKERS)

    with open(csv_file, newline='', encoding="utf-8") as f:
        header = next(csv.reader(f))  # header row
        processed_bytes = 0

        # Skip bytes already processed
        if start_bytes:
            f.seek(start_bytes)

        total_size = os.path.getsize(csv_file)

        with tqdm(total=total_size, unit="B", unit_scale=True, desc="Processing") as pbar:
            if start_bytes:
                pbar.update(start_bytes)

            chunk = []
            for line in f:
                chunk.append(line)
                processed_bytes += len(line.encode("utf-8"))
                pbar.update(len(line.encode("utf-8")))

                if len(chunk) >= CHUNK_SIZE:
                    results.append(pool.apply_async(process_chunk, (chunk, header)))
                    chunk = []

                    if len(results) >= WORKERS:
                        maps = [r.get() for r in results]
                        merged = merge_maps([merged] + maps)
                        results = []

                        with open(CHECKPOINT_FILE, "wb") as ckpt:
                            pickle.dump((processed_bytes, merged), ckpt)

            if chunk:
                results.append(pool.apply_async(process_chunk, (chunk, header)))

        pool.close()
        pool.join()

    maps = [r.get() for r in results]
    merged = merge_maps([merged] + maps)

    with open(CHECKPOINT_FILE, "wb") as ckpt:
        pickle.dump((processed_bytes, merged), ckpt)

    # Write results
    timestamp = time.strftime("%Y%m%d_%H%M")
    out_file = f"scan_results_reused_r_mp_{timestamp}.jsonl"
    reused_count = 0

    with open(out_file, "w", encoding="utf-8") as out:
        for r, entries in merged.items():
            if len(entries) > 1:
                reused_count += 1
                result = {"r": r, "entries": []}
                print(f"\n⚠️ Reused r: {r}")
                for txid, vin, s in entries:
                    print(f"   txid={txid}, input={vin}, s={s}")
                    result["entries"].append({
                        "txid": txid,
                        "input": vin,
                        "s": s
                    })
                out.write(json.dumps(result) + "\n")

    if reused_count == 0:
        print("✅ No reused r values found.")
    else:
        print(f"\n✅ Found {reused_count} reused r values. Results saved to {out_file}")


if __name__ == "__main__":
    scan_reused_r(CSV_PATH)
