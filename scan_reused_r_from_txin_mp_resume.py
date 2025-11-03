#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Multiprocessing scanner for reused ECDSA r values from Rusty-Blockparser's tx_in-XXXXX.csv
- Handles very large CSVs (100s of GB)
- Parallel processing
- Progress bar
- Checkpointing to resume after interruption
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
CHUNK_SIZE = 5_000_000   # number of lines per chunk (tune for RAM/speed)
WORKERS = max(1, mp.cpu_count() - 1)
CHECKPOINT_FILE = "reused_r_checkpoint.pkl"

# --- Logging ---
logging.basicConfig(filename='scan_reused_r_from_txin_mp_resume.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def extract_r_s_from_sig(sig_hex):
    """Parse DER-encoded ECDSA signature and return (r, s)."""
    try:
        sig_bytes = bytes.fromhex(sig_hex)
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
            start_line, merged = pickle.load(f)
    else:
        start_line, merged = 0, defaultdict(list)

    results = []
    pool = mp.Pool(WORKERS)

    with open(csv_file, newline='', encoding="utf-8") as f:
        header = next(csv.reader(f))  # header row
        current_line = 1  # header already consumed
        chunk = []
        chunk_id = 0

        # skip lines already processed
        for _ in range(start_line):
            next(f, None)
            current_line += 1

        total_size = os.path.getsize(csv_file)

        with tqdm(total=total_size, unit="B", unit_scale=True, desc="Processing") as pbar:
            processed_bytes = start_line
            pbar.update(processed_bytes)

            for line in f:
                chunk.append(line)
                processed_bytes += len(line.encode("utf-8"))
                pbar.update(len(line.encode("utf-8")))

                if len(chunk) >= CHUNK_SIZE:
                    chunk_id += 1
                    results.append(pool.apply_async(process_chunk, (chunk, header)))
                    chunk = []

                    # merge completed results periodically
                    if len(results) >= WORKERS:
                        maps = [r.get() for r in results]
                        merged = merge_maps([merged] + maps)
                        results = []

                        # save checkpoint
                        with open(CHECKPOINT_FILE, "wb") as ckpt:
                            pickle.dump((processed_bytes, merged), ckpt)

            # leftover
            if chunk:
                results.append(pool.apply_async(process_chunk, (chunk, header)))

        pool.close()
        pool.join()

    # merge all
    maps = [r.get() for r in results]
    merged = merge_maps([merged] + maps)

    # save final checkpoint
    with open(CHECKPOINT_FILE, "wb") as ckpt:
        pickle.dump((processed_bytes, merged), ckpt)

    # write results
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
