#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
High-speed importer for Rusty-Blockparser CSVs into SQLite.
- Optimized for speed: WAL, synchronous=OFF, big cache
- Parallel import (1 process per CSV)
- Resume from checkpoints
- Ctrl+C to stop gracefully
- Clean single-line progress with ETA
"""

import sqlite3, csv, os, time, sys, signal, pickle, multiprocessing as mp

DB_FILE = r"D:\rbp_dump\blockchain.db"
CSV_DIR = r"D:\rbp_dump"
BATCH_SIZE = 10_000         # rows per commit
CHECKPOINT_DIR = "checkpoints"
os.makedirs(CHECKPOINT_DIR, exist_ok=True)

stop_flag = mp.Value("b", False)


# ==============================
# Database + schema
# ==============================
def create_db():
    conn = sqlite3.connect(DB_FILE, timeout=60)
    cur = conn.cursor()

    # 🔥 speed pragmas
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=OFF;")
    cur.execute("PRAGMA temp_store=MEMORY;")
    cur.execute("PRAGMA cache_size=-500000;")  # ~500MB

    # Tables
    cur.execute("""CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        hash TEXT,
        time INTEGER,
        version INTEGER,
        merkle_root TEXT,
        nonce INTEGER,
        bits TEXT
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS transactions (
        txid TEXT PRIMARY KEY,
        block_height INTEGER,
        version INTEGER,
        lock_time INTEGER
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS tx_in (
        txid TEXT,
        input_index INTEGER,
        prev_txid TEXT,
        prev_vout INTEGER,
        scriptSig TEXT,
        sequence INTEGER
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS tx_out (
        txid TEXT,
        vout INTEGER,
        value REAL,
        scriptPubKey TEXT,
        address TEXT
    )""")

    conn.commit()
    return conn


TABLES = {
    "blocks": {
        "csv": "blocks-0-914566.csv",
        "columns": ["height", "hash", "time", "version", "merkle_root", "nonce", "bits"],
    },
    "transactions": {
        "csv": "transactions-0-914566.csv",
        "columns": ["txid", "block_height", "version", "lock_time"],
    },
    "tx_in": {
        "csv": "tx_in-0-914566.csv",
        "columns": ["txid", "input_index", "prev_txid", "prev_vout", "scriptSig", "sequence"],
    },
    "tx_out": {
        "csv": "tx_out-0-914566.csv",
        "columns": ["txid", "vout", "value", "scriptPubKey", "address"],
    },
}


# ==============================
# Import function
# ==============================
def import_csv(table, csv_file, columns):
    conn = sqlite3.connect(DB_FILE, timeout=60)
    cur = conn.cursor()

    checkpoint_file = os.path.join(CHECKPOINT_DIR, f"{table}.pkl")
    start_row = 0
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "rb") as f:
            start_row = pickle.load(f)

    total_size = os.path.getsize(csv_file)
    processed_bytes = 0
    start_time = time.time()

    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        # skip processed rows
        for _ in range(start_row):
            processed_bytes += len(next(f).encode("utf-8", "ignore"))

        batch, row_id = [], start_row
        for line in f:
            if stop_flag.value:
                break

            row_id += 1
            processed_bytes += len(line.encode("utf-8", "ignore"))
            row = dict(zip(reader.fieldnames, line.strip().split(",")))
            values = tuple(row.get(col, None) for col in columns)
            batch.append(values)

            if len(batch) >= BATCH_SIZE:
                cur.executemany(
                    f"INSERT OR IGNORE INTO {table} ({','.join(columns)}) VALUES ({','.join(['?']*len(columns))})",
                    batch,
                )
                conn.commit()
                batch.clear()

                with open(checkpoint_file, "wb") as ckpt:
                    pickle.dump(row_id, ckpt)

                elapsed = (time.time() - start_time) / 3600
                progress = processed_bytes / total_size
                eta = elapsed / progress - elapsed if progress > 0 else 0
                sys.stdout.write(
                    f"\r[{table}] {progress*100:6.2f}% | Elapsed {elapsed:5.2f}h | ETA {eta:5.2f}h"
                )
                sys.stdout.flush()

        if batch:
            cur.executemany(
                f"INSERT OR IGNORE INTO {table} ({','.join(columns)}) VALUES ({','.join(['?']*len(columns))})",
                batch,
            )
            conn.commit()

    conn.close()
    sys.stdout.write(f"\r[{table}] 100.00% | Elapsed {(time.time()-start_time)/3600:5.2f}h | ETA 0.00h ✅\n")
    sys.stdout.flush()


# ==============================
# Ctrl+C handler
# ==============================
def handle_sigint(sig, frame):
    print("\n🛑 Stopping gracefully... will resume next run.")
    stop_flag.value = True


# ==============================
# Main
# ==============================
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_sigint)
    create_db().close()

    with mp.Pool(processes=max(1, mp.cpu_count() - 1)) as pool:
        jobs = []
        for table, cfg in TABLES.items():
            csv_file = os.path.join(CSV_DIR, cfg["csv"])
            jobs.append(pool.apply_async(import_csv, (table, csv_file, cfg["columns"])))
        for j in jobs:
            j.get()
