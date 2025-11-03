#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3, csv, os, time

DB_FILE = r"D:\rbp_dump\transactions_lite.db"
CSV_FILE = r"D:\rbp_dump\transactions-0-914566.csv"
BATCH_SIZE = 100_000

def create_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            txid TEXT PRIMARY KEY,
            block_height INTEGER
        )
    """)
    conn.commit()
    return conn

def import_csv(conn, csv_file):
    cur = conn.cursor()
    count = 0
    batch = []
    start = time.time()

    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            txid = row.get("txid") or row.get("hash")
            height = row.get("block_height") or row.get("height")
            if txid:
                batch.append((txid, height))
                count += 1

            if len(batch) >= BATCH_SIZE:
                cur.executemany(
                    "INSERT OR IGNORE INTO transactions (txid, block_height) VALUES (?, ?)",
                    batch
                )
                conn.commit()
                print(f"   {count:,} rows inserted...")
                batch.clear()

    if batch:
        cur.executemany(
            "INSERT OR IGNORE INTO transactions (txid, block_height) VALUES (?, ?)",
            batch
        )
        conn.commit()

    elapsed = time.time() - start
    print(f"✅ Imported {count:,} transactions in {elapsed/60:.1f} minutes")

if __name__ == "__main__":
    conn = create_db()
    import_csv(conn, CSV_FILE)
    conn.close()
