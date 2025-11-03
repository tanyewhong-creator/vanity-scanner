#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check Bitcoin address balance from Rusty-Blockparser dump.
Needs tx_out and tx_in CSVs.
"""

import csv
import os

# --- Config ---
ADDRESS = "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"
TX_OUT_PATH = r"D:\rbp_dump\tx_out-0-914566.csv"
TX_IN_PATH = r"D:\rbp_dump\tx_in-0-914566.csv"

def load_unspent(address, tx_out_file):
    """Return dict {(txid, vout): value} of outputs belonging to address."""
    unspent = {}
    with open(tx_out_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            addr = row.get("address")
            if addr == address:
                txid = row.get("txid") or row.get("tx_hash")
                vout = row.get("index") or row.get("vout")
                value = float(row.get("value") or 0)
                unspent[(txid, vout)] = value
    return unspent

def remove_spent(unspent, tx_in_file):
    """Remove spent outputs from the unspent dict."""
    with open(tx_in_file, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prev_txid = row.get("prev_txid") or row.get("prev_out_hash")
            prev_vout = row.get("prev_vout") or row.get("prev_out_index")
            key = (prev_txid, prev_vout)
            if key in unspent:
                del unspent[key]

def check_balance(address, tx_out_file, tx_in_file):
    unspent = load_unspent(address, tx_out_file)
    remove_spent(unspent, tx_in_file)
    balance = sum(unspent.values())
    return balance, unspent

if __name__ == "__main__":
    balance, utxos = check_balance(ADDRESS, TX_OUT_PATH, TX_IN_PATH)
    print(f"Address: {ADDRESS}")
    print(f"Balance: {balance:.8f} BTC")
    print("\nUnspent outputs:")
    for (txid, vout), value in utxos.items():
        print(f"  {txid}:{vout}  {value:.8f} BTC")
