import requests
import json
import logging
import time
import os

# Set up logging
logging.basicConfig(filename='scan_reused_r.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to parse DER-encoded signature and extract r and s values
def extract_r_s_from_sigscript(sigscript):
    try:
        sig_bytes = bytes.fromhex(sigscript)
        if len(sig_bytes) < 1:
            logging.debug(f"Empty or invalid sigscript: {sigscript}")
            return None, None
        sig_length = sig_bytes[0]
        if sig_length + 1 > len(sig_bytes):
            logging.debug(f"Invalid signature length in sigscript: {sigscript}")
            return None, None
        sig_bytes = sig_bytes[1:sig_length + 1]
        if not sig_bytes.startswith(b"\x30"):
            logging.debug(f"Invalid DER sequence in sigscript: {sigscript}")
            return None, None
        total_length = sig_bytes[1]
        if total_length + 2 > len(sig_bytes):
            logging.debug(f"Invalid total length in sigscript: {sigscript}")
            return None, None
        pos = 2
        if pos + 1 >= len(sig_bytes) or sig_bytes[pos] != 0x02:
            logging.debug(f"Invalid r integer marker in sigscript: {sigscript}")
            return None, None
        pos += 1
        r_length = sig_bytes[pos]
        if pos + r_length >= len(sig_bytes):
            logging.debug(f"Invalid r length in sigscript: {sigscript}")
            return None, None
        pos += 1
        r = sig_bytes[pos:pos + r_length].hex()
        pos += r_length
        if pos + 1 >= len(sig_bytes) or sig_bytes[pos] != 0x02:
            logging.debug(f"Invalid s integer marker in sigscript: {sigscript}")
            return None, None
        pos += 1
        s_length = sig_bytes[pos]
        if pos + s_length >= len(sig_bytes):
            logging.debug(f"Invalid s length in sigscript: {sigscript}")
            return None, None
        pos += 1
        s = sig_bytes[pos:pos + s_length].hex()
        logging.debug(f"Extracted r: 0x{r}, length: {r_length}, s: 0x{s}, length: {s_length}")
        return r, s
    except Exception as e:
        logging.error(f"Error parsing sigscript {sigscript}: {e}")
        return None, None

# Function to parse witness data and extract r and s values
def extract_r_s_from_witness(witness):
    try:
        # Witness is a list of items; signature is typically the first or second item
        for item in witness:
            try:
                sig_bytes = bytes.fromhex(item)
                if not sig_bytes.startswith(b"\x30"):  # Check for DER-encoded signature
                    continue
                sig_length = sig_bytes[0]
                if sig_length + 1 > len(sig_bytes):
                    continue
                sig_bytes = sig_bytes[1:sig_length + 1]
                total_length = sig_bytes[1]
                if total_length + 2 > len(sig_bytes):
                    continue
                pos = 2
                if pos + 1 >= len(sig_bytes) or sig_bytes[pos] != 0x02:
                    continue
                pos += 1
                r_length = sig_bytes[pos]
                if pos + r_length >= len(sig_bytes):
                    continue
                pos += 1
                r = sig_bytes[pos:pos + r_length].hex()
                pos += r_length
                if pos + 1 >= len(sig_bytes) or sig_bytes[pos] != 0x02:
                    continue
                pos += 1
                s_length = sig_bytes[pos]
                if pos + s_length >= len(sig_bytes):
                    continue
                pos += 1
                s = sig_bytes[pos:pos + s_length].hex()
                logging.debug(f"Extracted r: 0x{r}, s: 0x{s} from witness")
                return r, s
            except Exception:
                continue
        return None, None
    except Exception as e:
        logging.error(f"Error parsing witness: {e}")
        return None, None

# Function to check transaction for reused r values
def check_transaction_for_reused_r(txid, address=None):
    try:
        # Get transaction data
        response = requests.get(f"https://blockchain.info/rawtx/{txid}")
        response.raise_for_status()
        tx_data = response.json()
        
        # Get raw transaction hex
        raw_response = requests.get(f"https://blockchain.info/rawtx/{txid}?format=hex")
        raw_response.raise_for_status()
        raw_hex = raw_response.text.strip()
        
        # Check if transaction has at least 2 inputs
        inputs = tx_data.get("inputs", [])
        if len(inputs) < 2:
            logging.debug(f"Txid {txid} has {len(inputs)} inputs, skipping")
            return None, None, None, None, None, None, None
        
        # Verify address is in inputs and collect script_pubkey and address
        if address:
            is_spending = False
            script_pubkeys = []
            input_addresses = []
            for inp in inputs:
                if "prev_out" in inp and "addr" in inp["prev_out"] and "script" in inp["prev_out"]:
                    input_addresses.append(inp["prev_out"]["addr"])
                    script_pubkeys.append(inp["prev_out"]["script"])
                    if inp["prev_out"]["addr"] == address:
                        is_spending = True
                else:
                    input_addresses.append(None)
                    script_pubkeys.append(None)
            if not is_spending:
                logging.debug(f"Txid {txid} is not a spending transaction for address {address}")
                return None, None, None, None, None, None, None
        
        r_values = []
        s_values = []
        is_segwit = "witness" in tx_data or any("witness" in inp for inp in inputs)
        for i, inp in enumerate(inputs):
            if is_segwit and "witness" in inp:
                r, s = extract_r_s_from_witness(inp["witness"])
                if r and s:
                    r_values.append((i, r))
                    s_values.append(s)
                    logging.debug(f"Txid {txid}, input {i}, r: 0x{r}, s: 0x{s} (from witness)")
            elif "script" in inp:
                sigscript = inp["script"]
                # Handle P2SH by checking if scriptSig contains a redeem script
                try:
                    script_bytes = bytes.fromhex(sigscript)
                    if script_bytes[-1] == 0xae:  # OP_CHECKMULTISIG for P2SH
                        # Last item is likely the redeem script; signatures are before it
                        items = []
                        pos = 0
                        while pos < len(script_bytes):
                            if pos + 1 < len(script_bytes) and script_bytes[pos] == 0:
                                pos += 1
                                continue
                            length = script_bytes[pos]
                            pos += 1
                            if pos + length <= len(script_bytes):
                                items.append(script_bytes[pos:pos + length].hex())
                                pos += length
                        for item in items[:-1]:  # Exclude redeem script
                            r, s = extract_r_s_from_sigscript(item)
                            if r and s:
                                r_values.append((i, r))
                                s_values.append(s)
                                logging.debug(f"Txid {txid}, input {i}, r: 0x{r}, s: 0x{s} (from P2SH scriptSig)")
                    else:
                        r, s = extract_r_s_from_sigscript(sigscript)
                        if r and s:
                            r_values.append((i, r))
                            s_values.append(s)
                            logging.debug(f"Txid {txid}, input {i}, r: 0x{r}, s: 0x{s} (from P2PKH scriptSig)")
                except Exception as e:
                    logging.debug(f"Error parsing scriptSig for input {i}: {e}")
        
        # Check for reused r values
        r_set = set(r for _, r in r_values)
        if len(r_set) < len(r_values):  # Reused r detected
            reused_r = [r for r in r_set if sum(1 for _, r2 in r_values if r2 == r) > 1]
            s1, s2 = None, None
            script_pubkey1, script_pubkey2 = None, None
            address1, address2 = None, None
            for i, r in r_values:
                if r in reused_r:
                    if s1 is None:
                        s1 = s_values[i]
                        script_pubkey1 = script_pubkeys[i]
                        address1 = input_addresses[i]
                    elif s2 is None and s_values[i] != s1:
                        s2 = s_values[i]
                        script_pubkey2 = script_pubkeys[i]
                        address2 = input_addresses[i]
                    if s1 and s2:
                        break
            logging.info(f"Found vulnerable txid: {txid}, address: {address}, reused r: {reused_r}, "
                         f"s1: {s1}, s2: {s2}, script_pubkey1: {script_pubkey1}, "
                         f"script_pubkey2: {script_pubkey2}, raw_hex: {raw_hex}")
            return txid, address, reused_r, s1, s2, (script_pubkey1, script_pubkey2), raw_hex
        logging.debug(f"Txid {txid} has no reused r values")
        return None, None, None, None, None, None, None
    except Exception as e:
        logging.error(f"Error processing txid {txid}: {e}")
        return None, None, None, None, None, None, None

# Function to scan transactions for a specific address
def scan_address_for_reused_r(address, max_txs=200):
    print(f"Scanning transactions for address {address}...")
    logging.info(f"Scanning transactions for address {address}")
    vulnerable_txs = []
    
    # Generate JSONL filename based on address and timestamp
    timestamp = time.strftime("%Y%m%d_%H%M")
    jsonl_filename = f"scan_results_{address}_{timestamp}.jsonl"
    # Save to the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    jsonl_filepath = os.path.join(script_dir, jsonl_filename)
    print(f"Saving results to {jsonl_filepath}")
    logging.info(f"Saving results to {jsonl_filepath}")
    
    # Use Blockchain.com API with pagination
    try:
        txids = []
        offset = 0
        while True:
            url = f"https://blockchain.info/rawaddr/{address}?limit={max_txs}&offset={offset}"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            new_txids = [tx["hash"] for tx in data.get("txs", [])]
            txids.extend(new_txids)
            print(f"Fetched {len(new_txids)} transactions at offset {offset}, total {len(txids)}")
            logging.info(f"Fetched {len(new_txids)} transactions at offset {offset}, total {len(txids)}")
            if len(new_txids) < max_txs:
                break
            offset += max_txs
        print(f"Found {len(txids)} transactions for address {address} via Blockchain.com")
        logging.info(f"Found {len(txids)} transactions for address {address} via Blockchain.com")
        for txid in txids:
            vuln_txid, vuln_address, reused_r, s1, s2, script_pubkeys, raw_hex = check_transaction_for_reused_r(txid, address)
            if vuln_txid:
                vulnerable_txs.append((vuln_txid, vuln_address, reused_r, s1, s2, script_pubkeys, raw_hex))
    except Exception as e:
        print(f"Blockchain.com API query failed: {e}")
        logging.error(f"Blockchain.com API query failed: {e}")
        # Fallback to Blockstream API
        try:
            url = f"https://blockstream.info/api/address/{address}/txs"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            txids = [tx["txid"] for tx in data]
            print(f"Found {len(txids)} transactions for address {address} via Blockstream")
            logging.info(f"Found {len(txids)} transactions for address {address} via Blockstream")
            for txid in txids:
                vuln_txid, vuln_address, reused_r, s1, s2, script_pubkeys, raw_hex = check_transaction_for_reused_r(txid, address)
                if vuln_txid:
                    vulnerable_txs.append((vuln_txid, vuln_address, reused_r, s1, s2, script_pubkeys, raw_hex))
        except Exception as e:
            print(f"Blockstream API query failed: {e}")
            logging.error(f"Blockstream API query failed: {e}")

    # Output results and save to JSONL
    if vulnerable_txs:
        print("\nVulnerable transactions found:")
        print("=" * 80)
        with open(jsonl_filepath, 'w') as jsonl_file:
            for txid, vuln_address, reused_r, s1, s2, (script_pubkey1, script_pubkey2), raw_hex in vulnerable_txs:
                print(f"Txid: {txid}")
                print(f"Address: {vuln_address}")
                print(f"Reused r: {reused_r[0]}")
                print(f"s1: {s1}")
                print(f"s2: {s2}")
                print(f"script_pubkey1: {script_pubkey1}")
                print(f"script_pubkey2: {script_pubkey2}")
                print(f"raw_hex: {raw_hex}")
                print("-" * 80)
                logging.info(f"Txid: {txid}, Address: {vuln_address}, Reused r: {reused_r}, s1: {s1}, s2: {s2}, "
                             f"script_pubkey1: {script_pubkey1}, script_pubkey2: {script_pubkey2}, raw_hex: {raw_hex}")
                # Save to JSONL
                result = {
                    "txid": txid,
                    "address": vuln_address,
                    "reused_r": reused_r[0],
                    "s1": s1,
                    "s2": s2,
                    "script_pubkey1": script_pubkey1,
                    "script_pubkey2": script_pubkey2,
                    "raw_hex": raw_hex
                }
                jsonl_file.write(json.dumps(result) + "\n")
        print(f"Results saved to {jsonl_filepath}")
    else:
        print(f"\nNo vulnerable transactions found for address {address}.")
        logging.info(f"No vulnerable transactions found for address {address}.")
    
    return vulnerable_txs

# Configuration
address = "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm"  # Your previous vulnerable address
max_txs = 200  # Number of transactions per API call

# Run the scan
vulnerable_transactions = scan_address_for_reused_r(address, max_txs)