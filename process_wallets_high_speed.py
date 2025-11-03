import hashlib
import base58
import csv
import json
import signal
import sys
from ecdsa import SigningKey, SECP256k1
import os
import time
from multiprocessing import Pool, cpu_count
import functools

# Global variable to track if we should stop processing
stop_processing = False

def signal_handler(sig, frame):
    """Handle Ctrl+C signal gracefully"""
    global stop_processing
    print(f"\n\nCtrl+C detected! Stopping processing gracefully...")
    stop_processing = True
    sys.exit(0)

def generate_wallet_info(passphrase):
    """Generate wallet information from a passphrase - OPTIMIZED VERSION"""
    try:
        # Step 1: SHA256(passphrase) => private key
        private_key_bytes = hashlib.sha256(passphrase.encode('utf-8')).digest()
        private_key_hex = private_key_bytes.hex()

        # Step 2: Convert to WIF (Mainnet, non-compressed)
        prefix = b'\x80'
        wif_payload = prefix + private_key_bytes
        # Double SHA256 in one line
        checksum = hashlib.sha256(hashlib.sha256(wif_payload).digest()).digest()[:4]
        wif = base58.b58encode(wif_payload + checksum).decode()

        # Step 3: Derive non-compressed public key
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        vk = sk.verifying_key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        public_key = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        public_key_hex = public_key.hex()

        # Step 4: Generate Bitcoin address (P2PKH)
        # Precompute SHA256 of public key
        sha256_pubkey = hashlib.sha256(public_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_pubkey)
        pubkey_hash = ripemd160.digest()
        
        addr_payload = b'\x00' + pubkey_hash
        addr_checksum = hashlib.sha256(hashlib.sha256(addr_payload).digest()).digest()[:4]
        address = base58.b58encode(addr_payload + addr_checksum).decode()

        return {
            "Raw input": repr(passphrase),
            "Private Key (hex)": private_key_hex,
            "WIF (Non-Compressed)": wif,
            "Public Key (Non-Compressed, hex)": public_key_hex,
            "Bitcoin Address (P2PKH)": address
        }
        
    except Exception as e:
        return {
            "Raw input": repr(passphrase),
            "Error": str(e)
        }

def process_batch(args):
    """Process a batch of addresses for parallel processing"""
    addresses, output_file_path = args
    results = []
    
    for address in addresses:
        if stop_processing:
            break
        results.append(generate_wallet_info(address))
    
    # Write batch to file
    if results and not stop_processing:
        with open(output_file_path, 'a', encoding='utf-8') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
    
    return len(results)

def get_processed_addresses(output_file_path):
    """Get set of addresses that have already been processed - OPTIMIZED"""
    processed_addresses = set()
    if os.path.exists(output_file_path):
        try:
            # Read in larger chunks for efficiency
            with open(output_file_path, 'r', encoding='utf-8') as f:
                buffer = []
                for line in f:
                    buffer.append(line)
                    if len(buffer) >= 1000:  # Process in chunks
                        for line_in_buffer in buffer:
                            try:
                                if line_in_buffer.strip():
                                    data = json.loads(line_in_buffer.strip())
                                    raw_input = data.get("Raw input", "")
                                    if raw_input.startswith("'") and raw_input.endswith("'"):
                                        address = raw_input[1:-1]
                                        processed_addresses.add(address)
                            except:
                                continue
                        buffer = []
                # Process remaining buffer
                for line_in_buffer in buffer:
                    try:
                        if line_in_buffer.strip():
                            data = json.loads(line_in_buffer.strip())
                            raw_input = data.get("Raw input", "")
                            if raw_input.startswith("'") and raw_input.endswith("'"):
                                address = raw_input[1:-1]
                                processed_addresses.add(address)
                    except:
                        continue
        except Exception as e:
            print(f"Warning: Could not read existing output file: {e}")
    return processed_addresses

def get_file_size(file_path):
    """Get human-readable file size"""
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    return "0 B"

def process_csv_file_fast(csv_file_path, output_file_path, batch_size=1000):
    """Process CSV file with maximum speed"""
    global stop_processing
    
    try:
        # Get already processed addresses
        processed_addresses = get_processed_addresses(output_file_path)
        print(f"Found {len(processed_addresses)} already processed addresses")
        
        # Read all addresses first for faster processing
        addresses_to_process = []
        total_rows = 0
        
        with open(csv_file_path, 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file, delimiter=';')
            next(reader)  # Skip header row
            
            for row in reader:
                if stop_processing:
                    break
                    
                total_rows += 1
                if row and row[0].strip():
                    address = row[0].strip()
                    if address not in processed_addresses:
                        addresses_to_process.append(address)
        
        if stop_processing:
            return 0, 0, total_rows
        
        print(f"Found {len(addresses_to_process)} addresses to process")
        
        # Process in batches for better performance
        processed_rows = 0
        start_time = time.time()
        last_update_time = start_time
        
        # Process in batches (no parallel for simplicity, but optimized)
        for i in range(0, len(addresses_to_process), batch_size):
            if stop_processing:
                break
                
            batch = addresses_to_process[i:i + batch_size]
            batch_results = []
            
            for address in batch:
                batch_results.append(generate_wallet_info(address))
            
            # Write batch to file
            with open(output_file_path, 'a', encoding='utf-8') as f:
                for result in batch_results:
                    f.write(json.dumps(result) + '\n')
            
            processed_rows += len(batch)
            
            # Update progress less frequently for better performance
            current_time = time.time()
            if current_time - last_update_time >= 1.0:  # Update every second
                elapsed = current_time - start_time
                speed = processed_rows / elapsed if elapsed > 0 else 0
                file_size = get_file_size(output_file_path)
                print(f"Processed {processed_rows}/{len(addresses_to_process)} rows | Speed: {speed:.1f} rows/sec | File: {file_size}")
                last_update_time = current_time
        
        return processed_rows, len(addresses_to_process), total_rows
        
    except Exception as e:
        print(f"Error processing CSV file: {e}")
        return 0, 0, 0

def main():
    """Main function with user interaction"""
    global stop_processing
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    csv_file_path = r"D:\balances-0-914122.csv"
    output_file_path = r"D:\wallet_info_output.jsonl"
    
    # Check if CSV file exists
    if not os.path.exists(csv_file_path):
        print(f"CSV file not found at: {csv_file_path}")
        print("Please make sure the file exists or update the path in the script.")
        return
    
    print(f"Found CSV file: {csv_file_path}")
    print(f"Output will be saved to: {output_file_path}")
    print("Press Ctrl+C at any time to stop processing gracefully")
    print("-" * 60)
    
    # Check if output file exists
    if os.path.exists(output_file_path):
        initial_size = get_file_size(output_file_path)
        processed_count = len(get_processed_addresses(output_file_path))
        print(f"Existing output file found: {initial_size} with {processed_count} entries")
        
        choice = input("Do you want to resume processing? (y/n): ").strip().lower()
        if choice not in ['y', 'yes']:
            # Backup existing file
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_path = f"{output_file_path}.backup_{timestamp}"
            os.rename(output_file_path, backup_path)
            print(f"Existing file backed up to: {backup_path}")
            # Create empty file
            open(output_file_path, 'w').close()
    else:
        # Create empty file
        open(output_file_path, 'w').close()
        print("Created new output file")
    
    print("Starting HIGH-SPEED processing...")
    print("=" * 60)
    
    try:
        start_time = time.time()
        processed_rows, total_to_process, total_rows = process_csv_file_fast(csv_file_path, output_file_path, batch_size=500)
        elapsed = time.time() - start_time
        
        if stop_processing:
            print(f"\nProcessing stopped by user!")
        else:
            print(f"\nProcessing completed!")
        
        print(f"Total time: {elapsed:.2f} seconds")
        print(f"Total rows in CSV: {total_rows}")
        print(f"Addresses to process: {total_to_process}")
        print(f"Processed rows: {processed_rows}")
        print(f"Processing speed: {processed_rows/elapsed:.1f} rows/sec" if elapsed > 0 else "Speed: N/A")
        
        final_file_size = get_file_size(output_file_path)
        print(f"Final output file size: {final_file_size}")
        print(f"Output saved to: {output_file_path}")
        
        if stop_processing:
            print("\nYou can resume later by running the script again")
        
    except KeyboardInterrupt:
        stop_processing = True
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        if stop_processing:
            current_size = get_file_size(output_file_path)
            processed_count = len(get_processed_addresses(output_file_path))
            print(f"\nFinal status: {processed_count} entries processed")
            print(f"Final file size: {current_size}")

if __name__ == "__main__":
    main()