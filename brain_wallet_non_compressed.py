import hashlib
import base58
from ecdsa import SigningKey, SECP256k1

# Step 1: Get passphrase from user input
passphrase = input("Enter brainwallet passphrase: ").strip()
print(f"Raw input: {repr(passphrase)}")  # Debug to confirm input

# Step 2: SHA256(passphrase) => private key
private_key_bytes = hashlib.sha256(passphrase.encode('utf-8')).digest()
private_key_hex = private_key_bytes.hex()
print(f"[1] Private Key (hex): {private_key_hex}")

# Step 3: Convert to WIF (Mainnet, non-compressed)
prefix = b'\x80'  # Mainnet prefix
wif_payload = prefix + private_key_bytes  # No 0x01 suffix for non-compressed
checksum = hashlib.sha256(hashlib.sha256(wif_payload).digest()).digest()[:4]
wif = base58.b58encode(wif_payload + checksum).decode()
print(f"[2] WIF (Non-Compressed): {wif}")

# Step 4: Derive non-compressed public key
sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
vk = sk.verifying_key
x = vk.pubkey.point.x()
y = vk.pubkey.point.y()
public_key = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')  # Non-compressed: 0x04 + x + y
print(f"[3] Public Key (Non-Compressed, hex): {public_key.hex()}")

# Step 5: Generate Bitcoin address (P2PKH)
ripemd160 = hashlib.new('ripemd160')
ripemd160.update(hashlib.sha256(public_key).digest())
pubkey_hash = ripemd160.digest()
addr_payload = b'\x00' + pubkey_hash  # 0x00 for mainnet
checksum = hashlib.sha256(hashlib.sha256(addr_payload).digest()).digest()[:4]
address = base58.b58encode(addr_payload + checksum).decode()
print(f"[4] Bitcoin Address (P2PKH): {address}")