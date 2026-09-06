import sys

def convert_line(line):
    parts = line.strip().split(';')
    if len(parts) < 6:
        return None
    
    r = parts[0]          # keep as hex string
    s = parts[1]          # keep as hex string
    z = parts[3]          # keep as hex string
    pub = parts[2]        # keep as hex string
    
    # Concatenate r and s (both are hex strings, just join them)
    signature_hex = r + s
    
    # nonce bit length: 256 for secp256k1
    nonce_bits = 256
    
    # Format: nonce_bits hash_hex signature_hex public_key_hex
    return f"{nonce_bits} {z} {signature_hex} {pub}"

if __name__ == "__main__":
    with open("my_signatures.txt", "r") as fin, open("input.txt", "w") as fout:
        for line in fin:
            res = convert_line(line)
            if res:
                fout.write(res + "\n")
