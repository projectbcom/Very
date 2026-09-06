#!/usr/bin/env sage

from sage.all import *
import sys

sys.stdout.write("=== attack.sage started ===\n")
sys.stdout.flush()

# secp256r1 (NIST P-256) order
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
bits = 5
SCALE = 2**(256 - bits)  # upper bound for nonces

def parse_sigs(filepath):
    sigs = []
    with open(filepath, 'r') as f:
        for line in f:
            parts = line.strip().split(';')
            if len(parts) < 6:
                continue
            r = int(parts[0], 16)
            s = int(parts[1], 16)
            z = int(parts[3], 16)
            pub = parts[2]
            sigs.append((r, s, z, pub))
    sys.stdout.write(f"Parsed {len(sigs)} signatures.\n")
    sys.stdout.flush()
    return sigs

def verify_key(d, pub_hex):
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    E = EllipticCurve(GF(p), [a, b])
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    G = E(Gx, Gy)
    pub_point = G * d
    x_hex = hex(pub_point[0])[2:].zfill(64)
    y_hex = hex(pub_point[1])[2:].zfill(64)
    computed = "04" + x_hex + y_hex
    return computed == pub_hex

def attack(sigs):
    m = len(sigs)
    if m < 2:
        return None
    # Build HNP lattice: 
    # We want vector (d, k_1, ..., k_m, 1) such that:
    # r_i*d + s_i*k_i - z_i*1 ≡ 0 (mod N) for each i.
    # Lattice rows (each is a linear equation modulo N):
    # Row i: (r_i, 0,..., s_i at column i+1, ..., -z_i)
    # Last row: (N, 0, ..., 0)
    # We need m+2 columns: column 0 for d, columns 1..m for k_i, column m+1 for constant 1.
    # The lattice basis:
    # B = [[N, 0, ..., 0],   # modulus row
    #      [r_0, s_0, 0, ..., -z_0],
    #      [r_1, 0, s_1, ..., -z_1],
    #      ...
    #      [r_{m-1}, 0, ..., s_{m-1}, -z_{m-1}]]
    # But we also want to enforce that the constant 1 is exactly 1, so we add a row (0,...,0,1) and reduce it.
    # Actually, the standard approach is to include a column for the constant and then after reduction, look for a vector with last coordinate 1.
    # We'll use the construction from the literature: 
    # B = [[N, 0, 0, ..., 0],
    #      [r_0, s_0, 0, ..., -z_0],
    #      [r_1, 0, s_1, ..., -z_1],
    #      ...
    #      [r_{m-1}, 0, ..., s_{m-1}, -z_{m-1}]]
    # Then we need to add a row (0, ..., 0, 1) to fix the constant to 1? Actually we can just use the vector (d, k_1, ..., k_m) and the constant is implicit.
    # For HNP, we usually embed the constant as an extra column.
    # Let's do the standard construction with m+2 columns:
    B = matrix(ZZ, m+2, m+2)
    # Row 0: modulus for d
    B[0, 0] = n
    # Rows for each signature: (r_i, 0,..., s_i at i+1, ..., -z_i, 0) 
    for i in range(m):
        r, s, z, _ = sigs[i]
        B[i+1, 0] = r
        B[i+1, i+1] = s   # column i+1 is for k_i
        B[i+1, m+1] = -z   # last column for constant 1
    # Last row: (0, ..., 0, 1) to fix constant to 1
    B[m+1, m+1] = 1
    
    # Scale the k_i columns to balance the lattice (since k_i are small)
    # We scale column i+1 by SCALE (the upper bound) to make the lattice more balanced.
    for i in range(m):
        for row in range(m+2):
            B[row, i+1] *= SCALE
    
    # Also scale the constant column? Not necessary.
    
    sys.stdout.write("Running BKZ-20...\n")
    sys.stdout.flush()
    # BKZ reduction
    B = B.BKZ(block_size=20, algorithm='FPLLL')
    
    sys.stdout.write("Checking for short vector with last coordinate 1...\n")
    sys.stdout.flush()
    # After reduction, look for a row where last column is 1 or -1
    for i in range(m+2):
        row = B[i]
        if abs(row[m+1]) != 1:
            continue
        # Candidate d = row[0] / SCALE? Actually we scaled, so we need to recover d.
        # Since we scaled columns 1..m by SCALE, the vector (d, k_1*SCALE, ..., k_m*SCALE, 1) is in the lattice.
        # So d = row[0] (since we didn't scale column 0)
        d_candidate = row[0] % n
        if d_candidate == 0:
            continue
        # Verify with first signature's public key
        if verify_key(d_candidate, sigs[0][3]):
            return d_candidate
        # Try negative
        if verify_key(n - d_candidate, sigs[0][3]):
            return n - d_candidate
    return None

def main():
    sys.stdout.write("main() started.\n")
    sys.stdout.flush()
    sigs = parse_sigs('my_signatures.txt')
    if len(sigs) < 2:
        sys.stdout.write("Need at least 2 signatures.\n")
        sys.stdout.flush()
        sys.exit(1)
    sys.stdout.write(f"Loaded {len(sigs)} signatures with {bits}-bit MSB zero bias.\n")
    sys.stdout.flush()
    key = attack(sigs)
    if key:
        sys.stdout.write(f"✅ Private key found: {hex(key)}\n")
        sys.stdout.flush()
        if verify_key(key, sigs[0][3]):
            sys.stdout.write("Verification passed.\n")
        else:
            sys.stdout.write("Verification failed.\n")
        sys.stdout.flush()
    else:
        sys.stdout.write("❌ No key recovered.\n")
        sys.stdout.flush()

if __name__ == '__main__':
    main()
