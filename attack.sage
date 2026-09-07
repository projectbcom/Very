#!/usr/bin/env sage

import sys
sys.stdout.write("=== attack.sage started ===\n")
sys.stdout.flush()

# secp256r1 order
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
bits = 5
M = 2**(256 - bits)  # bound for nonces (since MSB bits are zero)

def parse_sigs(filepath):
    sys.stdout.write("Parsing signatures...\n")
    sys.stdout.flush()
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
    # Recover public key from d and compare hex
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
    sys.stdout.write(f"Building HNP lattice with m={m}, bound={M}...\n")
    sys.stdout.flush()

    # We use the standard construction:
    # Matrix of size (m+1) x (m+1)
    # Row i (0 <= i < m):
    #   [r_i, s_i, 0, ..., 0, -z_i]  (with s_i at column i+1)
    # Last row:
    #   [n, 0, ..., 0, 0]
    # Then we scale the k_i columns (1..m) by a factor to balance the lattice.
    # The vector (d, k_1, ..., k_m, 1) is in the lattice, and should be short.
    # Since we know k_i < M, we scale columns 1..m by M.
    # Also we need to ensure the constant 1 is present; we add a row (0,...,0,1).
    # But we can also embed the constant by adding a column.
    # Let's use the simpler construction (without constant column) and just check for short vectors.
    # We'll construct the lattice B as:
    # B = [[n, 0, ..., 0],
    #      [r_0, s_0, 0, ..., -z_0],
    #      [r_1, 0, s_1, ..., -z_1],
    #      ...
    #      [r_{m-1}, 0, ..., s_{m-1}, -z_{m-1}]]
    # The vector (d, k_1, ..., k_m) satisfies:
    #   d*r_i + s_i*k_i ≡ z_i (mod n)  =>  d*r_i + s_i*k_i - z_i = q_i * n.
    # So (d, k_1, ..., k_m) is in the lattice.
    # We also need to include a column for the "constant 1" to account for the -z_i, but we can just shift rows.
    # However, the standard HNP lattice uses:
    # B = [[n, 0, ..., 0],
    #      [r_0, 1, 0, ..., 0],
    #      [r_1, 0, 1, ..., 0],
    #      ...
    #      [r_{m-1}, 0, ..., 1]]
    # and then the vector (d, k_0, ..., k_{m-1}) is short with the relation k_i = (z_i - d*r_i) * s_i^{-1} mod n.
    # But this requires knowing z_i and s_i; the short vector will contain d in the first coordinate.
    # Actually, the correct lattice for the Hidden Number Problem is:
    # B = [[n, 0, ..., 0],
    #      [r_0, 1, 0, ..., 0],
    #      [r_1, 0, 1, ..., 0],
    #      ...
    #      [r_{m-1}, 0, ..., 1]]
    # Then a short vector v = (d, k_0, ..., k_{m-1}) satisfies:
    #   r_i * d ≡ z_i - s_i * k_i (mod n)
    # which is exactly the equation we have.
    # We need to construct this lattice and then reduce it.
    # The size of the lattice is (m+1) x (m+1).
    # We'll use the above construction with scaling of the k_i columns by M to balance.
    # So we have:
    # B[0,0] = n
    # for i in 1..m:
    #   B[i,0] = r_{i-1}
    #   B[i,i] = 1   (but we scale by M)
    # Then after reduction, we look for a vector where the first coordinate is d and the rest are small (|k_i| < M).
    # We'll scale the k_i columns by M to make the lattice more balanced.
    # That means for i in 1..m, B[i,i] = M.
    # After reduction, we get a vector (d, k_0*M, ..., k_{m-1}*M) so we recover k_i = row[i] / M.
    # We'll also need to include the -z_i terms? Actually we don't need to include z_i in the lattice; the relation is handled by the reduction.
    # The vector we want is (d, k_0, ..., k_{m-1}) where d*r_i ≡ z_i - s_i*k_i (mod n).
    # This is exactly the HNP.
    # So we build:
    B = matrix(ZZ, m+1, m+1)
    B[0,0] = n
    for i in range(m):
        r, s, z, _ = sigs[i]
        B[i+1, 0] = r
        # We'll scale the k_i column by M
        B[i+1, i+1] = M
        # We also need to incorporate the known z_i? Actually, we don't include z_i in the lattice; the relation is that the vector (d, k_0, ..., k_{m-1}) satisfies the congruence, and the lattice is just the set of vectors (d, k_0, ..., k_{m-1}) with d arbitrary and k_i integers.
        # The condition d*r_i - s_i*k_i ≡ 0 (mod n) would be the case if z_i = 0. But z_i is not zero.
        # We need to shift the target so that the vector (d, k_i) satisfies d*r_i + s_i*k_i ≡ z_i (mod n).
        # This can be handled by including the -z_i as an extra column (as we did before) or by using a different approach.
        # In the HNP with known MSB, the standard approach is to set the lattice rows as:
        # Row 0: (n, 0, ..., 0)
        # Row i+1: (r_i, 0, ..., s_i, ..., -z_i)
        # We'll use that construction, but scale the k_i columns by M.
        # So we rebuild with m+2 columns (including the constant column for -z_i).
    # Let's use the following construction with m+1 columns (no constant column) and handle z_i by shifting the row.
    # Actually, we can just use the construction from the paper:
    # For each i, we have the equation:
    #   d * r_i + s_i * k_i - z_i ≡ 0 (mod n)
    # We can write this as:
    #   d * r_i + s_i * k_i - z_i + t_i * n = 0
    # So the lattice contains the vector (d, k_0, ..., k_{m-1}, t_0, ..., t_{m-1}, 1) but that's overkill.
    # The simplest correct construction for HNP with known MSB is:
    # B = [[n, 0, ..., 0],
    #      [r_0, s_0, 0, ..., 0],
    #      [r_1, 0, s_1, ..., 0],
    #      ...
    #      [r_{m-1}, 0, ..., s_{m-1}]]
    # and we look for a vector (d, k_0, ..., k_{m-1}) such that for each i, the row dot product is a multiple of n.
    # But we also need to incorporate the -z_i. We can do that by subtracting z_i * e_0 from the vector, but that's not straightforward.
    # The standard trick is to add a row for the constant 1:
    # We add a final column for the constant 1, and set the last row to (0,...,0,1).
    # Then the lattice is:
    # B = [[n, 0, ..., 0, 0],
    #      [r_0, s_0, 0, ..., 0, -z_0],
    #      [r_1, 0, s_1, ..., 0, -z_1],
    #      ...
    #      [r_{m-1}, 0, ..., s_{m-1}, -z_{m-1}],
    #      [0, 0, ..., 0, 1]]
    # Then a vector (d, k_0, ..., k_{m-1}, 1) is in the lattice if it satisfies the congruences.
    # So we'll build this lattice with m+2 columns.
    # Columns: 0: d, 1..m: k_i, m+1: constant 1.
    # We'll scale columns 1..m by M.
    # So:
    B = matrix(ZZ, m+2, m+2)
    B[0,0] = n
    for i in range(m):
        r, s, z, _ = sigs[i]
        B[i+1, 0] = r
        B[i+1, i+1] = s   # will scale later
        B[i+1, m+1] = -z
    B[m+1, m+1] = 1
    # Scale k_i columns
    for i in range(m):
        for row in range(m+2):
            B[row, i+1] *= M

    sys.stdout.write("Running LLL (or BKZ)...\n")
    sys.stdout.flush()
    # Try BKZ-20 first, if fails fallback to LLL
    try:
        B = B.BKZ(block_size=20)
    except:
        B = B.LLL()

    # After reduction, look for a row where the last column is ±1
    sys.stdout.write("Checking rows...\n")
    sys.stdout.flush()
    for i in range(m+2):
        row = B[i]
        if abs(row[m+1]) != 1:
            continue
        d_candidate = row[0] % n
        if d_candidate == 0:
            continue
        # Verify with the first signature's public key
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
