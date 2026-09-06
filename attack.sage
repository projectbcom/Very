#!/usr/bin/env sage

from sage.all import *
import sys

# secp256r1 (NIST P-256) parameters
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
E = EllipticCurve(GF(p), [a, b])
G = E((0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
       0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5))
order = n

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
            sigs.append((r, s, z))
    return sigs

def attack(sigs, bits=5):
    m = len(sigs)
    if m < 2:
        return None
    # Build lattice for HNP with known MSB bits (zero)
    # We use the standard construction:
    # matrix = [[N, 0, ..., 0],
    #           [r_i, s_i, ..., -z_i?]]
    # Actually we need to incorporate the scaling for the bias.
    # For MSB bits zero, the lattice is:
    # B = [[N, 0, 0, ...],
    #      [r_0, s_0, 0, ...],
    #      [r_1, 0, s_1, ...],
    #      ...
    #      [z_0, 0, 0, ...]] etc.
    # More precisely, we want to find d such that d*r_i + s_i*k_i ≡ z_i (mod N)
    # with 0 <= k_i < 2^(256-bits) (because MSB bits are zero)
    # We can transform to: d*r_i + s_i*k_i' ≡ z_i (mod N) where k_i' = k_i (since no known offset)
    # So we build the lattice:
    # Rows: for i in 0..m-1: [r_i, s_i, 0, ..., -z_i, ...]
    # Last row: [N, 0, ..., 0]
    # Then reduce and look for short vectors with first coordinate close to d.
    # But simpler: use the standard approach from the literature.
    # We'll construct the matrix with columns: d, k_0, k_1, ..., k_{m-1}, 1 (or similar)
    # Actually, we need to find a vector (d, k_0, ..., k_{m-1}) such that:
    # r_i*d + s_i*k_i - z_i ≡ 0 (mod N) for each i.
    # We set up the lattice:
    # For i = 0..m-1: row: (r_i, s_i, 0, ..., -z_i, ...) with a column for the constant?
    # Let's use the construction from the original paper:
    # B = [[N, 0, 0, ..., 0],
    #      [r_0, 1, 0, ..., 0],
    #      [r_1, 0, 1, ..., 0],
    #      ...
    #      [r_{m-1}, 0, 0, ..., 1]]
    # Then the vector (d, k_0, ..., k_{m-1}) is a short vector in the lattice.
    # We also need to incorporate the z_i values; they are used to shift.
    # The correct construction for HNP is:
    # B = [[N, 0, 0, ..., 0],
    #      [r_0, 1, 0, ..., 0],
    #      [r_1, 0, 1, ..., 0],
    #      ...
    #      [r_{m-1}, 0, 0, ..., 1]]
    # Then we look for a vector v = (d, k_0, ..., k_{m-1}) such that:
    # v[0] = d, and for each i, v[0]*r_i + v[i+1] ≡ z_i (mod N)
    # So we can compute candidate d from the reduced basis.
    # However, we must also incorporate the scaling factor for the biased nonces.
    # For MSB zero with bits bits, the nonce is small: 0 <= k_i < 2^(256-bits)
    # We can scale the last m columns by a factor to balance the lattice.
    # We'll use a scaling factor of N for the first column and 1 for others.
    # Also we need to add the -z_i to the equations, but we can incorporate them by shifting.
    # Simpler approach: use the standard method from the ecdsa_break library.
    # Since we have Sage, we can use its LLL/BKZ functions directly.
    # We'll implement the construction from the "Breaking ECDSA with LLL" paper.
    
    # We'll build the lattice as follows:
    # Matrix of size (m+1) x (m+1)
    # For i in range(m):
    #   B[i, 0] = r_i
    #   B[i, i+1] = s_i
    #   B[i, m] = -z_i
    # B[m, 0] = N
    # Then we reduce with BKZ.
    # Then we look for a row where the last column is small and the first column gives d.
    # We'll use Sage's matrix.
    B = matrix(ZZ, m+1, m+1)
    for i in range(m):
        r, s, z = sigs[i]
        B[i, 0] = r
        B[i, i+1] = s
        B[i, m] = -z
    B[m, 0] = n
    
    # Reduce with BKZ-20
    Bkz = BKZ.BKZ(block_size=20)
    B_reduced = Bkz(B)  # In Sage, we can call B.BKZ(block_size=20) but syntax may vary
    # Actually Sage's matrix has a .BKZ() method if we import the right module.
    # Alternatively, we can use LLL first.
    B = B.LLL()
    # Then try BKZ if LLL fails.
    # We'll just use LLL for speed.
    # After reduction, check each row for candidate.
    for i in range(m+1):
        row = B[i]
        d_candidate = row[0] % n
        if d_candidate != 0 and d_candidate < n:
            # Verify with first signature
            r0, s0, z0 = sigs[0]
            # Check if r0*d_candidate - z0 is divisible by s0? Actually we need to check the equation.
            # We can compute k0 = (z0 - r0*d_candidate) * inverse_mod(s0, n) % n
            # Then check if 0 <= k0 < 2^(256-bits)
            k0 = ((z0 - r0*d_candidate) * inverse_mod(s0, n)) % n
            if k0 < 2**(256-bits):
                return d_candidate
    return None

def main():
    sigs = parse_sigs('my_signatures.txt')
    if len(sigs) < 2:
        print("Need at least 2 signatures.")
        sys.exit(1)
    print(f"Loaded {len(sigs)} signatures with 5-bit MSB zero bias.")
    key = attack(sigs, bits=5)
    if key:
        print(f"✅ Private key found: {hex(key)}")
    else:
        print("❌ No key recovered.")

if __name__ == '__main__':
    main()
