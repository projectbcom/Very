import sys
import gmpy2
from fpylll import BKZ, IntegerMatrix, LLL
from fpylll.fplll.gso import MatGSO
from ecdsa import NIST256p
from ecdsa.numbertheory import inverse_mod

# secp256r1 order
N = NIST256p.order

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

def build_lattice(sigs, bits=5):
    # For 5-bit MSB zero bias: nonce = k_unknown + (known_bits << (256-bits))
    # Here known_bits = 0, so nonce is in [0, 2^(256-bits)-1]
    m = len(sigs)
    # We need m+1 dimension lattice
    A = IntegerMatrix(m+1, m+1)
    for i in range(m):
        r, s, z = sigs[i]
        A[i, 0] = r
        A[i, i+1] = s
        A[i, i+1] = (s * pow(2, bits, N)) % N   # scale factor
        # Actually, we follow the standard HNP construction:
        # We want to find d such that d*r_i + s_i * k_i ≡ z_i (mod N)
        # With k_i = k_i' + 0 (since MSB bits are zero), we have:
        # d*r_i + s_i * k_i' ≡ z_i (mod N)
        # Rewrite as d*r_i + s_i * k_i' - z_i = q_i * N
        # So we build lattice rows: [r_i, s_i, -z_i, ...]
        A[i, 0] = r
        A[i, i+1] = s
        A[i, m] = -z
        # The last row is modulus
    # Last row: [N, 0, ..., 0]
    A[m, 0] = N
    return A

def recover_key(sigs, bits=5):
    m = len(sigs)
    if m < 2:
        return None
    A = build_lattice(sigs, bits)
    # Reduce with BKZ-20 (fast, good enough)
    BKZ.reduction(A, BKZ.Param(block_size=20, strategies=BKZ.DEFAULT_STRATEGY))
    # Check each row for a small vector that gives the private key
    for i in range(m+1):
        row = [A[i, j] for j in range(m+1)]
        # The private key d is the value at column 0 divided by r_0 etc.
        # We can extract from the first row: row[0] should be d * r_0 mod N?
        # Better: use the approach: find vector v = (d, k_1, ..., k_m)
        # The lattice is designed so that the shortest vector contains d.
        # We'll try to recover d from the first two rows.
        # Simple check: take row[0] and see if it corresponds to a valid private key.
        d_candidate = row[0] % N
        if d_candidate > 0 and d_candidate < N:
            # Verify with first signature
            r0, s0, z0 = sigs[0]
            if (pow(d_candidate, -1, N) * (r0 * d_candidate + s0 * 0) % N) == z0: # simplified
                return d_candidate
    return None

def main():
    sigs = parse_sigs('my_signatures.txt')
    if len(sigs) < 2:
        print("Need at least 2 signatures.")
        sys.exit(1)
    print(f"Loaded {len(sigs)} signatures with 5-bit MSB zero bias.")
    key = recover_key(sigs, bits=5)
    if key:
        print(f"✅ Private key found: {hex(key)}")
    else:
        print("❌ No key recovered.")

if __name__ == '__main__':
    main()
