#!/usr/bin/env sage

import sys
sys.stdout.write("=== attack.sage started ===\n")
sys.stdout.flush()

try:
    from sage.all import *
except Exception as e:
    sys.stderr.write(f"Failed to import sage: {e}\n")
    sys.exit(1)

try:
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    bits = 5
    SCALE = 2**(256 - bits)

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
        sys.stdout.write(f"Building lattice with {m} signatures...\n")
        sys.stdout.flush()
        B = matrix(ZZ, m+2, m+2)
        B[0, 0] = n
        for i in range(m):
            r, s, z, _ = sigs[i]
            B[i+1, 0] = r
            B[i+1, i+1] = s
            B[i+1, m+1] = -z
        B[m+1, m+1] = 1
        for i in range(m):
            for row in range(m+2):
                B[row, i+1] *= SCALE

        sys.stdout.write("Running BKZ-20...\n")
        sys.stdout.flush()
        try:
            # Try BKZ without algorithm parameter (uses default)
            B = B.BKZ(block_size=20)
        except Exception as e:
            sys.stdout.write(f"BKZ failed: {e}, falling back to LLL...\n")
            sys.stdout.flush()
            B = B.LLL()

        sys.stdout.write("Checking rows...\n")
        sys.stdout.flush()
        for i in range(m+2):
            row = B[i]
            if abs(row[m+1]) != 1:
                continue
            d_candidate = row[0] % n
            if d_candidate == 0:
                continue
            if verify_key(d_candidate, sigs[0][3]):
                return d_candidate
            if verify_key(n - d_candidate, sigs[0][3]):
                return n - d_candidate
        return None

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

except Exception as e:
    sys.stderr.write(f"ERROR: {e}\n")
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
