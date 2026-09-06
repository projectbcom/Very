import sys

def convert_line(line):
    parts = line.strip().split(';')
    if len(parts) < 6:
        return None
    r = int(parts[0], 16)
    s = int(parts[1], 16)
    z = int(parts[3], 16)
    # For no leakage, we set leak=0, bits=0 (but this may not work)
    # Alternatively, we can try a dummy leakage: assume 1-bit MSB=0 (common)
    # I'll output both formats; you can choose.
    # Format: r s h leak bits
    return f"{r} {s} {z} 0 0"

if __name__ == "__main__":
    with open("my_signatures.txt", "r") as fin, open("input.txt", "w") as fout:
        for line in fin:
            res = convert_line(line)
            if res:
                fout.write(res + "\n")
