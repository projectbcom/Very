import sys

def convert_line(line):
    parts = line.strip().split(';')
    if len(parts) < 6:
        return None
    r = int(parts[0], 16)
    s = int(parts[1], 16)
    z = int(parts[3], 16)
    # Known bias: 5 MSB bits are zero
    leak = 0
    bits = 5
    return f"{r} {s} {z} {leak} {bits}"

if __name__ == "__main__":
    with open("my_signatures.txt", "r") as fin, open("input.txt", "w") as fout:
        for line in fin:
            res = convert_line(line)
            if res:
                fout.write(res + "\n")
