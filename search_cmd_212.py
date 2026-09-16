import os
import re
import multiprocessing as mp

BASE_DIR = "/root/zalo/base_decoded"
pattern = re.compile(r"const(?:/16)?\s+([vp]\d+),\s*0xd4\b")

def scan(path):
    res = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if "0xd4" in content:
                for line in content.splitlines():
                    if pattern.search(line):
                        res.append((os.path.relpath(path, BASE_DIR), line.strip()))
    except:
        pass
    return res

def main():
    files = []
    for root, dirs, fns in os.walk(BASE_DIR):
        for fn in fns:
            if fn.endswith(".smali"):
                files.append(os.path.join(root, fn))

    with mp.Pool(8) as pool:
        results = pool.map(scan, files, chunksize=500)

    flat = [item for sub in results for item in sub]
    print(f"Found {len(flat)} occurrences of 0xd4 (212):")
    for path, line in flat:
        print(f"  {path}: {line}")

if __name__ == "__main__":
    main()
