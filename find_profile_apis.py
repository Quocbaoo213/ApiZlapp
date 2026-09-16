import os
import re
import multiprocessing as mp

BASE_DIR = "/root/zalo/base_decoded"
patterns = [
    re.compile(b"searchProfile"),
    re.compile(b"ext-profile"),
    re.compile(b"/api/v1/ext-profile"),
    re.compile(b"profile-userplatform"),
    re.compile(b"search_profile"),
    re.compile(b"/api/contact/searchProfile"),
    re.compile(b"profile/info"),
    re.compile(b"user/profile"),
]

def scan_file(fpath):
    res = []
    try:
        with open(fpath, "rb") as f:
            data = f.read()
            for p in patterns:
                if p.search(data):
                    res.append((p.pattern.decode(), os.path.relpath(fpath, BASE_DIR)))
    except Exception:
        pass
    return res

def main():
    files = []
    for root, dirs, fns in os.walk(BASE_DIR):
        for fn in fns:
            if fn.endswith(".smali"):
                files.append(os.path.join(root, fn))

    print(f"Total files: {len(files)}")
    with mp.Pool(processes=8) as pool:
        results = pool.map(scan_file, files, chunksize=500)

    flat = [item for sub in results for item in sub]
    print(f"Found {len(flat)} matches:")
    for pat, path in sorted(set(flat)):
        print(f"[{pat}] {path}")

if __name__ == "__main__":
    main()
