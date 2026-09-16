import os
import re
import multiprocessing as mp
from collections import defaultdict

BASE_DIR = "/root/zalo/base_decoded"

cmd_pattern = re.compile(r'\.field.*?((?:CMD|SUB|COMMAND|PTCL)_[A-Z0-9_]+).*?=\\s*(0x[0-9a-fA-F]+|-?\d+)')
url_pattern = re.compile(r'\"(https?://[^\"\s]+zalo[^\"\s]*|/api/[a-zA-Z0-9_/.-]+|group/[a-zA-Z0-9_/.-]+|message/[a-zA-Z0-9_/.-]+)\"')
json_key_pattern = re.compile(r'\"([a-zA-Z0-9_]{3,30})\"')

def scan_file(file_path):
    cmds = []
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for m in cmd_pattern.finditer(content):
                name, val = m.groups()
                try:
                    val_int = int(val, 16) if val.startswith("0x") else int(val)
                    cmds.append((name, val_int, file_path))
                except Exception:
                    pass
            for m in url_pattern.finditer(content):
                urls.append((m.group(1), file_path))
    except Exception:
        pass
    return cmds, urls

def get_all_files():
    files = []
    for root, dirs, filenames in os.walk(BASE_DIR):
        for fn in filenames:
            if fn.endswith(".smali"):
                files.append(os.path.join(root, fn))
    return files

def main():
    print("Collecting files...")
    all_files = get_all_files()
    print(f"Total smali files: {len(all_files)}")
    
    with mp.Pool(processes=8) as pool:
        results = pool.map(scan_file, all_files, chunksize=500)
        
    all_cmds = defaultdict(set)
    all_urls = defaultdict(set)
    
    for cmds, urls in results:
        for name, val, path in cmds:
            rel_path = os.path.relpath(path, BASE_DIR)
            all_cmds[(name, val)].add(rel_path)
        for url, path in urls:
            rel_path = os.path.relpath(path, BASE_DIR)
            all_urls[url].add(rel_path)
            
    print(f"Found {len(all_cmds)} unique socket CMD constants")
    print(f"Found {len(all_urls)} unique URLs/endpoints")
    
    with open("/root/zalo/discovered_socket_cmds.txt", "w", encoding="utf-8") as f:
        for (name, val), paths in sorted(all_cmds.items(), key=lambda x: (x[0][1], x[0][0])):
            f.write(f"[{val:5d} | 0x{val & 0xFFFF:04X}] {name:<40} (in {len(paths)} files: {list(paths)[0]})\n")
            
    with open("/root/zalo/discovered_http_apis.txt", "w", encoding="utf-8") as f:
        for url, paths in sorted(all_urls.items()):
            f.write(f"{url:<80} ({list(paths)[0]})\n")
            
    print("Done writing to discovered_socket_cmds.txt and discovered_http_apis.txt")

if __name__ == '__main__':
    main()
