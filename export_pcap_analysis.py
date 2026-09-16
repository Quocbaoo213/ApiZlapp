#!/usr/bin/env python3
import sys, os, glob, struct, json, datetime
sys.path.insert(0, '/root/zalo')

import zalo_re
from protocol import InnerPacketHeader
from scapy.all import rdpcap, TCP, IP

OUT_FILE = '/sdcard/Download/pcap_analysis.txt'

def log(msg, f=None):
    print(msg)
    if f:
        f.write(str(msg) + '\n')

def main():
    # Tìm pcap mới nhất
    pcaps = sorted(glob.glob('/sdcard/Download/PCAPdroid/*.pcap'),
                   key=os.path.getmtime, reverse=True)
    if not pcaps:
        print("Không có pcap")
        sys.exit(1)

    latest = pcaps[0]

    with open(OUT_FILE, 'w', encoding='utf-8') as f:
        log("=" * 80, f)
        log("PCAP ANALYSIS", f)
        log("=" * 80, f)
        log(f"File: {latest}", f)
        log(f"Size: {os.path.getsize(latest)} bytes", f)
        mtime = os.path.getmtime(latest)
        log(f"Mtime: {mtime} ({datetime.datetime.fromtimestamp(mtime)})", f)
        log("", f)

        # Đọc flows có TCP reassembly từ zalo_re
        print(f"[*] Đang nạp và reassemble PCAP: {latest} ...")
        flows = zalo_re.parse_network_capture(latest)
        log(f"Total TCP Reassembled Flows: {len(flows)}", f)

        # Lấy timestamps từ packets sơ bộ
        try:
            packets = rdpcap(latest)
            log(f"Total packets: {len(packets)}", f)
            if len(packets) > 0:
                log(f"Start: {datetime.datetime.fromtimestamp(float(packets[0].time))}", f)
                log(f"End:   {datetime.datetime.fromtimestamp(float(packets[-1].time))}", f)
        except Exception:
            pass
        log("", f)

        log("=" * 80, f)
        log(f"TOTAL FLOWS: {len(flows)}", f)
        log("=" * 80, f)

        # List top 20 flows by size
        flow_stats = []
        for key, buf in flows:
            flow_stats.append((key, len(buf), buf))

        flow_stats.sort(key=lambda x: x[1], reverse=True)

        log("\nTOP 20 FLOWS BY SIZE:", f)
        for i, (key, total, buf) in enumerate(flow_stats[:20]):
            src, sport, dst, dport = key
            log(f"  #{i+1:3d} {src}:{sport} -> {dst}:{dport}  {total:,} bytes", f)
        log("", f)

        # Load candidate DKs from zaloprefs and session
        candidate_dks = []
        user_uid = 463450795
        ksid = ""
        try:
            pref = zalo_re.parse_zaloprefs('/root/zalo/zaloprefs')
            for u, d in pref.get('users', {}).items():
                if d.get('dk'):
                    candidate_dks.append((f'zaloprefs_{u}', d['dk']))
                    user_uid = int(u)
                    ksid = d.get('keySetId', '')
        except Exception as e:
            pass

        try:
            sess = json.load(open('/root/zalo/fresh_session.json'))
            dk_fresh = bytes.fromhex(sess['dk_hex'])
            candidate_dks.append(('fresh_session', dk_fresh))
        except Exception:
            pass

        log("=" * 80, f)
        log(f"SESSION: uid={user_uid}, ksid={ksid}, candidate_dks={len(candidate_dks)}", f)
        for name, k in candidate_dks:
            log(f"  DK [{name}]: {k.hex()}", f)
        log("=" * 80, f)
        log("", f)

        # Decrypt tất cả frames
        all_frames = []
        for key, buf in flows:
            src, sport, dst, dport = key
            if not (dst.startswith('49.213.95.') or src.startswith('49.213.95.') or dport in (443, 8080, 8081) or sport in (443, 8080, 8081)):
                continue

            cleaned = zalo_re.strip_http_handshake(buf)
            for frame_idx, (ftype, fbody) in enumerate(zalo_re.parse_socket_frames(cleaned)):
                if ftype in (3, 4):
                    decrypted = False
                    for dk_name, dk in candidate_dks:
                        try:
                            pt = zalo_re.gcm_decrypt_body(dk, fbody)
                            hdr = InnerPacketHeader.unpack(pt)
                            params = pt[18:]
                            all_frames.append({
                                'flow': f"{src}:{sport}->{dst}:{dport}",
                                'frame_idx': frame_idx,
                                'ftype': ftype,
                                'cmd': hdr.cmd,
                                'sub': hdr.sub,
                                'seq': hdr.seq,
                                'uid': hdr.uid,
                                'ty': hdr.ty,
                                'bb': hdr.bb,
                                'params_len': len(params),
                                'params_hex': params.hex(),
                                'raw_frame_hex': struct.pack('<IB', len(fbody) + 5, ftype).hex() + fbody.hex(),
                            })
                            decrypted = True
                            break
                        except Exception:
                            pass

        log("=" * 80, f)
        log(f"TOTAL DECRYPTED FRAMES: {len(all_frames)}", f)
        log("=" * 80, f)
        log("", f)

        # CMD distinct
        cmds = {}
        for fr in all_frames:
            key = (fr['cmd'], fr['sub'])
            cmds.setdefault(key, 0)
            cmds[key] += 1

        log("CMD DISTRIBUTION:", f)
        for (cmd, sub), count in sorted(cmds.items()):
            log(f"  CMD={cmd:5d} SUB={sub:3d}: {count} frames", f)
        log("", f)

        # Chi tiết từng frame
        log("=" * 80, f)
        log("FRAME DETAILS", f)
        log("=" * 80, f)

        for i, fr in enumerate(all_frames):
            log(f"\n[Frame #{i+1}]", f)
            log(f"  Flow:       {fr['flow']}", f)
            log(f"  Type:       {fr['ftype']}  (3=control, 4=data)", f)
            log(f"  CMD:        {fr['cmd']}", f)
            log(f"  SUB:        {fr['sub']}", f)
            log(f"  seq:        {fr['seq']}", f)
            log(f"  uid:        {fr['uid']}", f)
            log(f"  ty:         {fr['ty']}   bb: {fr['bb']}", f)
            log(f"  params_len: {fr['params_len']}", f)
            log(f"  params_hex: {fr['params_hex'][:200]}...", f)
            log(f"  raw_hex:    {fr['raw_frame_hex'][:120]}...", f)

        # CMD lạ (không thuộc known list)
        known = {101, 201, 1865, 1867, 113, 207, 1703, 1708, 1971, 1, 2, 133,
                 384, 390, 525, 620, 700, 151, 1411, 1418, 1419, 1484, 1530,
                 1582, 1588, 1764, 1785, 1814, 1915, 1963, 2085, 2190, 2061,
                 2070, 1430, 3400, 10100, 10301, 1701, 1705, 1853, 1267, 1793,
                 2109, 1973, 600, 208, 224, 121, 2060, 210, 396, 376, 272, 1399,
                 1400, 1407, 1413, 1630, 176, 177, 2204, 271, 3875, 3878, 152,
                 153, 156, 2204, 1418, 1703, 202, 203, 205, 206, 242, 1757, 1786,
                 1787, 1860, 225, 212}

        log("\n" + "=" * 80, f)
        log("UNKNOWN CMDs (không thuộc known list):", f)
        log("=" * 80, f)

        unknown_count = 0
        for fr in all_frames:
            if fr['cmd'] not in known:
                unknown_count += 1
                log(f"\n[UNKNOWN CMD #{unknown_count}]", f)
                log(f"  Flow: {fr['flow']}", f)
                log(f"  CMD={fr['cmd']} SUB={fr['sub']} uid={fr['uid']} ty={fr['ty']}", f)
                log(f"  params_len: {fr['params_len']}", f)
                log(f"  params_hex: {fr['params_hex']}", f)

        if unknown_count == 0:
            log("  (Không có CMD nào ngoài danh sách known)", f)

        log("\n" + "=" * 80, f)
        log("END OF REPORT", f)
        log("=" * 80, f)

    print(f"\n[✔] Đã lưu báo cáo vào: {OUT_FILE}")
    print(f"    Size: {os.path.getsize(OUT_FILE):,} bytes")

if __name__ == '__main__':
    main()
