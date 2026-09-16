import os
import json

def generate_report():
    test_run_log = ''
    if os.path.isfile('/tmp/final_run.log'):
        with open('/tmp/final_run.log', 'r', encoding='utf-8') as f:
            test_run_log = f.read()

    debug_log = ''
    if os.path.isfile('/root/zalo/debug.log'):
        with open('/root/zalo/debug.log', 'r', encoding='utf-8') as f:
            debug_log = f.read()

    zalo_send_code = ''
    if os.path.isfile('/root/zalo/zalo_send.py'):
        with open('/root/zalo/zalo_send.py', 'r', encoding='utf-8') as f:
            zalo_send_code = f.read()

    report_md = ''
    if os.path.isfile('/root/zalo/report.md'):
        with open('/root/zalo/report.md', 'r', encoding='utf-8') as f:
            report_md = f.read()

    init_seq_summary = ''
    if os.path.isfile('/root/zalo/init_sequence.json'):
        with open('/root/zalo/init_sequence.json', 'r', encoding='utf-8') as f:
            init_data = json.load(f)
        frames = init_data.get('frames', [])
        init_seq_summary = f"Total C2S frames: {len(frames)}\n"
        for fr in frames:
            init_seq_summary += f"  Idx: {fr['idx']:2d} | Seq: {fr['seq']:4d} | CMD: {fr['cmd']:4d} | SUB: {fr['sub']:2d} | Ty: {fr['ty']} | ck: {fr.get('ck_hex','0')} | BodyLen: {len(fr['raw_body_hex'])//2:3d}B\n"

    frame0_hex = ''
    if os.path.isfile('/root/zalo/frame0.bin'):
        frame0_hex = open('/root/zalo/frame0.bin', 'rb').read().hex()

    zalo_listen_code = ''
    if os.path.isfile('/root/zalo/zalo_listen.py'):
        with open('/root/zalo/zalo_listen.py', 'r', encoding='utf-8') as f:
            zalo_listen_code = f.read()

    content = f"""================================================================================
BÁO CÁO TOÀN DIỆN: REVERSE ENGINEERING ZALO TCP BINARY SOCKET (CAPTURE MỚI)
================================================================================
Thời gian: 2026-09-13
Mục đích: Cung cấp đầy đủ toàn bộ mã nguồn, cấu hình, trace log gửi/nhận thành công
và tài liệu kỹ thuật để AI/Kỹ sư tiếp tục phân tích, hoàn thiện và tích hợp.

================================================================================
PHẦN 1: BÁO CÁO KỸ THUẬT & ĐỐI CHIẾU (REPORT.MD)
================================================================================
{report_md}

================================================================================
PHẦN 2: THÔNG TIN TÀI KHOẢN & KHÓA MÃ HÓA (TỪ ZALOPREFS)
================================================================================
- Sender UID: 463450795
- Target Group ID: 686355764 (Hex: 0x28e8f534)
- Target Private User: 692675055
- KeySet ID: SESKpve-lDrcssv0
- Data Key (DK - AES-256-GCM): OWFLU/v810vuguZqiCckFYT0UwOPHDJcAAEsxPZWp/Y= (32 bytes)
- CryptKey (AES-128-CBC cho 1-1 Chat): NrfD2tg2jEDfzjt63crRqw== (16 bytes)
- Frame 0 Handshake Binary: {len(frame0_hex)//2} bytes
- Frame 0 Hex: {frame0_hex}

================================================================================
PHẦN 3: KẾT QUẢ CHẠY THỰC TẾ (TERMINAL OUTPUT THÀNH CÔNG)
================================================================================
{test_run_log}

================================================================================
PHẦN 4: TOÀN BỘ NHẬT KÝ DEBUG TRACE LOG (DEBUG.LOG)
================================================================================
{debug_log}

================================================================================
PHẦN 5: CHI TIẾT CÁC FRAME TRÍCH XUẤT TỪ PCAP MỚI
================================================================================
{init_seq_summary}

================================================================================
PHẦN 6: TOÀN BỘ MÃ NGUỒN ZALO_SEND.PY (GỬI TIN NHẮN)
================================================================================
```python
{zalo_send_code}
```

================================================================================
PHẦN 7: TOÀN BỘ MÃ NGUỒN ZALO_LISTEN.PY (LẮNG NGHE REALTIME & GIẢI MÃ TOÀN DIỆN)
================================================================================
```python
{zalo_listen_code}
```
"""
    os.makedirs('/sdcard/Download', exist_ok=True)
    with open('/sdcard/Download/c.txt', 'w', encoding='utf-8') as f:
        f.write(content)

    with open('/root/c.txt', 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[✔] Đã xuất báo cáo thành công ra /sdcard/Download/c.txt ({len(content):,} bytes)")

if __name__ == '__main__':
    generate_report()
