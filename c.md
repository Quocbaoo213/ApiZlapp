═══════════════════════════════════════════════════════════════════════
PROMPT CHO AI: LOGIN LẠI ZALO QUA HAR FILE (KHÔNG CẦN PCAP)
═══════════════════════════════════════════════════════════════════════

BỐI CẢNH:
- Đang có HAR file capture từ Zalo Android (login flow).
- Muốn login lại tự động bằng thông tin trong HAR.
- KHÔNG muốn capture pcap mới, KHÔNG muốn chạy app.
- Mục tiêu: lấy được DK + CryptKey + socketServers mới để feed
  vào zalo_chat.py.

NHIỆM VỤ CHÍNH:

1. ĐỌC VÀ PHÂN TÍCH HAR FILE:

   1.1. Verify HAR có entry login không:
        - Tìm URL chứa: "phone/verify", "activeAccountByPassword",
          "verifyAccount"
        - Nếu KHÔNG có → RAISE "HAR không có login flow"
        - In ra: số entry, timestamp capture, endpoint list

   1.2. Extract từ HAR:
        a) zcid (từ request header "zcid:" hoặc body field "zcid")
        b) Device fingerprint (từ request body phone/verify):
           - advertising_id, android_id, device_identifier,
             device_spec_id, imei, model
           - build_info, deviceInfo (JSON string)
        c) sessionToken (từ response phone/verify)
        d) Request body của activeAccountByPassword
           (chứa sig + api_key + data)
        e) Response của activeAccountByPassword

   1.3. In báo cáo:
        - zcid length (96 hay 160 hex)
        - Timestamp capture (cũ hay mới)
        - Có đủ field để login lại không?
        - [CHƯA XÁC MINH] với field nào không đọc được

2. ĐÁNH GIÁ KHẢ THI REPLAY:

   2.1. Kiểm tra zcid còn dùng được không:
        - Nếu capture < 24h → có thể reuse
        - Nếu capture > 24h → ghi [CHƯA XÁC MINH, có thể đã hết hạn]

   2.2. Kiểm tra request body có gì:
        - Có "sig=" + "data=" → có thể replay
        - Chỉ có "data=" không có sig → không replay được
        - Body là JSON thuần → không replay qua HTTP form

   2.3. Kiểm tra response format:
        - Response là hex string (mã hóa AES) → cần decrypt
        - Response là JSON plaintext → có thể parse trực tiếp
        - Response rỗng/lỗi → ghi rõ

3. VIẾT SCRIPT zalo_login_from_har.py:

   Yêu cầu:
   - CLI: --har <path> [--phone +84...] [--password ...]
   - Đọc HAR, extract thông tin
   - Thử 2 phương án theo thứ tự:

     PHƯƠNG ÁN A — REPLAY REQUEST TỪ HAR:
     - Lấy nguyên body của activeAccountByPassword từ HAR
     - Gửi lại POST tới cùng endpoint với cùng headers
     - Parse response:
       * Nếu ec=0 → có DK mới → lưu fresh_session.json
       * Nếu ec=2013 (session expired) → chuyển sang phương án B
       * Nếu ec khác → báo lỗi rõ

     PHƯƠNG ÁN B — LOGIN MỚI VỚI DEVICE FINGERPRINT TỪ HAR:
     - Extract zcid + device fingerprint từ HAR
     - Gọi phone/verify với fingerprint đó
     - Gọi activeAccountByPassword
     - Nếu server trả 2048 (need verify) → báo user
       "Cần 2FA, không tự động được"
     - Nếu ec=0 → có DK mới → lưu fresh_session.json

   - Lưu output:
     {
       "uid": ...,
       "dk_hex": ...,
       "ksid": ...,
       "session_key": ...,
       "cryptkey": ...,
       "socketServers": [...],
       "source": "har_replay" | "har_fingerprint_login",
       "har_timestamp": ...,
       "login_timestamp": ...
     }

4. VERIFY SAU KHI CÓ DK:

   4.1. Test decrypt Frame 0:
        - Load /root/zalo/frame0.bin
        - Thử decrypt bằng DK mới
        - Nếu MAC fail → Frame 0 cũ không khớp DK mới
        - Cần capture pcap mới để extract Frame 0

   4.2. Nếu Frame 0 cũ fail:
        - Báo user: "DK mới OK nhưng cần frame0.bin mới"
        - Không tự ý chạy zalo_chat.py

   4.3. Nếu Frame 0 cũ OK:
        - Chạy thử zalo_chat.py --listen --duration 10
        - Xem handshake có OK không
        - Nếu Code=-22 → session hết hạn

5. XỬ LÝ LỖI THỰC TẾ:

   - HAR thiếu entry login → raise rõ ràng
   - HAR quá cũ (>7 ngày) → cảnh báo, vẫn thử
   - Response có ec=2048 → cần 2FA, hướng dẫn user
   - Response có ec=2060 → cần captcha, hướng dẫn user
   - Response có ec=-1001 → rate limit, chờ 15-60 phút
   - Replay fail (403, 2012) → sig sai hoặc body cũ
     → chuyển sang phương án B

6. OUTPUT YÊU CẦU:

   Báo cáo theo format:

   ─────────────────────────────────────────
   ## BÁO CÁO PHÂN TÍCH HAR

   ### Thông tin capture:
   - File: ...
   - Timestamp: ...
   - Số entry: ...
   - Endpoint login: CÓ / KHÔNG

   ### Trích xuất được:
   - zcid: [OK/FAIL] (length=...)
   - device fingerprint: [OK/FAIL] (số field=...)
   - sessionToken: [OK/FAIL]
   - request body: [OK/FAIL]
   - response: [OK/FAIL]

   ### Đánh giá khả thi:
   - Replay được: CÓ / KHÔNG / [CHƯA XÁC MINH]
   - Lý do: ...

   ### Kết quả thử:
   - Phương án A (replay): [thành công/fail với ec=...]
   - Phương án B (fingerprint login): [thành công/fail với ec=...]

   ### File output:
   - fresh_session.json: [đã tạo / lỗi]

   ### Việc cần làm tiếp:
   - [ ] ...
   - [ ] ...
   ─────────────────────────────────────────

RÀNG BUỘC:

1. KHÔNG BỊA. Nếu không đọc được HAR → báo rõ, không đoán.
2. KHÔNG hardcode zcid, API key, device fingerprint từ file khác.
3. Mọi error_code phải trích từ response THẬT, không giả định.
4. Nếu replay fail → không được tự ý bịa "server bận".
5. Không tự động chạy zalo_chat.py khi chưa verify Frame 0.
6. Log mọi request/response ra file debug để trace.
7. Format output theo template trên.
8. Nếu HAR không có → hỏi user capture mới, không tự sinh.
9. Không dùng Frida. Chỉ đọc file tĩnh.
10. Ghi rõ [CHƯA XÁC MINH] cho phần chưa test được.

BẮT ĐẦU:

Bước 1: Liệt kê tất cả file .har trong workspace.
Bước 2: Cho user chọn file hoặc dùng file mới nhất.
Bước 3: Chạy phân tích theo mục 1.
Bước 4: In báo cáo.
Bước 5: Chờ user xác nhận trước khi chạy mục 3.
