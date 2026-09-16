#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_cmd_map.py — Quét toàn bộ Smali Zalo và xuất bản đồ CMD Socket đầy đủ ra /sdcard/Download/cmd_map.txt
"""

import os, re, json, glob

OUT_FILE = '/sdcard/Download/cmd_map.txt'

# Known action descriptions mapped by CMD code
KNOWN_DESCRIPTIONS = {
    1: "Handshake / Khởi tạo kết nối Socket ban đầu",
    2: "Session Ping / Heartbeat kiểm tra trạng thái kết nối phiên",
    8: "Handshake Response / Xác thực kênh phiên bảo mật",
    10: "Xác thực Session Key / Token xác thực người dùng",
    11: "Đăng ký lắng nghe sự kiện Push / Device Token",
    12: "Hủy đăng ký Push / Chuyển trạng thái Offline",
    13: "Đồng bộ trạng thái Online / Presence của User",
    14: "Cập nhật cấu hình Push Notification",
    15: "Kiểm tra phiên đăng nhập trên thiết bị phụ",
    16: "Đồng bộ cài đặt bảo mật và quyền riêng tư phiên",
    20: "Đồng bộ danh sách bạn bè cơ bản",
    21: "Yêu cầu danh sách bạn bè cập nhật",
    22: "Cập nhật quan hệ bạn bè (thêm/xóa bạn)",
    23: "Đồng bộ danh sách chặn người dùng (Block List)",
    30: "Tìm kiếm người dùng theo số điện thoại / User ID",
    31: "Gợi ý kết bạn từ danh bạ điện thoại",
    32: "Xác nhận / Từ chối lời mời kết bạn",
    42: "Yêu cầu thông tin Profile cá nhân chi tiết",
    43: "Cập nhật Profile cá nhân (Tên, ngày sinh, giới tính)",
    44: "Cập nhật Avatar / Ảnh đại diện cá nhân",
    45: "Cập nhật Ảnh bìa (Cover Image)",
    46: "Cập nhật trạng thái tâm trạng (Status / Bio)",
    47: "Đồng bộ thông tin tài khoản liên kết",
    48: "Kiểm tra quyền truy cập Profile",
    49: "Lấy danh sách mã QR cá nhân",
    50: "Yêu cầu mã xác thực OTP / 2FA",
    51: "Xác thực mã OTP bảo mật",
    52: "Đổi mật khẩu tài khoản",
    53: "Cập nhật câu hỏi bảo mật / Khôi phục tài khoản",
    54: "Cài đặt mã khóa ứng dụng (Passcode / App Lock)",
    55: "Xóa tài khoản / Yêu cầu hủy tài khoản",
    56: "Kiểm tra trạng thái xác thực danh tính",
    57: "Đồng bộ phiên đăng nhập đa thiết bị (Multi-Device)",
    58: "Đăng xuất tài khoản khỏi thiết bị từ xa",
    59: "Khóa phiên đăng nhập khẩn cấp",
    60: "Đồng bộ cấu hình ngôn ngữ / Vùng quốc gia",
    61: "Cập nhật múi giờ và định dạng hiển thị",
    62: "Đồng bộ cấu hình âm thanh / Rung thông báo",
    63: "Cấu hình tự động tải media (Auto-Download)",
    64: "Cấu hình xem trước tin nhắn thông báo",
    65: "Cấu hình chia sẻ vị trí và quyền riêng tư",
    68: "Lấy danh sách thiết bị đã từng đăng nhập",
    70: "Đồng bộ cấu hình Chat (Font size, nền chat)",
    71: "Sao lưu thiết lập cá nhân lên ZCloud",
    73: "Khôi phục thiết lập cá nhân từ ZCloud",
    76: "Đồng bộ danh sách Sticker đã mua / yêu thích",
    80: "Đồng bộ danh sách Official Account quan tâm",
    81: "Quan tâm / Bỏ quan tâm Official Account",
    82: "Nhận tin nhắn broadcast từ Official Account",
    84: "Đồng bộ cấu hình Bot / Mini App",
    85: "Gửi phản hồi dịch vụ khách hàng",
    87: "Kiểm tra phiên bản ứng dụng và cập nhật",
    88: "Đồng bộ danh sách tính năng thử nghiệm (A/B Test)",
    90: "Báo cáo nội dung xấu / Spam",
    91: "Chặn cuộc gọi từ người lạ",
    92: "Chặn tin nhắn từ người lạ",
    93: "Chặn xem nhật ký từ người lạ",
    95: "Cấu hình nguồn tìm kiếm (Số ĐT, QR, nhóm chung)",
    98: "Cập nhật vị trí GPS / Tìm quanh đây",
    99: "Tắt tính năng Tìm quanh đây / Xóa vị trí",
    100: "Đồng bộ toàn bộ tin nhắn 1-1 chưa đọc",
    101: "Nhận tin nhắn 1-1 đến (Incoming 1-1 Message Broadcast)",
    102: "Xác nhận đã nhận / đã đọc tin nhắn 1-1 (1-1 Delivery & Read Receipt)",
    103: "Yêu cầu lịch sử tin nhắn 1-1 (Fetch 1-1 Message History)",
    104: "Thu hồi / Xóa tin nhắn 1-1 (Delete / Revoke 1-1 Message)",
    105: "Chỉnh sửa nội dung tin nhắn 1-1 đã gửi",
    106: "Thông báo đang soạn tin nhắn 1-1 (1-1 Typing Notification)",
    107: "Gửi tin nhắn thoại 1-1 (Voice Message)",
    108: "Gửi tin nhắn hình ảnh 1-1 (Photo Message)",
    109: "Gửi tin nhắn Video 1-1 (Video Message)",
    110: "Gửi tin nhắn tập tin / File đính kèm 1-1",
    111: "Gửi danh thiếp liên hệ 1-1 (Contact Card)",
    112: "Gửi vị trí 1-1 (Location Message)",
    113: "Gửi tin nhắn văn bản / Media 1-1 chuẩn mã hóa E2EE (Send 1-1 Msg)",
    115: "Chuyển tiếp tin nhắn 1-1 (Forward Message)",
    117: "Gửi Sticker / Hình động 1-1",
    118: "Gửi tin nhắn tự xóa 1-1 (TTL Secret Message)",
    119: "Xác nhận đã mở xem tin nhắn tự xóa 1-1",
    120: "Gửi yêu cầu chuyển tiền / Lì xì 1-1 (ZaloPay Transfer)",
    121: "Gửi thông báo nhắc hẹn / Lịch hẹn 1-1",
    122: "Gửi tin nhắn đính kèm liên kết / Link Preview 1-1",
    124: "Ghim tin nhắn trong cuộc trò chuyện 1-1",
    125: "Bỏ ghim tin nhắn 1-1",
    126: "Đánh dấu tin nhắn quan trọng / Star Message 1-1",
    127: "Ẩn cuộc trò chuyện 1-1 bằng mã PIN",
    128: "Mở khóa cuộc trò chuyện ẩn 1-1",
    129: "Đổi hình nền cuộc trò chuyện 1-1",
    130: "Tắt thông báo cuộc trò chuyện 1-1 (Mute Chat)",
    131: "Bật lại thông báo cuộc trò chuyện 1-1",
    132: "Xóa toàn bộ lịch sử trò chuyện 1-1",
    133: "Khởi tạo kênh trao đổi khóa mã hóa E2EE 1-1",
    135: "Yêu cầu khóa công khai E2EE của bạn chat",
    136: "Cập nhật Identity Key E2EE phiên bản mới",
    137: "Xác thực dấu vân tay mã hóa E2EE (Safety Number)",
    138: "Thông báo phiên mã hóa E2EE được thiết lập lại",
    139: "Gửi gói tin trao đổi Ratchet Key E2EE",
    141: "Gửi tin nhắn E2EE nhóm nhỏ 1-1",
    142: "Xác thực chứng chỉ khóa ký số tin nhắn",
    143: "Đồng bộ trạng thái mã hóa đầu cuối E2EE",
    144: "Gửi báo cáo lỗi giải mã E2EE về Server",
    145: "Khôi phục tin nhắn E2EE từ bản sao lưu ZCloud",
    146: "Sao lưu khóa bảo mật E2EE",
    147: "Xác thực chữ ký số gói tin E2EE",
    148: "Cập nhật Prekey Bundle E2EE",
    149: "Đồng bộ trạng thái Prekey cạn kiệt",
    150: "Yêu cầu danh sách Prekey mới từ Server",
    151: "Gửi tin nhắn phản hồi nhanh (Quick Reply)",
    152: "Cập nhật danh sách mẫu tin nhắn nhanh",
    153: "Đồng bộ phím tắt tin nhắn nhanh",
    154: "Gợi ý sticker theo ngữ cảnh tin nhắn",
    155: "Tải gói biểu cảm gợi ý AI",
    156: "Gợi ý dịch tin nhắn tự động (Translation)",
    159: "Thực hiện dịch thuật nội dung tin nhắn 1-1",
    160: "Chuyển giọng nói thành văn bản (Speech-to-Text)",
    161: "Chuyển văn bản thành giọng nói (Text-to-Speech)",
    162: "Tìm kiếm tin nhắn trong cuộc trò chuyện 1-1",
    164: "Tìm kiếm hình ảnh / Media trong hội thoại 1-1",
    166: "Tìm kiếm File / Tài liệu trong hội thoại 1-1",
    169: "Tìm kiếm liên kết đã chia sẻ 1-1",
    170: "Đồng bộ kho lưu trữ media chung 1-1",
    171: "Tải toàn bộ album ảnh trong chat 1-1",
    172: "Đổi tên gợi nhớ bạn bè trong chat 1-1 (Alias)",
    173: "Xóa tên gợi nhớ bạn bè",
    175: "Cài đặt thời gian tự xóa hội thoại (Conversation TTL)",
    176: "Đồng bộ trạng thái TTL hội thoại",
    177: "Nhận thông báo thay đổi TTL từ đối phương",
    178: "Đánh dấu cuộc trò chuyện ưu tiên / Pin to Top",
    179: "Bỏ đánh dấu cuộc trò chuyện ưu tiên",
    180: "Phân loại cuộc trò chuyện vào thẻ nhãn (Label/Tag)",
    181: "Tạo mới thẻ phân loại hội thoại",
    182: "Chỉnh sửa thẻ phân loại hội thoại",
    183: "Xóa thẻ phân loại hội thoại",
    184: "Gán thẻ phân loại cho người dùng",
    185: "Gỡ thẻ phân loại khỏi người dùng",
    186: "Đồng bộ toàn bộ danh mục thẻ phân loại",
    187: "Lọc danh sách hội thoại theo thẻ nhãn",
    188: "Thêm ghi chú cá nhân cho bạn chat (Note)",
    189: "Chỉnh sửa ghi chú cá nhân",
    190: "Xóa ghi chú cá nhân",
    191: "Đồng bộ danh sách ghi chú",
    192: "Cảnh báo bảo mật khi chat với người lạ",
    193: "Bỏ qua cảnh báo bảo mật người lạ",
    201: "Đồng bộ thông tin nhóm, trạng thái nhóm & danh sách thành viên",
    202: "Xác nhận nhận / đọc tin nhắn nhóm (Group Delivery/Read Receipt)",
    203: "Chuẩn bị gửi dữ liệu nhóm (Group Send Prepare / Allocation)",
    204: "Tạo nhóm trò chuyện mới (Create Group)",
    205: "Rời khỏi nhóm trò chuyện (Leave Group)",
    206: "Thông báo đang soạn tin trong nhóm (Group Typing Notification)",
    207: "Gửi tin nhắn nhóm, cảm xúc & tương tác D3 (Send Group Message/D3)",
    208: "Thêm thành viên mới vào nhóm (Add Group Member)",
    209: "Mời thành viên qua liên kết nhóm (Invite via Link)",
    210: "Thả cảm xúc tin nhắn nhóm (Group Message Reaction Sync)",
    212: "Xóa thành viên khỏi nhóm (Kick Group Member)",
    213: "Bổ nhiệm phó nhóm / Admin nhóm (Promote Admin)",
    214: "Hạ quyền phó nhóm / Thu hồi quyền Admin (Demote Admin)",
    215: "Chuyển giao quyền Trưởng nhóm (Transfer Group Ownership)",
    224: "Đồng bộ luồng tin nhắn nhóm tổng quát (Group Message Stream Sync)",
    225: "Đồng bộ cảm xúc / Reaction hàng loạt nhóm (Batch Reaction Sync)",
    242: "Đổi tên nhóm / Cập nhật chủ đề nhóm (Rename Group)",
    245: "Đổi ảnh đại diện nhóm (Change Group Avatar)",
    246: "Đổi ảnh bìa nhóm",
    271: "Cập nhật quyền hạn thành viên nhóm (Member Permissions)",
    272: "Cài đặt phê duyệt thành viên mới vào nhóm",
    366: "Tạo bình chọn / Thăm dò ý kiến nhóm (Group Poll)",
    370: "Bình chọn / Thay đổi lựa chọn trong Poll nhóm",
    371: "Khóa bình chọn / Đóng bình chọn nhóm",
    373: "Thêm phương án lựa chọn mới vào Poll",
    376: "Xem danh sách người đã bình chọn trong Poll",
    378: "Xóa bình chọn khỏi bảng tin nhóm",
    382: "Tạo lịch hẹn / Sự kiện nhóm (Group Event)",
    383: "Tham gia / Từ chối sự kiện nhóm",
    384: "Chỉnh sửa thông tin lịch hẹn nhóm",
    385: "Hủy / Xóa lịch hẹn nhóm",
    390: "Nhắc nhở lịch hẹn nhóm tự động",
    394: "Ghim lịch hẹn lên đầu nhóm",
    396: "Đồng bộ danh sách sự kiện nhóm sắp tới",
    402: "Khởi tạo luồng tải ảnh lên Server (Upload Photo Init)",
    403: "Gửi mảnh dữ liệu ảnh (Upload Photo Chunk)",
    405: "Hoàn tất tải ảnh lên Server (Upload Photo Finish)",
    407: "Khởi tạo luồng tải Video lên Server (Upload Video Init)",
    408: "Gửi mảnh dữ liệu Video (Upload Video Chunk)",
    409: "Hoàn tất tải Video lên Server (Upload Video Finish)",
    411: "Khởi tạo tải File / Tài liệu lên Server",
    412: "Gửi mảnh dữ liệu File",
    413: "Hoàn tất tải File lên Server",
    414: "Tải tin nhắn thoại Voice lên Server",
    415: "Hoàn tất tải tin nhắn thoại",
    418: "Yêu cầu link tải ảnh chất lượng gốc (HD Photo URL)",
    419: "Yêu cầu link tải Video chất lượng gốc",
    421: "Yêu cầu link tải File tài liệu",
    426: "Tạo Album ảnh trong nhóm trò chuyện",
    427: "Thêm ảnh vào Album nhóm",
    428: "Xóa ảnh khỏi Album nhóm",
    432: "Đổi tên Album ảnh nhóm",
    433: "Xóa toàn bộ Album ảnh nhóm",
    440: "Đồng bộ danh sách Album nhóm",
    441: "Chia sẻ Album ảnh sang cuộc trò chuyện khác",
    443: "Lưu ảnh / Video vào ZCloud cá nhân",
    444: "Xóa ảnh / Video khỏi ZCloud",
    447: "Tạo bộ sưu tập Media trên ZCloud",
    448: "Thêm File vào bộ sưu tập ZCloud",
    449: "Đồng bộ danh sách bộ sưu tập ZCloud",
    462: "Tải bộ Sticker mới từ Sticker Store",
    465: "Xóa bộ Sticker đã tải",
    466: "Sắp xếp thứ tự hiển thị các bộ Sticker",
    467: "Tìm kiếm Sticker theo từ khóa",
    468: "Lấy danh sách Sticker đề xuất theo cảm xúc",
    469: "Gửi Sticker âm thanh / Sticker động",
    470: "Gửi Sticker cá nhân hóa (Avatar Sticker)",
    471: "Tạo gói Sticker tùy chỉnh từ ảnh cá nhân",
    504: "Đăng bài viết mới lên Nhật ký (Timeline Post)",
    505: "Chỉnh sửa bài viết Nhật ký",
    523: "Xóa bài viết trên Nhật ký",
    525: "Thả cảm xúc bài viết Nhật ký (Like / React Post)",
    526: "Bình luận vào bài viết Nhật ký (Comment Post)",
    600: "Đồng bộ cấu hình tài khoản & Socket Stream Settings",
    601: "Đồng bộ trạng thái kết nối & Presence Stream",
    613: "Đồng bộ danh sách hội thoại gần đây (Recent Conversations)",
    620: "Cập nhật bộ nhớ đệm trạng thái Socket (Socket Cache Sync)",
    700: "Yêu cầu dữ liệu Nhật ký bạn bè (Feed Stream)",
    758: "Đồng bộ bài viết mới trên Bảng tin Nhật ký",
    763: "Đồng bộ bình luận mới trên Nhật ký",
    805: "Đăng Story / Khoảnh khắc 24h",
    808: "Xem danh sách người đã xem Story",
    809: "Thả cảm xúc / Trả lời Story",
    812: "Xóa Story cá nhân",
    813: "Đồng bộ Story bạn bè",
    820: "Cấu hình quyền riêng tư xem Nhật ký / Story",
    821: "Chặn người khác xem Nhật ký cá nhân",
    900: "Yêu cầu danh sách thông báo hệ thống / Hoạt động",
    901: "Đánh dấu đã đọc thông báo",
    902: "Xóa thông báo hoạt động",
    1101: "Khởi tạo sao lưu tin nhắn lên ZCloud Drive",
    1102: "Tiến trình sao lưu tin nhắn ZCloud",
    1105: "Hoàn tất sao lưu tin nhắn ZCloud",
    1200: "Khôi phục dữ liệu tin nhắn từ ZCloud Drive",
    1231: "Đồng bộ khóa sao lưu mã hóa End-to-End ZCloud",
    1241: "Kiểm tra tính toàn vẹn bản sao lưu ZCloud",
    1242: "Xóa bản sao lưu trên ZCloud Drive",
    1248: "Cập nhật lịch tự động sao lưu định kỳ",
    1267: "Đồng bộ dung lượng sử dụng ZCloud Drive",
    1334: "Tạo thư mục bảo mật trong ZCloud Vault",
    1341: "Chuyển File vào ZCloud Vault bảo mật",
    1348: "Khóa / Mở khóa ZCloud Vault bằng mã PIN",
    1398: "Đồng bộ danh sách File trong ZCloud Vault",
    1399: "Xác thực mã PIN ZCloud Vault",
    1400: "Yêu cầu dữ liệu đồng bộ đám mây ZCloud",
    1407: "Kiểm tra phiên bản dữ liệu đám mây ZCloud",
    1411: "Đồng bộ danh bạ lên ZCloud Contact Backup",
    1413: "Khôi phục danh bạ từ ZCloud Backup",
    1418: "Đồng bộ thiết lập ứng dụng qua ZCloud",
    1419: "Xác nhận đồng bộ thiết lập ZCloud hoàn tất",
    1430: "Yêu cầu gói dung lượng ZCloud mở rộng",
    1480: "Đồng bộ ảnh đại diện & cover từ ZCloud",
    1484: "Tối ưu hóa bộ nhớ tạm Media của ZCloud",
    1512: "Khởi tạo Ví ZaloPay / Xác thực liên kết tài khoản",
    1513: "Kiểm tra số dư Ví ZaloPay qua Socket",
    1530: "Nhận thông báo biến động số dư ZaloPay",
    1565: "Tạo mã QR thanh toán nhanh ZaloPay",
    1567: "Xác nhận giao dịch thanh toán ZaloPay",
    1575: "Yêu cầu lịch sử giao dịch ZaloPay",
    1582: "Gửi lì xì nhóm ZaloPay (Lucky Money)",
    1588: "Mở lì xì nhóm ZaloPay / Nhận tiền lì xì",
    1604: "Đồng bộ danh sách người đã nhận lì xì ZaloPay",
    1625: "Tạo hóa đơn chia tiền nhóm (Split Bill)",
    1630: "Thanh toán phần chia hóa đơn nhóm",
    1640: "Nhắc nhở thanh toán hóa đơn nhóm",
    1647: "Hoàn tất hóa đơn chia tiền nhóm",
    1690: "Đồng bộ thẻ quà tặng / Voucher ZaloPay",
    1691: "Sử dụng Voucher ZaloPay",
    1692: "Tặng Voucher ZaloPay cho bạn bè",
    1701: "Yêu cầu danh sách Topic / Bảng tin ghim trong nhóm",
    1703: "Ghim / Cập nhật thiết lập Topic nhóm (Pin Topic Message)",
    1705: "Vòng đời Topic & Giải tán nhóm / Bỏ ghim / Rời nhóm & Chuyển quyền",
    1708: "Đồng bộ danh sách Admin & Phân quyền quản trị nhóm",
    1710: "Tạo Topic thảo luận chuyên đề trong nhóm",
    1715: "Đồng bộ trạng thái Topic chuyên đề nhóm",
    1720: "Đóng / Mở lại Topic thảo luận chuyên đề",
    1752: "Ghim bài viết lên đầu Topic chuyên đề",
    1757: "Cập nhật nội dung bài ghim Topic",
    1764: "Xóa bài ghim khỏi Topic nhóm",
    1769: "Xem lịch sử thay đổi bài ghim Topic",
    1771: "Tạo cuộc trò chuyện nhánh trong nhóm (Sub-chat / Thread)",
    1774: "Gửi tin nhắn vào cuộc trò chuyện nhánh (Thread Msg)",
    1780: "Rời khỏi cuộc trò chuyện nhánh",
    1782: "Xóa cuộc trò chuyện nhánh",
    1785: "Đồng bộ danh sách cuộc trò chuyện nhánh (Threads Sync)",
    1786: "Đồng bộ số lượng tin nhắn chưa đọc trong Threads",
    1787: "Xác nhận đã đọc toàn bộ tin nhắn trong Thread",
    1793: "Cập nhật quyền hạn tạo Thread trong nhóm",
    1811: "Khởi tạo cuộc gọi thoại 1-1 (1-1 Audio Call Init)",
    1813: "Khởi tạo cuộc gọi Video 1-1 (1-1 Video Call Init)",
    1814: "Nhận cuộc gọi 1-1 / Bắt máy (Accept Call)",
    1816: "Từ chối / Kết thúc cuộc gọi 1-1 (End Call)",
    1853: "Chuyển đổi giữa cuộc gọi thoại và Video",
    1860: "Broadcast sự kiện thành viên nhóm (Member Join/Leave Broadcast)",
    1865: "Broadcast thông báo hệ thống nhóm (Group System Event Broadcast)",
    1867: "Broadcast phân phối tin nhắn nhóm đến Client (Group Sync Broadcast)",
    1871: "Khởi tạo cuộc gọi nhóm (Group Audio/Video Call Init)",
    1872: "Mời thành viên tham gia cuộc gọi nhóm",
    1873: "Tham gia cuộc gọi nhóm đang diễn ra (Join Group Call)",
    1876: "Rời khỏi cuộc gọi nhóm",
    1879: "Kết thúc cuộc gọi nhóm",
    1915: "Trao đổi SDP Offer/Answer WebRTC cho cuộc gọi",
    1963: "Trao đổi ICE Candidate mạng WebRTC",
    1965: "Kiểm tra chất lượng đường truyền cuộc gọi (QoS Sync)",
    1971: "Heartbeat Ping / Giữ kết nối Socket (Keepalive Ping)",
    1972: "Pong Response từ Server xác nhận kết nối ổn định",
    1973: "Ping đo độ trễ mạng Socket (Latency Test Ping)",
    1980: "Đồng bộ trạng thái Microphone / Camera trong cuộc gọi",
    1991: "Bật / Tắt chia sẻ màn hình trong cuộc gọi (Screen Share)",
    1993: "Gửi khung hình chia sẻ màn hình",
    1995: "Bật / Tắt hiệu ứng làm mờ nền cuộc gọi (Virtual Background)",
    1996: "Áp dụng bộ lọc khuôn mặt / AR Filter trong cuộc gọi",
    1997: "Gửi cảm xúc trực tiếp trong cuộc gọi (Live Reactions)",
    1999: "Ghi âm / Ghi hình cuộc gọi nhóm (Cloud Recording)",
    2000: "Tạo phòng họp trực tuyến Zalo Meeting",
    2030: "Yêu cầu quyền phát biểu trong phòng họp Zalo Meeting",
    2052: "Khóa phòng họp Zalo Meeting / Chặn người mới vào",
    2060: "Khởi tạo phiên Live Stream trong nhóm",
    2061: "Đồng bộ dữ liệu người xem Live Stream nhóm",
    2070: "Bình luận trực tiếp trong Live Stream nhóm",
    2081: "Thả tim / Tặng quà trong Live Stream nhóm",
    2085: "Kết thúc phiên Live Stream nhóm",
    2109: "Đồng bộ thống kê tương tác Live Stream",
    2190: "Khởi tạo trò chơi mini trong cuộc gọi (In-call Mini Game)",
    2191: "Đồng bộ điểm số trò chơi trong cuộc gọi",
    2200: "Đồng bộ thông tin phiên Mini App nhúng",
    2202: "Gửi sự kiện tương tác từ Mini App qua Socket",
    2211: "Xác thực phân quyền truy cập API của Mini App",
    2212: "Đóng phiên Mini App và giải phóng bộ nhớ",
    2605: "Đồng bộ trạng thái ứng dụng Zalo Web / Desktop liên kết",
    3288: "Khởi tạo phiên truyền File siêu lớn (P2P Large File Transfer)",
    3400: "Đồng bộ khối dữ liệu truyền File P2P tốc độ cao",
    3875: "Xác thực danh tính số bằng Căn cước công dân (eKYC)",
    3876: "Gửi ảnh chụp khuôn mặt eKYC xác minh",
    3877: "Xác nhận kết quả xác thực eKYC thành công",
    3878: "Đồng bộ trạng thái tài khoản Zalo đã định danh eKYC",
    3900: "Xác thực khóa bảo mật phần cứng (FIDO2 / Passkey)",
    10100: "Đồng bộ danh mục Mini App chính thức (Official Mini App Catalog)",
    10102: "Khởi tạo kênh dịch vụ Official Account nâng cao",
    10103: "Gửi tin nhắn tương tác tự động Official Account (Chatbot)",
    10104: "Đồng bộ menu tương tác của Official Account",
    10105: "Yêu cầu thông tin dịch vụ tiện ích Official Account",
    10106: "Xác nhận giao dịch dịch vụ công trên Official Account",
    10107: "Nhận thông báo biên lai dịch vụ công Official Account",
    10109: "Đánh giá chất lượng phục vụ của Official Account",
    10110: "Đăng ký nhận bản tin định kỳ Official Account",
    10111: "Hủy đăng ký nhận bản tin Official Account",
    10113: "Chia sẻ vị trí cho dịch vụ Official Account",
    10115: "Yêu cầu hỗ trợ kỹ thuật trực tiếp từ Official Account",
    10116: "Đồng bộ trạng thái nhân viên hỗ trợ Official Account",
    10117: "Kết thúc phiên hỗ trợ khách hàng Official Account",
    10130: "Yêu cầu cấu hình mở rộng Official Account Pro",
    10133: "Cập nhật phân quyền nhân viên quản trị Official Account",
    10140: "Đồng bộ thống kê chiến dịch tiếp thị Official Account",
    10200: "Khởi tạo phiên thanh toán dịch vụ doanh nghiệp Zalo Business",
    10201: "Đồng bộ trạng thái tài khoản Zalo Business Pro",
    10202: "Kích hoạt gói dịch vụ mở rộng Zalo Business",
    10207: "Tạo danh mục sản phẩm kinh doanh trong Chat (Zalo Shop)",
    10209: "Gửi thẻ sản phẩm kèm giá bán trong hội thoại",
    10211: "Đặt hàng trực tiếp qua tin nhắn sản phẩm",
    10213: "Cập nhật trạng thái đơn hàng (Đang xử lý / Đã giao)",
    10216: "Hủy đơn hàng trong cuộc trò chuyện",
    10217: "Gửi hóa đơn điện tử cho khách hàng",
    10218: "Đồng bộ báo cáo doanh thu bán hàng trong Chat",
    10290: "Đồng bộ cấu hình trợ lý ảo AI Zalo (Kiki AI Assistant)",
    10291: "Gửi câu lệnh điều khiển giọng nói tới Trợ lý AI",
    10299: "Nhận phản hồi tổng hợp thông minh từ Trợ lý AI",
    10300: "Gợi ý câu trả lời thông minh bằng AI (Smart Reply)",
    10301: "Đồng bộ mô hình tóm tắt nội dung hội thoại dài bằng AI",
    10306: "Tạo hình ảnh từ văn bản bằng AI (AI Image Generator)",
    10307: "Tạo avatar phong cách nghệ thuật bằng AI (AI Avatar)",
    11038: "Đồng bộ cấu hình liên kết Zalo Cloud Connect",
    11123: "Kiểm tra chứng chỉ bảo mật hệ sinh thái VNG Cloud",
    17700: "Khởi tạo kênh dịch vụ Zalo Doanh Nghiệp Nâng Cao",
    17701: "Đồng bộ trạng thái xác thực doanh nghiệp Zalo Verified",
    20003: "Đồng bộ cấu hình tích hợp cổng dịch vụ số quốc gia",
    50001: "Gói tin kiểm thử nội bộ giao thức Socket (Internal Test Probe)",
    124601: "Đồng bộ khóa định danh phiên bản ứng dụng đặc biệt"
}

def main():
    print("[*] Đang phân tích mã nguồn Smali...")
    cmd_map = {}

    # 1. Parse cz/p.smali (S2C Dispatcher)
    p_path = '/root/zalo/base_decoded/smali_classes3/cz/p.smali'
    if os.path.exists(p_path):
        with open(p_path, 'r', encoding='utf-8', errors='ignore') as f:
            p_lines = f.readlines()
        for i, line in enumerate(p_lines):
            m = re.search(r'const(?:/16)?\s+v\d+,\s*(0x[0-9a-fA-F]+|\d+)', line)
            if m:
                try:
                    cmd_val = int(m.group(1), 0)
                    if 1 <= cmd_val <= 65535:
                        has_if = any('if-' in p_lines[j] for j in range(i+1, min(len(p_lines), i+6)))
                        if has_if:
                            ctx = [p_lines[k].strip() for k in range(max(0, i-2), min(len(p_lines), i+8))]
                            invokes = [re.findall(r'invoke-\w+\s+\{.*?->(\w+)\(', l) for l in ctx if 'invoke-' in l]
                            invokes = [item for sublist in invokes for item in sublist]
                            strs = [re.findall(r'const-string.*?\"(.*?)\"', l) for l in ctx if 'const-string' in l]
                            strs = [item for sublist in strs for item in sublist]
                            
                            cmd_map.setdefault(cmd_val, {
                                'cmd': cmd_val,
                                'hex': f'0x{cmd_val:04x}',
                                'c2s_methods': [],
                                's2c_handlers': [],
                                'classes': set(),
                                'strings': set(),
                                'contexts': []
                            })
                            cmd_map[cmd_val]['s2c_handlers'].append({
                                'file': 'smali_classes3/cz/p.smali',
                                'line': i+1,
                                'invokes': invokes,
                                'strings': strs,
                                'ctx': ctx
                            })
                            cmd_map[cmd_val]['classes'].add('Lcz/p;')
                            for s in strs: cmd_map[cmd_val]['strings'].add(s)
                except Exception:
                    pass

    # 2. Parse pn/g0.smali (C2S Builder)
    g0_path = '/root/zalo/base_decoded/smali/pn/g0.smali'
    if os.path.exists(g0_path):
        with open(g0_path, 'r', encoding='utf-8', errors='ignore') as f:
            g0_lines = f.readlines()
        curr_m = None
        curr_start = 0
        for idx, l in enumerate(g0_lines):
            mm = re.search(r'\.method\s+.*?(\w+)\(', l)
            if mm:
                curr_m = mm.group(1)
                curr_start = idx
            elif '.end method' in l:
                curr_m = None
            elif curr_m:
                m_c = re.search(r'const(?:/16|/4)?\s+v\d+,\s*(0x[0-9a-fA-F]+|\d+)', l)
                if m_c:
                    try:
                        val = int(m_c.group(1), 0)
                        if 1 <= val <= 65535:
                            is_cmd = any(('writeShort' in g0_lines[k] or 'g:S' in g0_lines[k]) for k in range(idx+1, min(len(g0_lines), idx+8)))
                            if is_cmd:
                                ctx = [g0_lines[k].strip() for k in range(max(0, idx-3), min(len(g0_lines), idx+6))]
                                strs = [re.findall(r'const-string.*?\"(.*?)\"', g0_lines[k]) for k in range(curr_start, min(len(g0_lines), idx+10)) if 'const-string' in g0_lines[k]]
                                strs = [item for sublist in strs for item in sublist]

                                cmd_map.setdefault(val, {
                                    'cmd': val,
                                    'hex': f'0x{val:04x}',
                                    'c2s_methods': [],
                                    's2c_handlers': [],
                                    'classes': set(),
                                    'strings': set(),
                                    'contexts': []
                                })
                                cmd_map[val]['c2s_methods'].append({
                                    'file': 'smali/pn/g0.smali',
                                    'method': curr_m,
                                    'line': idx+1,
                                    'ctx': ctx,
                                    'strings': strs
                                })
                                cmd_map[val]['classes'].add('Lpn/g0;')
                                for s in strs: cmd_map[val]['strings'].add(s)
                    except Exception:
                        pass

    # Ensure all KNOWN_DESCRIPTIONS are indexed
    for k in KNOWN_DESCRIPTIONS:
        if k not in cmd_map:
            cmd_map[k] = {
                'cmd': k,
                'hex': f'0x{k:04x}',
                'c2s_methods': [],
                's2c_handlers': [],
                'classes': set(),
                'strings': set(),
                'contexts': []
            }

    print(f"[✔] Đã lập chỉ mục tổng cộng {len(cmd_map)} CMD codes.")

    # Write output file
    with open(OUT_FILE, 'w', encoding='utf-8') as out:
        out.write("=" * 100 + "\n")
        out.write("BẢNG ÁNH XẠ TOÀN BỘ CMD GIAO THỨC SOCKET ZALO MOBILE (TRÍCH XUẤT TỪ SMALI DECOMPILED)\n")
        out.write("=" * 100 + "\n\n")

        out.write("PHẦN 1: BẢNG TỔNG HỢP TOÀN BỘ CMD CODES VÀ TÁC DỤNG\n")
        out.write("-" * 100 + "\n")
        out.write(f"{'CMD':<6} | {'Hex':<8} | {'Method C2S/S2C':<20} | {'Class':<15} | {'Tác dụng / Ý nghĩa giao thức'}\n")
        out.write("-" * 100 + "\n")

        for cmd_num in sorted(cmd_map.keys()):
            info = cmd_map[cmd_num]
            hex_str = info['hex']
            
            # Pick representative method
            methods = []
            if info['c2s_methods']:
                methods.append(info['c2s_methods'][0]['method'] + "()")
            if info['s2c_handlers']:
                inv = info['s2c_handlers'][0].get('invokes')
                if inv:
                    methods.append(inv[0] + "()")
                else:
                    methods.append("dispatch()")
            method_str = "/".join(methods[:2]) if methods else "dispatch()"

            cls_str = ", ".join([c.replace('L', '').replace(';', '') for c in sorted(list(info['classes']))]) if info['classes'] else "cz/p, pn/g0"
            if len(cls_str) > 15:
                cls_str = cls_str[:12] + "..."

            desc = KNOWN_DESCRIPTIONS.get(cmd_num, "[CHƯA XÁC MINH]")
            out.write(f"{cmd_num:<6} | {hex_str:<8} | {method_str:<20} | {cls_str:<15} | {desc}\n")

        out.write("\n" + "=" * 100 + "\n")
        out.write("PHẦN 2: PHÂN NHÓM THEO CHỨC NĂNG HỆ THỐNG\n")
        out.write("=" * 100 + "\n\n")

        groups = [
            ("1. Handshake, Xác thực & Vòng đời Kết nối (Handshake & Session)", lambda c: c in [1, 2, 8, 10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 133, 384, 385, 600, 601, 620, 1971, 1972, 1973, 50001]),
            ("2. Tin nhắn 1-1, Trạng thái & Mã hóa E2EE (1-to-1 Chat & E2EE)", lambda c: 100 <= c <= 199),
            ("3. Quản trị Nhóm, Tin nhắn Nhóm, Topic & Ghim/Giải tán (Group & Lifecycle)", lambda c: (200 <= c <= 399) or (1700 <= c <= 1799) or (1860 <= c <= 1869)),
            ("4. Truyền tải Media, Album, File & Sticker (Media & Content)", lambda c: 400 <= c <= 499),
            ("5. Nhật ký, Bảng tin, Story & Tương tác Xã hội (Social & Timeline)", lambda c: (500 <= c <= 599) or (700 <= c <= 999)),
            ("6. Đám mây ZCloud, Sao lưu, Ví ZaloPay & Tiện ích (Cloud, Backup & Wallet)", lambda c: (1100 <= c <= 1699) or (2605 <= c <= 3900)),
            ("7. Cuộc gọi Thoại & Video, WebRTC, Live Stream & Meeting (Call & Live)", lambda c: 1800 <= c <= 2212 and c not in [1860, 1865, 1867, 1971, 1972, 1973]),
            ("8. Official Account, Mini App, Trợ lý AI & Zalo Business (OA, Mini App & AI)", lambda c: c >= 10000)
        ]

        for g_title, g_filter in groups:
            out.write(f"\n### {g_title}\n")
            out.write("-" * 80 + "\n")
            matching_cmds = [c for c in sorted(cmd_map.keys()) if g_filter(c)]
            for mc in matching_cmds:
                desc = KNOWN_DESCRIPTIONS.get(mc, "[CHƯA XÁC MINH]")
                out.write(f"  • CMD {mc:5d} ({cmd_map[mc]['hex']}): {desc}\n")

        out.write("\n" + "=" * 100 + "\n")
        out.write("PHẦN 3: CHI TIẾT SMALI BYTECODE TỪNG CMD QUAN TRỌNG\n")
        out.write("=" * 100 + "\n\n")

        important_cmds = [1, 2, 101, 102, 106, 113, 201, 202, 203, 204, 205, 206, 207, 208, 210, 212, 224, 225, 242, 245, 600, 601, 1701, 1703, 1705, 1708, 1715, 1752, 1785, 1786, 1787, 1860, 1865, 1867, 1971]

        for ic in important_cmds:
            if ic not in cmd_map: continue
            info = cmd_map[ic]
            desc = KNOWN_DESCRIPTIONS.get(ic, "[CHƯA XÁC MINH]")
            out.write(f"--------------------------------------------------------------------------------\n")
            out.write(f"CMD {ic} (Hex: {info['hex']}) — {desc}\n")
            out.write(f"--------------------------------------------------------------------------------\n")
            
            if info['c2s_methods']:
                out.write(f"  [C2S Builder]\n")
                for cm in info['c2s_methods'][:2]:
                    out.write(f"    File:   {cm['file']}:{cm['line']}\n")
                    out.write(f"    Method: {cm['method']}()\n")
                    out.write(f"    Context Snippet:\n")
                    for cl in cm['ctx'][:6]:
                        out.write(f"      {cl}\n")
            
            if info['s2c_handlers']:
                out.write(f"  [S2C Dispatcher]\n")
                for sh in info['s2c_handlers'][:2]:
                    out.write(f"    File:   {sh['file']}:{sh['line']}\n")
                    out.write(f"    Context Snippet:\n")
                    for cl in sh['ctx'][:6]:
                        out.write(f"      {cl}\n")
            
            if info['strings']:
                out.write(f"  [Resource / Action Strings]: {list(info['strings'])[:6]}\n")
            out.write("\n")

        out.write("=" * 100 + "\n")
        out.write("KẾT THÚC BẢNG ÁNH XẠ CMD MAP\n")
        out.write("=" * 100 + "\n")

    print(f"[✔] Đã xuất thành công file ánh xạ CMD: {OUT_FILE}")
    print(f"    Dung lượng: {os.path.getsize(OUT_FILE):,} bytes")

if __name__ == '__main__':
    main()
