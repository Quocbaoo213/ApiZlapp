/**
 * hook.js — Frida Script gửi tin nhắn Zalo trực tiếp qua Socket Native Socket (Zero Lag)
 * Đã loại bỏ hoàn toàn các hook native .so nặng gây giật lag.
 */

setImmediate(function () {
    Java.perform(function () {
        console.log("=================================================");
        console.log("🚀 [Zalo Frida Hook] Đã khởi tạo thành công (No-Lag)!");
        console.log("👉 Hàm gửi Group: sendGroupMsg(groupId, text)");
        console.log("👉 Ví dụ: sendGroupMsg(686355764, 'Hello Group!')");
        console.log("=================================================");

        const XK = [
            80, 49, 66, 76, 50, 71, 53, 73, 55, 78, 74, 68, 50, 72, 51, 74,
            65, 85, 68, 53, 53, 52, 71, 55, 54, 52, 53, 80, 72, 53, 52, 70
        ]; // "P1BL2G5I7NJD2H3JAUD554G7645PH54F"

        function buildGroupMsgParams(groupId, text, uid) {
            const propJson = '{"sSrcType":-1,"sSrcStr":"","msg_warning_type":0,"emoji":{"content":0,"num":0,"uniq":0,"first":"","last":"","most":"","text":1}}';
            const propBytes = Java.use("java.lang.String").$new(propJson).getBytes("UTF-8");
            const textBytes = Java.use("java.lang.String").$new(text).getBytes("UTF-8");

            // 1. D3 Plain: [0x01, 0x00, 0x01, 0x07, 0x00] [12B 0xff] [4B LE json_len] [json] [text]
            const d3Plain = [];
            d3Plain.push(0x01, 0x00, 0x01, 0x07, 0x00);
            for (let i = 0; i < 12; i++) d3Plain.push(0xff);

            const jLen = propBytes.length;
            d3Plain.push(jLen & 0xff, (jLen >> 8) & 0xff, (jLen >> 16) & 0xff, (jLen >> 24) & 0xff);
            for (let i = 0; i < propBytes.length; i++) d3Plain.push(propBytes[i]);
            for (let i = 0; i < textBytes.length; i++) d3Plain.push(textBytes[i]);

            // 2. XOR Stream Cipher với XK + (len + 36) + UID
            const a4 = d3Plain.length + 36;
            const le4 = [a4 & 0xff, (a4 >> 8) & 0xff, (a4 >> 16) & 0xff, (a4 >> 24) & 0xff];
            const ule = [uid & 0xff, (uid >> 8) & 0xff, (uid >> 16) & 0xff, (uid >> 24) & 0xff];

            const k = [];
            for (let i = 0; i < 32; i++) {
                k.push(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4]);
            }

            const d3Xor = [];
            for (let i = 0; i < d3Plain.length; i++) {
                d3Xor.push(d3Plain[i] ^ k[i % 32]);
            }

            // 3. Params: [4B target_id][1B 4][4B msg_id][4B flags=416][d3Xor]
            const msgId = (Date.now() & 0xffffffff);
            const flags = 416;

            const paramsArr = [];
            paramsArr.push(groupId & 0xff, (groupId >> 8) & 0xff, (groupId >> 16) & 0xff, (groupId >> 24) & 0xff);
            paramsArr.push(4); // target_type 4 = Group
            paramsArr.push(msgId & 0xff, (msgId >> 8) & 0xff, (msgId >> 16) & 0xff, (msgId >> 24) & 0xff);
            paramsArr.push(flags & 0xff, (flags >> 8) & 0xff, (flags >> 16) & 0xff, (flags >> 24) & 0xff);
            for (let i = 0; i < d3Xor.length; i++) {
                paramsArr.push(d3Xor[i]);
            }

            // Convert to Java signed byte array
            const signedArr = [];
            for (let i = 0; i < paramsArr.length; i++) {
                let v = paramsArr[i] & 0xff;
                if (v > 127) v = v - 256;
                signedArr.push(v);
            }
            return Java.array('byte', signedArr);
        }

        // Đăng ký hàm toàn cục để gọi từ Frida CLI hoặc script
        global.sendGroupMsg = function (groupId, text, uid) {
            uid = uid || 463450795;
            groupId = parseInt(groupId);
            console.log(`\n[*] 📤 Đang gửi tin nhắn vào Group ${groupId} (UID: ${uid}): "${text}"...`);

            Java.perform(function () {
                try {
                    const RequestPacket = Java.use("com.zing.zalocore.connection.socket.RequestPacket");
                    const params = buildGroupMsgParams(groupId, text, uid);

                    const pkt = RequestPacket.$new();
                    pkt.g.value = 207; // CMD 207
                    pkt.h.value = 1;   // SUB 1
                    pkt.d.value = -Math.floor(Math.random() * 1000 + 100); // SEQ
                    pkt.e.value = uid; // UID
                    pkt.f.value = 3;   // ver 3
                    pkt.b.value = 1;   // bb 1
                    pkt.c.value = 2;   // ty 2
                    pkt.params.value = params;
                    pkt.p.value = 15000; // timeout 15s

                    let sent = false;
                    Java.choose("com.zing.zalocore.connection.socket.NativeSocket", {
                        onMatch: function (ns) {
                            try {
                                ns.f(pkt, null);
                                console.log("[✔] Đã gửi gói tin CMD 207 qua NativeSocket đang kết nối!");
                                sent = true;
                            } catch (err) {
                                console.log("[!] Lỗi khi gọi NativeSocket.f: " + err);
                            }
                        },
                        onComplete: function () {
                            if (!sent) {
                                console.log("[!] Không tìm thấy instance NativeSocket đang chạy.");
                            }
                        }
                    });
                } catch (e) {
                    console.log("[!] Lỗi sendGroupMsg: " + e);
                }
            });
        };

        // Tự động gửi 1 tin nhắn thử nghiệm sau khi hook nạp 3 giây
        setTimeout(function () {
            try {
                global.sendGroupMsg(686355764, "Xin chào nhóm từ Frida Socket Hook!");
            } catch (e) {
                console.log("[!] Lỗi auto send: " + e);
            }
        }, 3000);
    });
});
