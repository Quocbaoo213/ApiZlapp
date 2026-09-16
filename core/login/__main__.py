import sys
import getpass
import argparse
import logging
from core.login.password import PasswordAuth
from core.login.session import save_session_file, read_from_zaloprefs
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def main():
    parser = argparse.ArgumentParser(prog='python3 -m core.login', description='Zalo Mobile Login CLI v10 (Auto-Captcha + 2FA / Friend Verify + PROV Authen Probe)')
    parser.add_argument('phone', nargs='?', default='', help='Số điện thoại Zalo (VD: 0993903236 hoặc +84993903236)')
    parser.add_argument('password', nargs='?', default='', help='Mật khẩu tài khoản Zalo')
    parser.add_argument('-u', '--phone-opt', dest='opt_phone', default='', help='Số điện thoại Zalo')
    parser.add_argument('-p', '--password-opt', dest='opt_password', default='', help='Mật khẩu tài khoản Zalo')
    parser.add_argument('-o', '--out', default='fresh_session.json', help='Đường dẫn lưu session JSON (mặc định: fresh_session.json)')
    parser.add_argument('--zcid', default=None, help='Chỉ định ZCID 96-hex cụ thể (ghi đè)')
    parser.add_argument('--renew-zcid', action='store_true', help='Bắt buộc sinh ZCID 96-hex mới')
    parser.add_argument('--zcid-path', default='zcid_trusted.txt', help='Đường dẫn file lưu ZCID (mặc định: zcid_trusted.txt)')
    parser.add_argument('--zaloprefs', default=None, help='Đường dẫn file zaloprefs SQLite để đọc DK/KSID offline')
    parser.add_argument('--uid', default=None, help='User ID (UID) của tài khoản khi dùng với --zaloprefs')
    parser.add_argument('--real-friends', default='', help='Danh sách tên bạn bè thật gần đây (cách nhau bởi dấu phẩy) để auto-match')
    parser.add_argument('--no-probe', action='store_true', help='Bỏ qua bước thử nghiệm Socket PROV Handshake')
    args = parser.parse_args()
    phone = args.phone or args.opt_phone
    if not phone:
        phone = input('SDT: ').strip()
    password = args.password or args.opt_password
    if not password:
        password = getpass.getpass('Password: ').strip()
    if not phone or not password:
        print('Lỗi: Số điện thoại và mật khẩu không được để trống.')
        sys.exit(1)
    real_friends = [f.strip() for f in args.real_friends.split(',') if f.strip()] if args.real_friends else None
    auth = PasswordAuth(zcid=args.zcid, zcid_path=args.zcid_path, renew_zcid=args.renew_zcid)
    try:
        session = auth.authenticate(phone=phone, password=password, real_friends=real_friends, out_session_path=args.out, zaloprefs_path=args.zaloprefs, target_uid=args.uid, probe_socket=not args.no_probe)
        print('\n' + '=' * 50)
        print('Dang nhap thanh cong')
        print(f"  User ID (UID) : {session.get('uid')}")
        print(f"  KeySetId      : {session.get('ksid')}")
        print(f"  Socket Servers: {len(session.get('socketServers', []))} máy chủ")
        print(f'  File Session  : {args.out}')
        print('=' * 50 + '\n')
    except PermissionError as pe:
        print(f'\nYêu cầu xác thực bổ sung: {pe}')
        sys.exit(2)
    except ValueError as ve:
        print(f'\nLỗi xác thực: {ve}')
        sys.exit(3)
    except Exception as ex:
        print(f'\nLỗi khi đăng nhập: {ex}')
        sys.exit(1)
if __name__ == '__main__':
    main()
