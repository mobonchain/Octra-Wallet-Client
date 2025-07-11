import base64, hashlib, base58, nacl.signing, requests, secrets, time, json, hmac, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mnemonic import Mnemonic
from colorama import Fore, Style, init

init(autoreset=True)

RPC_URL = "https://octra.network"
μ = 1_000_000

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_one_wallet():
    """Tạo một ví Octra mới với mnemonic"""
    mnemo = Mnemonic("english")
    mnemonic = mnemo.generate(strength=128)
    seed = mnemo.to_seed(mnemonic)

    master_key = hmac.new(b'Octra seed', seed, hashlib.sha512).digest()
    priv_key = master_key[:32]

    signing_key = nacl.signing.SigningKey(priv_key)
    verify_key = signing_key.verify_key
    pubkey_bytes = verify_key.encode()

    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    octra_addr = "oct" + base58.b58encode(sha256_hash).decode()

    return {
        'mnemonic': mnemonic,
        'rpc': RPC_URL,
        'addr': octra_addr,
        'priv': base64.b64encode(priv_key).decode(),
        'pub': pubkey_bytes.hex(),
        'signing_key': signing_key,
        'pub_b64': base64.b64encode(pubkey_bytes).decode(),
        'priv_b64': base64.b64encode(signing_key.encode()).decode(),
        'address': octra_addr
    }

def create_new_wallet():
    """Interface để tạo 1 ví mới"""
    clear_screen()
    print(Fore.CYAN + "=== TẠO VÍ MỚI ===")
    
    try:
        with open("wallets.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        existing_wallets = data.get("wallets", [])
        default_wallet = data.get("default_wallet", "")
    except:
        existing_wallets = []
        default_wallet = ""

    wallet_counter = 1
    for wallet in existing_wallets:
        name = wallet.get("name", "")
        if "Ví" in name:
            try:
                num = int(name.split()[-1])
                wallet_counter = max(wallet_counter, num + 1)
            except:
                pass

    wallet = generate_one_wallet()
    
    default_name = f'Ví {wallet_counter}'
    wallet_name = input(Fore.YELLOW + f"Nhập tên cho ví (mặc định '{default_name}'): ").strip()
    if not wallet_name:
        wallet_name = default_name
    
    new_wallet = {
        'name': wallet_name,
        'addr': wallet['addr'],
        'priv': wallet['priv'],
        'pub': wallet['pub'],
        'mnemonic': wallet['mnemonic']
    }
    
    existing_wallets.append(new_wallet)
    
    if not default_wallet:
        default_wallet = wallet_name

    print(Fore.GREEN + f"\n=== {wallet_name} ===")
    print(Fore.CYAN + "Mnemonic:", Style.RESET_ALL + wallet['mnemonic'])
    print(Fore.MAGENTA + "Private Key (base64):", Style.RESET_ALL + wallet['priv'])
    print(Fore.BLUE + "Public Key (hex):", Style.RESET_ALL + wallet['pub'])
    print(Fore.YELLOW + "Địa chỉ ví:", Style.BRIGHT + wallet['addr'])
    print(Fore.WHITE + '-' * 50)

    updated_data = {
        "wallets": existing_wallets,
        "default_wallet": default_wallet
    }
    
    with open("wallets.json", "w", encoding="utf-8") as f:
        json.dump(updated_data, f, indent=2, ensure_ascii=False)
    
    print(Fore.GREEN + "\n✅ Đã tạo ví mới thành công!")
    print(Fore.GREEN + "📁 Đã lưu vào 'wallets.json'")
    print(Fore.CYAN + "🔒 Hãy lưu Mnemonic & Private Key AN TOÀN!")

def derive_encryption_key(priv_b64):
    priv_bytes = base64.b64decode(priv_b64)
    salt = b"octra_encrypted_balance_v2"
    return hashlib.sha256(salt + priv_bytes).digest()[:32]

def encrypt_client_balance(balance_raw, priv_b64):
    key = derive_encryption_key(priv_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    plaintext = str(balance_raw).encode()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return "v2|" + base64.b64encode(nonce + ciphertext).decode()

def login_wallet(priv_b64):
    try:
        secret_key_bytes = base64.b64decode(priv_b64.strip())
    except Exception:
        priv_b64 = priv_b64.strip()
        missing_padding = len(priv_b64) % 4
        if missing_padding:
            priv_b64 += '=' * (4 - missing_padding)
        secret_key_bytes = base64.b64decode(priv_b64)
    
    if len(secret_key_bytes) == 64:
        signing_key = nacl.signing.SigningKey(secret_key_bytes[:32])
    elif len(secret_key_bytes) == 32:
        signing_key = nacl.signing.SigningKey(secret_key_bytes)
    else:
        raise ValueError(f"Invalid private key length: {len(secret_key_bytes)} bytes")
    
    pubkey_bytes = signing_key.verify_key.encode()
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    octra_addr = "oct" + base58.b58encode(sha256_hash).decode()
    return {
        'signing_key': signing_key,
        'pub_b64': base64.b64encode(pubkey_bytes).decode(),
        'priv_b64': base64.b64encode(signing_key.encode()).decode(),
        'address': octra_addr
    }

def load_wallets_from_file():
    """Load wallets from wallets.json file"""
    try:
        with open("wallets.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("wallets", []), data.get("default_wallet", "")
    except FileNotFoundError:
        print(Fore.YELLOW + "⚠️  Không tìm thấy file wallets.json")
        return [], ""
    except Exception as e:
        print(Fore.RED + f"❌ Lỗi đọc file wallets.json: {e}")
        return [], ""

def get_wallet_name_by_address(address):
    """Lấy tên ví từ địa chỉ"""
    try:
        with open("wallets.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        wallets = data.get("wallets", [])
        for wallet in wallets:
            if wallet.get('addr') == address:
                return wallet.get('name', 'Unknown')
        return 'Unknown'
    except:
        return 'Unknown'

def select_wallet_from_file():
    """Select a wallet from wallets.json"""
    clear_screen()
    wallets, default_wallet = load_wallets_from_file()
    if not wallets:
        print(Fore.RED + "Không có ví nào trong file wallets.json!")
        return None
    
    print(Fore.CYAN + "DANH SÁCH VÍ CÓ SẴN:")
    print(Fore.WHITE + "=" * 60)
    for i, wallet in enumerate(wallets):
        name = wallet.get('name', 'Unnamed')
        addr_short = wallet['addr'][:15] + "..." if len(wallet['addr']) > 15 else wallet['addr']
        default_mark = Fore.GREEN + " (Default)" if name == default_wallet else ""
        mnemonic_mark = Fore.CYAN + " [M]" if wallet.get('mnemonic') else Fore.YELLOW + " [I]"
        print(f"{Fore.WHITE}[{i+1}] {Fore.YELLOW}{name}{default_mark}{mnemonic_mark} {Fore.WHITE}- {addr_short}")
    
    print(f"{Fore.WHITE}[0] {Fore.RED}Quay lại")
    print(Fore.WHITE + "=" * 60)
    print(Fore.CYAN + "Chú thích: [M] = Có Mnemonic, [I] = Import")
    
    try:
        choice = input(Fore.YELLOW + "Chọn ví (số): ").strip()
        if choice == "0":
            return None
        choice = int(choice) - 1
        if 0 <= choice < len(wallets):
            selected = wallets[choice]
            return login_wallet(selected['priv'])
        else:
            print(Fore.RED + "❌ Lựa chọn không hợp lệ!")
            return None
    except ValueError:
        print(Fore.RED + "❌ Vui lòng nhập số!")
        return None

def switch_wallet(current_wallet):
    """Switch to a different wallet during runtime"""
    clear_screen()
    print(Fore.CYAN + "=== CHUYỂN ĐỔI VÍ ===")
    wallets, default_wallet = load_wallets_from_file()
    if not wallets:
        print(Fore.RED + "Không có ví nào trong file!")
        return current_wallet
    
    print(Fore.CYAN + "DANH SÁCH VÍ:")
    print(Fore.WHITE + "=" * 60)
    current_addr = current_wallet['address']
    for i, wallet in enumerate(wallets):
        name = wallet.get('name', 'Unnamed')
        addr_short = wallet['addr'][:15] + "..." if len(wallet['addr']) > 15 else wallet['addr']
        current_mark = Fore.GREEN + " (Hiện tại)" if wallet['addr'] == current_addr else ""
        default_mark = Fore.BLUE + " (Default)" if name == default_wallet else ""
        mnemonic_mark = Fore.CYAN + " [M]" if wallet.get('mnemonic') else Fore.YELLOW + " [I]"
        print(f"{Fore.WHITE}[{i+1}] {Fore.YELLOW}{name}{current_mark}{default_mark}{mnemonic_mark} {Fore.WHITE}- {addr_short}")
    
    print(f"{Fore.WHITE}[0] {Fore.RED}Hủy")
    print(Fore.WHITE + "=" * 60)
    
    try:
        choice = input(Fore.YELLOW + "Chọn ví để chuyển đổi: ").strip()
        if choice == "0":
            return current_wallet
        choice = int(choice) - 1
        if 0 <= choice < len(wallets):
            selected = wallets[choice]
            if selected['addr'] == current_addr:
                print(Fore.YELLOW + "⚠️  Bạn đang sử dụng ví này rồi!")
                input(Fore.CYAN + "Nhấn Enter để tiếp tục...")
                return current_wallet
            new_wallet = login_wallet(selected['priv'])
            print(Fore.GREEN + f"✅ Đã chuyển sang ví: {selected.get('name', 'Unnamed')}")
            print(Fore.GREEN + f"📍 Địa chỉ: {new_wallet['address']}")
            input(Fore.CYAN + "Nhấn Enter để tiếp tục...")
            return new_wallet
        else:
            print(Fore.RED + "❌ Lựa chọn không hợp lệ!")
            return current_wallet
    except ValueError:
        print(Fore.RED + "❌ Vui lòng nhập số!")
        return current_wallet

def get_balance(addr):
    r = requests.get(f"{RPC_URL}/balance/{addr}", timeout=10)
    if r.status_code == 200:
        data = r.json()
        return float(data.get('balance', 0)), int(data.get('nonce', 0))
    return 0.0, 0

def get_encrypted_balance(wallet):
    hdr = {"X-Private-Key": wallet['priv_b64']}
    r = requests.get(f"{RPC_URL}/view_encrypted_balance/{wallet['address']}", headers=hdr)
    if r.status_code==200:
        j = r.json()
        return int(j.get("encrypted_balance_raw",0))
    return 0

def get_pending_transfers(wallet):
    hdr = {"X-Private-Key": wallet['priv_b64']}
    r = requests.get(f"{RPC_URL}/pending_private_transfers?address={wallet['address']}", headers=hdr)
    if r.status_code==200:
        return r.json().get("pending_transfers",[])
    return []

def send_tx(wallet, to_addr, amount, nonce):
    tx = {
        "from": wallet['address'],
        "to_": to_addr,
        "amount": str(int(amount * μ)),
        "nonce": nonce,
        "ou": "1" if amount < 1000 else "3",
        "timestamp": time.time()
    }
    bl = '{' + f'"from":"{tx["from"]}","to_":"{tx["to_"]}","amount":"{tx["amount"]}","nonce":{tx["nonce"]},"ou":"{tx["ou"]}","timestamp":{tx["timestamp"]}' + '}'
    sig = base64.b64encode(wallet['signing_key'].sign(bl.encode()).signature).decode()
    tx['signature'] = sig
    tx['public_key'] = wallet['pub_b64']
    r = requests.post(f"{RPC_URL}/send-tx", json=tx)
    
    if r.status_code == 200:
        try:
            data = r.json()
            print(Fore.GREEN + f"✅ Status: {data.get('status')}")
            print(Fore.YELLOW + f"🔑 TX Hash: {data.get('tx_hash')}")
            print(Fore.CYAN + f"✔️ Nonce accepted: {data.get('nonce_accepted')}")
            print(Fore.MAGENTA + f"💸 Cost (ou_cost): {data.get('ou_cost')} OCT")
            if data.get("pool_info"):
                pending = data['pool_info'].get("pending_from_sender", 0)
                total_pool = data['pool_info'].get("total_pool_size", 0)
                print(Fore.BLUE + f"📌 Pending from sender: {pending}")
                print(Fore.BLUE + f"🌐 Total pool size: {total_pool}")
            print(Fore.GREEN + "🚀 Transaction committed to staging!")
        except Exception as e:
            print(Fore.RED + f"❌ Response parse error: {e}")
    else:
        print(Fore.RED + f"❌ Transaction failed! HTTP {r.status_code} | {r.text}")

def encrypt_balance(wallet):
    b, _ = get_balance(wallet['address'])
    enc = get_encrypted_balance(wallet)
    print(f"Số dư công khai: {b} | Đã encrypt: {enc/μ}")
    amt = float(input("Nhập số OCT muốn Encrypt: "))
    new_enc = enc + int(amt*μ)
    enc_data = encrypt_client_balance(new_enc, wallet['priv_b64'])
    payload = {
        "address": wallet['address'],
        "amount": str(int(amt*μ)),
        "private_key": wallet['priv_b64'],
        "encrypted_data": enc_data
    }
    r = requests.post(f"{RPC_URL}/encrypt_balance", json=payload)
    print(Fore.GREEN + "✅ Encrypt thành công!" if r.status_code==200 else Fore.RED + f"❌ {r.text}")

def decrypt_balance(wallet):
    enc = get_encrypted_balance(wallet)
    print(f"Số dư encrypted hiện tại: {enc/μ}")
    amt = float(input("Nhập số OCT muốn Decrypt: "))
    if amt*μ > enc:
        print(Fore.RED + "❌ Không đủ encrypted balance!")
        return
    new_enc = enc - int(amt*μ)
    enc_data = encrypt_client_balance(new_enc, wallet['priv_b64'])
    payload = {
        "address": wallet['address'],
        "amount": str(int(amt*μ)),
        "private_key": wallet['priv_b64'],
        "encrypted_data": enc_data
    }
    r = requests.post(f"{RPC_URL}/decrypt_balance", json=payload)
    print(Fore.GREEN + "✅ Decrypt thành công!" if r.status_code==200 else Fore.RED + f"❌ {r.text}")

def multi_send(wallet):
    recipients = []
    print(Fore.CYAN + "\n=== MULTI-SEND ===")
    print(Fore.YELLOW + "Nhập mỗi dòng: [oct_address] [amount]. Enter để kết thúc.")
    while True:
        line = input(Fore.WHITE + "> ").strip()
        if not line: break
        parts = line.split()
        if len(parts)==2: 
            try:
                recipients.append((parts[0], float(parts[1])))
                print(Fore.GREEN + f"✅ Đã thêm: {parts[0][:20]}... - {parts[1]} OCT")
            except ValueError:
                print(Fore.RED + "❌ Số lượng không hợp lệ.")
                continue
        else:
            print(Fore.RED + "❌ Format không hợp lệ. Dòng phải là: address amount")
            continue
    
    if not recipients:
        print(Fore.RED + "❌ Không có ví nhận nào!")
        return
        
    b, n = get_balance(wallet['address'])
    total_amount = sum(a for _, a in recipients)
    
    print(Fore.GREEN + f"\n📤 Ví GỬI: {wallet['address']}")
    print(Fore.BLUE + f"📋 Tổng số ví nhận: {len(recipients)}")
    print(Fore.MAGENTA + f"💸 Tổng số lượng sẽ gửi: {total_amount} OCT")
    print(Fore.CYAN + f"💰 Số dư: {b} OCT | Nonce hiện tại: {n}")
    
    if total_amount > b:
        print(Fore.RED + "❌ Không đủ số dư.")
        return
        
    confirm = input(Fore.YELLOW + "Xác nhận gửi? (y/n): ").strip().lower()
    if confirm != 'y':
        print(Fore.YELLOW + "⚠️  Đã hủy multi-send.")
        return
        
    for idx, (to, a) in enumerate(recipients, start=1):
        print(Fore.YELLOW + f"\n[{idx}/{len(recipients)}] Gửi {a} OCT đến {to[:20]}...")
        send_tx(wallet, to, a, n + idx)
        time.sleep(0.5)

def private_transfer(wallet):
    to = input("Địa chỉ nhận: ").strip()
    amt = float(input("Số OCT: "))
    pk_res = requests.get(f"{RPC_URL}/public_key/{to}")
    if pk_res.status_code != 200:
        print(Fore.RED + "❌ Không có public key người nhận.")
        return
    to_pub = pk_res.json().get("public_key")
    data = {
        "from": wallet['address'],
        "to": to,
        "amount": str(int(amt*μ)),
        "from_private_key": wallet['priv_b64'],
        "to_public_key": to_pub
    }
    r = requests.post(f"{RPC_URL}/private_transfer", json=data)
    print(Fore.GREEN + "✅ Private Transfer OK!" if r.status_code==200 else Fore.RED + f"❌ {r.text}")

def claim_transfers(wallet):
    transfers = get_pending_transfers(wallet)
    if not transfers:
        print(Fore.YELLOW + "Không có transfer nào.")
        return
    for i,t in enumerate(transfers): print(f"[{i+1}] ID {t['id']} Sender {t['sender']}")
    idx = int(input("Chọn số để claim: "))-1
    tid = transfers[idx]['id']
    payload = {
        "recipient_address": wallet['address'],
        "private_key": wallet['priv_b64'],
        "transfer_id": tid
    }
    c = requests.post(f"{RPC_URL}/claim_private_transfer", json=payload)
    print(Fore.GREEN + "✅ Claim OK!" if c.status_code==200 else Fore.RED + f"❌ {c.text}")

def check_overview(wallet):
    print(Fore.CYAN + f"📄 Địa chỉ: {wallet['address']}")
    b,_ = get_balance(wallet['address'])
    print(f"💰 Số dư Public: {b} OCT")
    enc = get_encrypted_balance(wallet)
    print(f"🔒 Số dư Encrypted: {enc/μ} OCT")
    transfers = get_pending_transfers(wallet)
    if not transfers:
        print(Fore.YELLOW + "✅ Không có Private Transfers chờ claim.")
    else:
        print(Fore.GREEN + "🔑 Private Transfers chưa claim:")
        for t in transfers:
            print(f"  - ID {t['id']} Sender: {t['sender']} Epoch: {t['epoch_id']}")

def main():
    clear_screen()
    print(Fore.CYAN + Style.BRIGHT + "╔════════════════════════════════════════╗")
    print(Fore.CYAN + Style.BRIGHT + "║      OCTRA WALLET ALL-IN-ONE TOOL      ║")
    print(Fore.CYAN + Style.BRIGHT + "╚════════════════════════════════════════╝")
    print(Fore.YELLOW + "[1] Chọn ví từ file wallets.json")
    print(Fore.YELLOW + "[2] Import ví bằng Private Key") 
    print(Fore.YELLOW + "[3] Tạo ví mới")
    print(Fore.RED + "[0] Thoát")
    print(Fore.WHITE + "=" * 42)
    
    choice = input(Fore.CYAN + "Chọn: ").strip()
    
    if choice == '3':
        create_new_wallet()
        input(Fore.CYAN + "\nNhấn Enter để tiếp tục...")
        main()
        return
    elif choice == '0':
        print(Fore.GREEN + "👋 Tạm biệt!")
        return
    elif choice == '2':
        wallet = import_wallet_by_private_key()
        if wallet is None:
            input(Fore.CYAN + "\nNhấn Enter để tiếp tục...")
            main()
            return
    elif choice == '1':
        wallet = select_wallet_from_file()
        if wallet is None:
            input(Fore.CYAN + "\nNhấn Enter để tiếp tục...")
            main()
            return
    else:
        print(Fore.RED + "❌ Lựa chọn không hợp lệ!")
        input(Fore.CYAN + "\nNhấn Enter để tiếp tục...")
        main()
        return
    
    clear_screen()
    print(Fore.GREEN + f"✅ Đăng nhập thành công!")
    current_wallet_name = get_wallet_name_by_address(wallet['address'])
    print(Fore.GREEN + f"📍 Ví: {current_wallet_name}")
    print(Fore.GREEN + f"📍 Địa chỉ: {wallet['address']}")
    
    while True:
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.CYAN + f"📍 VÍ HIỆN TẠI: {Fore.YELLOW}{current_wallet_name}")
        print(Fore.CYAN + f"📍 ĐỊA CHỈ: {Fore.WHITE}{wallet['address'][:30]}...")
        print(Fore.CYAN + "="*60)
        print(Fore.CYAN + "[1] Kiểm tra tổng quan")
        print(Fore.CYAN + "[2] Gửi TX") 
        print(Fore.CYAN + "[3] Multi-send")
        print(Fore.CYAN + "[4] Encrypt Balance")
        print(Fore.CYAN + "[5] Decrypt Balance")
        print(Fore.CYAN + "[6] Private Transfer")
        print(Fore.CYAN + "[7] Claim Private Transfer")
        print(Fore.CYAN + "[8] Export thông tin")
        print(Fore.YELLOW + "[9] Tạo ví mới")
        print(Fore.MAGENTA + "[10] Chuyển đổi ví")
        print(Fore.MAGENTA + "[11] Import ví mới")
        print(Fore.GREEN + "[12] Clear màn hình")
        print(Fore.RED + "[0] Quay lại menu chính")
        print(Fore.CYAN + "="*60)
        
        cmd = input(Fore.YELLOW + "Chọn chức năng: ").strip()
        try:
            if cmd == '1': 
                check_overview(wallet)
            elif cmd == '2':
                b,n = get_balance(wallet['address'])
                print(Fore.CYAN + f"💰 Số dư hiện tại: {Fore.GREEN}{b} OCT")
                to = input(Fore.YELLOW + "Địa chỉ nhận: ").strip()
                if not to:
                    print(Fore.RED + "❌ Địa chỉ không được để trống!")
                    continue
                try:
                    amt = float(input(Fore.YELLOW + "Số OCT: "))
                    send_tx(wallet,to,amt,n+1)
                except ValueError:
                    print(Fore.RED + "❌ Số lượng không hợp lệ!")
            elif cmd=='3': 
                multi_send(wallet)
            elif cmd=='4': 
                encrypt_balance(wallet)
            elif cmd=='5': 
                decrypt_balance(wallet)
            elif cmd=='6': 
                private_transfer(wallet)
            elif cmd=='7': 
                claim_transfers(wallet)
            elif cmd=='8':
                print(Fore.MAGENTA + "\n=== THÔNG TIN VÍ ===")
                print(Fore.CYAN + "Private Key:", Style.RESET_ALL + wallet['priv_b64'])
                print(Fore.CYAN + "Public Key:", Style.RESET_ALL + wallet['pub_b64'])
                print(Fore.CYAN + "Address:", Style.RESET_ALL + wallet['address'])
            elif cmd=='9': 
                create_new_wallet()
            elif cmd=='10':
                new_wallet = switch_wallet(wallet)
                if new_wallet != wallet:
                    wallet = new_wallet
                    current_wallet_name = get_wallet_name_by_address(wallet['address'])
            elif cmd=='11':
                new_wallet = import_wallet_by_private_key()
                if new_wallet:
                    wallet = new_wallet
                    current_wallet_name = get_wallet_name_by_address(wallet['address'])
            elif cmd=='12':
                clear_screen()
                print(Fore.GREEN + "✨ Đã clear màn hình!")
            elif cmd=='0': 
                break
            else:
                print(Fore.RED + "❌ Lựa chọn không hợp lệ!")
        except Exception as e:
            print(Fore.RED + f"❌ Lỗi: {e}")
            
    main()

def import_wallet_by_private_key():
    """Import wallet bằng private key"""
    clear_screen()
    print(Fore.CYAN + "=== IMPORT VÍ BẰNG PRIVATE KEY ===")
    
    while True:
        print(Fore.YELLOW + "\nNhập Private Key (Base64):")
        priv_key = input(Fore.WHITE + "> ").strip()
        
        if not priv_key:
            print(Fore.RED + "❌ Private key không được để trống!")
            continue
            
        try:
            test_wallet = login_wallet(priv_key)
            break
        except Exception as e:
            print(Fore.RED + f"❌ Private key không hợp lệ: {e}")
            retry = input(Fore.YELLOW + "Thử lại? (y/n): ").strip().lower()
            if retry != 'y':
                return None
    
    wallet_name = input(Fore.YELLOW + "Nhập tên cho ví này: ").strip()
    if not wallet_name:
        wallet_name = f"Ví Import {int(time.time())}"
    
    try:
        with open("wallets.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        existing_wallets = data.get("wallets", [])
        default_wallet = data.get("default_wallet", "")
    except:
        existing_wallets = []
        default_wallet = ""
    
    for wallet in existing_wallets:
        if wallet['addr'] == test_wallet['address']:
            print(Fore.YELLOW + f"⚠️  Ví này đã tồn tại với tên: {wallet['name']}")
            return test_wallet
    
    new_wallet = {
        'name': wallet_name,
        'addr': test_wallet['address'],
        'priv': priv_key,
        'pub': test_wallet['pub_b64'],
        'mnemonic': None
    }
    
    existing_wallets.append(new_wallet)
    
    if not default_wallet:
        default_wallet = wallet_name
    
    updated_data = {
        "wallets": existing_wallets,
        "default_wallet": default_wallet
    }
    
    with open("wallets.json", "w", encoding="utf-8") as f:
        json.dump(updated_data, f, indent=2, ensure_ascii=False)
    
    print(Fore.GREEN + f"\n✅ Đã import ví '{wallet_name}' thành công!")
    print(Fore.GREEN + f"📍 Địa chỉ: {test_wallet['address']}")
    print(Fore.GREEN + f"📁 Đã lưu vào 'wallets.json'")
    print(Fore.YELLOW + f"ℹ️  Lưu ý: Ví import không có mnemonic")
    
    return test_wallet

if __name__ == '__main__':
    main()
