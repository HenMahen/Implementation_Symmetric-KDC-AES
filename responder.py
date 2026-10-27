import socket
import json
import os
import threading

# Tabel S-Box AES
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Tabel Rcon
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def sub_word(w): return [SBOX[b] for b in w]
def rot_word(w): return w[1:] + w[:1]

def key_expansion(key_bytes):
    words = [list(key_bytes[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i-1]
        if i % 4 == 0:
            temp = [b ^ r for b, r in zip(sub_word(rot_word(temp)), [RCON[i//4], 0, 0, 0])]
        words.append([b ^ c for b, c in zip(words[i-4], temp)])
    return words

def add_round_key(state, round_key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[c][r]

def sub_bytes(state):
    for r in range(4):
        for c in range(4): state[r][c] = SBOX[state[r][c]]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4): state[r][c] = INV_SBOX[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return p

def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        state[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        state[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        state[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)

def inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0], 0x0e) ^ gmul(col[1], 0x0b) ^ gmul(col[2], 0x0d) ^ gmul(col[3], 0x09)
        state[1][c] = gmul(col[0], 0x09) ^ gmul(col[1], 0x0e) ^ gmul(col[2], 0x0b) ^ gmul(col[3], 0x0d)
        state[2][c] = gmul(col[0], 0x0d) ^ gmul(col[1], 0x09) ^ gmul(col[2], 0x0e) ^ gmul(col[3], 0x0b)
        state[3][c] = gmul(col[0], 0x0b) ^ gmul(col[1], 0x0d) ^ gmul(col[2], 0x09) ^ gmul(col[3], 0x0e)

def aes_encrypt_block(block, round_keys):
    state = [[block[i + 4*j] for j in range(4)] for i in range(4)]
    add_round_key(state, round_keys[0:4])
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r*4:(r+1)*4])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[40:44])
    out = [0]*16
    for r in range(4):
        for c in range(4): out[r + 4*c] = state[r][c]
    return bytes(out)

def aes_decrypt_block(block, round_keys):
    state = [[block[i + 4*j] for j in range(4)] for i in range(4)]
    add_round_key(state, round_keys[40:44])
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r*4:(r+1)*4])
        inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0:4])
    out = [0]*16
    for r in range(4):
        for c in range(4): out[r + 4*c] = state[r][c]
    return bytes(out)

def aes_encrypt_cbc(key, plaintext_bytes):
    pad_len = 16 - (len(plaintext_bytes) % 16)
    padded = plaintext_bytes + bytes([pad_len]*pad_len)
    iv = os.urandom(16)
    round_keys = key_expansion(key)
    ciphertext = bytearray(iv)
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes([b ^ p for b, p in zip(padded[i:i+16], prev)])
        enc_block = aes_encrypt_block(block, round_keys)
        ciphertext.extend(enc_block)
        prev = enc_block
    return bytes(ciphertext)

def aes_decrypt_cbc(key, ciphertext_bytes):
    if len(ciphertext_bytes) < 32 or len(ciphertext_bytes) % 16 != 0:
        raise ValueError("Panjang ciphertext tidak valid.")
    iv = ciphertext_bytes[:16]
    ct = ciphertext_bytes[16:]
    round_keys = key_expansion(key)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        dec_block = aes_decrypt_block(block, round_keys)
        pt_block = bytes([b ^ p for b, p in zip(dec_block, prev)])
        plaintext.extend(pt_block)
        prev = block
    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > 16 or plaintext[-pad_len:] != bytes([pad_len]*pad_len):
        raise ValueError("Invalid PKCS#7 Padding. Key mungkin salah!")
    return bytes(plaintext[:-pad_len])

def f(n2):
    return n2 - 1

def format_key(key_str):
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) < 16:
        return key_bytes.ljust(16, b'0')
    return key_bytes[:16]

def receive_messages(conn, ks, stop_event):
    buffer = ""
    while not stop_event.is_set():
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data:
                print("\n[Chat] Alice terputus.")
                break
            buffer += data
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    decrypted_bytes = aes_decrypt_cbc(ks, bytes.fromhex(line))
                    message = decrypted_bytes.decode('utf-8')
                    print(f"\n[Alice (Hex)]      : {line}")
                    print(f"[Alice (Decrypted)]: {message}")
                    print("Bob > ", end="", flush=True)
                except Exception as err:
                    print(f"\n[Error Dekripsi] Data korup / key salah: {err}")
                    print("Bob > ", end="", flush=True)
        except Exception:
            break

# Wadah Master Key Bob
CURRENT_KB = {}

def handle_alice_connection(conn, addr):
    KB = CURRENT_KB.get("Bob")
    print(f"\n[Bob] Terhubung dengan {addr[0]}")
    try:
        # Langkah 3: Terima tiket dari Alice
        ticket_hex = conn.recv(4096).decode('utf-8').strip()
        ticket_bytes = bytes.fromhex(ticket_hex)
        ticket_decrypted = json.loads(aes_decrypt_cbc(KB, ticket_bytes).decode('utf-8'))

        ks_ascii = ticket_decrypted['ks']
        ks = ks_ascii.encode('ascii')
        id_a = ticket_decrypted['id_a']

        print(f"[Bob] Tiket dari '{id_a}' berhasil diverifikasi.")
        print(f"  [+] Session Key Ks (ASCII) : {ks_ascii}")
        print(f"  [+] Session Key Ks (Hex)   : {ks.hex()}")

        # Langkah 4: Kirim tantangan Nonce N2 terenkripsi Ks ke Alice
        n2 = int.from_bytes(os.urandom(4), 'big')
        print(f"[Langkah 4] Mengirim tantangan N2 ({n2}) ke Alice...")
        msg4_enc = aes_encrypt_cbc(ks, json.dumps({'n2': n2}).encode('utf-8'))
        conn.send((msg4_enc.hex() + "\n").encode('utf-8'))

        # Langkah 5: Terima balasan f(N2) dari Alice
        msg5_hex = conn.recv(4096).decode('utf-8').strip()
        msg5_dec = json.loads(aes_decrypt_cbc(ks, bytes.fromhex(msg5_hex)).decode('utf-8'))

        if msg5_dec.get('fn2') == f(n2):
            print("\n" + "="*50)
            print("  [BOB] OTENTIKASI BERHASIL! SESSION TERJALIN")
            print("="*50)
        else:
            print("[Bob Error] Nilai f(N2) salah! Otentikasi ditolak.")
            conn.close()
            return
    except Exception as e:
        print(f"[Bob Error] Gagal memverifikasi tiket/otentikasi: {e}")
        conn.close()
        return

    print("Ketik pesan Anda lalu tekan ENTER.")
    print("Ketik '/exit' untuk mengakhiri sesi chat.\n")

    stop_event = threading.Event()
    recv_thread = threading.Thread(target=receive_messages, args=(conn, ks, stop_event), daemon=True)
    recv_thread.start()

    while True:
        try:
            msg = input("Bob > ")
            if msg.strip().lower() == '/exit':
                break
            if not msg.strip():
                continue
            enc_msg = aes_encrypt_cbc(ks, msg.encode('utf-8'))
            conn.send((enc_msg.hex() + "\n").encode('utf-8'))
            print(f"  └─ Sent (Hex): {enc_msg.hex()}")
        except KeyboardInterrupt:
            break

    stop_event.set()
    conn.close()
    print("\n[Bob] Sesi chat selesai. Kembali menunggu koneksi berikutnya...\n")

def main():
    print("="*50)
    print("        RESPONDER ENTITY (BOB) ")
    print("="*50)
    kb_str = input("Masukkan Master Key B (ASCII, 16 karakter): ").strip()
    CURRENT_KB["Bob"] = format_key(kb_str)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 8002))
    server.listen(5)
    print(f"\n[Bob] Server aktif di port 8002. Master Key KB: '{CURRENT_KB['Bob'].decode('utf-8')}'")
    print("Menunggu Alice menghubungi (Tekan Ctrl+C untuk ubah key / menu)...")

    while True:
        try:
            conn, addr = server.accept()
            handle_alice_connection(conn, addr)
            print("[Bob] Menunggu koneksi berikutnya di port 8002...")
        except KeyboardInterrupt:
            print("\n" + "-"*40)
            print("[1] Lanjutkan Menunggu Koneksi")
            print("[2] Ubah Master Key KB (Tanpa Restart)")
            print("[3] Keluar")
            pil = input("Pilih menu [1-3]: ").strip()
            if pil == '2':
                baru = input("Masukkan Master Key B baru: ").strip()
                if baru:
                    CURRENT_KB["Bob"] = format_key(baru)
                    print(f"[Sukses] Master Key KB diubah menjadi: '{CURRENT_KB['Bob'].decode('utf-8')}'")
            elif pil == '3':
                print("Keluar dari program Bob.")
                break
            print("\n[Bob] Kembali mendengarkan koneksi di port 8002...")

if __name__ == '__main__':
    main()