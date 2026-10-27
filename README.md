# Implementasi Protokol Distribusi Kunci (KDC) dan Enkripsi Manual AES-128-CBC

Tugas 2 Mata Kuliah Keamanan Informasi  
Departemen Teknik Informatika, Fakultas Teknologi Elektro dan Informatika Cerdas  
Institut Teknologi Sepuluh Nopember

---

## Anggota Kelompok

| Nama Lengkap            | NRP        | Peran dan Kontribusi                                                                                                                                                             |
| :---------------------- | :--------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mahendra Agung Darmawan | 5025241032 | Implementasi algoritma manual AES (key expansion, core rounds, CBC Mode, PKCS#7), perancangan protokol jaringan KDC, serta penulisan dokumentasi teknis dan pengujian Wireshark |
| Farras Nizar            | 5025241143 | Implementasi entitas Alice (Initiator) dan Bob (Responder), mekanisme socket multithreading dua arah, pengujian program                                                          |

---

## 1. Deskripsi Singkat

Repositori ini memuat implementasi sistem distribusi kunci simetris berbasis **Key Distribution Center (KDC)** yang dipadukan dengan algoritma kriptografi **Advanced Encryption Standard (AES)** mode **Cipher Block Chaining (CBC)**. Sistem ini dibangun menggunakan arsitektur tiga entitas mandiri (KDC, Alice sebagai Initiator, dan Bob sebagai Responder) yang berkomunikasi melalui protokol TCP/IP pada antarmuka jaringan terpisah.

Sesuai dengan batasan akademis tugas, **seluruh komponen kriptografi AES diimplementasikan secara manual dari nol (*pure Python standard library*) tanpa menggunakan pustaka eksternal** seperti `pycryptodome`, `cryptography`, atau sejenisnya. Sistem menerapkan skenario 5 langkah pertukaran kunci simetris (*Needham-Schroeder Symmetric Key Protocol / Stallings Key Distribution*) yang dilengkapi mekanisme tantangan Nonce (`N1` dan `N2`) untuk menjamin otentikasi timbal balik (*mutual authentication*) serta menangkal serangan pemutaran ulang (*replay attack*). Setelah sesi kunci terbentuk, entitas Alice dan Bob dapat melangsungkan komunikasi pesan dua arah secara aman dengan format ciphertext heksadesimal.

---

## 2. Arsitektur Sistem dan Skenario Distribusi Kunci

Pertukaran kunci dan sesi komunikasi terbagi ke dalam 5 tahapan utama sebelum kanal pertukaran pesan interaktif dibuka:

```
    +-------------------------------------------------------+
    |           Key Distribution Center (Port 8000)         |
    +-------------------------------------------------------+
           ^                                         |
(Langkah 1)| Request ID_A, ID_B, N1                  |(Langkah 2) E(KA, [Ks, ID_B, N1, Ticket_B])
           |                                         v
    +---------------+                       +---------------+
    |  Alice (Init) |                       | Bob (Respond) |
    +---------------+                       +---------------+
           |                                         ^
           |----(Langkah 3) Ticket_B --------------->|
           |<---(Langkah 4) E(Ks, N2) ---------------|
           |----(Langkah 5) E(Ks, f(N2)) ----------->|
           |                                         |
           |<=== Komunikasi Dua Arah AES-128-CBC ===>|
```

### Rincian Alur Protokol:

1. **Langkah 1 (Alice → KDC)**:  
   Alice membangkitkan bilangan acak semu berukuran 32-bit sebagai Nonce `N1`. Alice mengirimkan paket permintaan plaintext ke KDC berisi identitasnya, identitas tujuan, dan Nonce:  
   `Req = { ID_A, ID_B, N1 }`

2. **Langkah 2 (KDC → Alice)**:  
   KDC menerima permintaan, memvalidasi keberadaan Master Key `KA` dan `KB`, kemudian membangkitkan Session Key `Ks` (16 karakter ASCII acak). KDC menyusun:
   * **Ticket Bob**: `E(KB, [Ks || ID_A])`
   * **Paket Alice**: `E(KA, [Ks || ID_A || ID_B || N1 || Ticket_B])`  
   Paket dienkripsi menggunakan AES-CBC dengan Master Key masing-masing dan dikirimkan kembali ke Alice dalam bentuk heksadesimal.

3. **Langkah 3 (Alice → Bob)**:  
   Alice mendekripsi paket balasan KDC menggunakan `KA`. Alice memverifikasi bahwa `N1` dan `ID_B` identik dengan permintaannya. Jika valid, Alice mengekstrak `Ks` dan meneruskan `Ticket_B` ke port Bob (port 8002).

4. **Langkah 4 (Bob → Alice)**:  
   Bob menerima `Ticket_B`, mendekripsinya menggunakan Master Key `KB`, lalu memperoleh Session Key `Ks` dan identitas pemohon (`ID_A`). Bob kemudian membangkitkan Nonce baru `N2` (32-bit) dan mengirimkannya ke Alice dalam keadaan terenkripsi dengan `Ks`:  
   `Pesan_4 = E(Ks, N2)`

5. **Langkah 5 (Alice → Bob)**:  
   Alice mendekripsi `Pesan_4` dengan `Ks`, menerapkan fungsi transformasi aritmatika `f(N2) = N2 - 1`, mengenkripsinya kembali dengan `Ks`, dan mengirimkannya ke Bob:  
   `Pesan_5 = E(Ks, f(N2))`  
   Bob mendekripsi `Pesan_5` dan memverifikasi apakah nilainya tepat sama dengan `N2 - 1`. Jika sesuai, Bob meyakini identitas Alice dan sesi chat dua arah resmi dibuka.

---

## 3. Fitur Utama

* **Implementasi Manual AES-128**: Transformasi tingkat *byte* (SubBytes, ShiftRows, MixColumns, AddRoundKey, dan Key Expansion) ditulis secara murni tanpa pustaka eksternal.
* **Mode Operasi CBC dan PKCS#7**: Menggunakan Initialization Vector (IV) acak 16-byte untuk setiap blok pesan dan bantalan PKCS#7 berstandar industri dengan validasi integritas saat dekripsi.
* **Kepatuhan Format Data**:
  * Master Key (`KA`, `KB`) dan Session Key (`Ks`): Format karakter ASCII (16 byte / 128 bit).
  * Plaintext: Format karakter ASCII.
  * Ciphertext: Ditransmisikan dan ditampilkan dalam representasi Heksadesimal (Hex).
* **Interaktivitas Runtime (Mengubah Kunci Tanpa Restart)**:
  * KDC menyediakan antarmuka baris perintah dinamis untuk melihat dan mengubah Master Key Alice/Bob saat server sedang berjalan.
  * Alice menyediakan menu navigasi interaktif untuk mengubah Master Key `KA` atau mengganti IP target tanpa mematikan program.
  * Bob mendukung pergantian Master Key `KB` via interupsi terkontrol (`Ctrl+C`) tanpa memutus loop penerimaan koneksi socket.
* **Framing Socket Kebal *Sticky Packets***: Penambahan pembatas baris baru (`\n`) pada setiap pengiriman ciphertext guna menjamin transmisi TCP stream tidak saling menumpuk.
* **Siap Pengujian Wireshark**: Paket data dirancang transparan untuk inspeksi analitik paket jaringan.

---

## 4. Panduan Eksekusi (Setup & Execution)

### Persyaratan Lingkungan
* Python 3.10 atau versi yang lebih baru.
* Tidak memerlukan instalasi paket `pip` pihak ketiga (hanya modul standar: `socket`, `json`, `os`, `string`, `secrets`, `threading`).

### Langkah Menjalankan Tiga Terminal

Jalankan program secara berurutan pada 3 jendela terminal berbeda:

#### Terminal 1: Menjalankan KDC
```bash
python kdc.py
```
1. Masukkan Master Key Alice (16 karakter ASCII): `kunci_alice_1234`
2. Masukkan Master Key Bob (16 karakter ASCII): `kunci_bob_123456`
3. KDC akan aktif mendengarkan koneksi pada port `8000`.
4. Tersedia perintah internal: `list` (melihat kunci aktif) dan `set <Alice/Bob> <kunci_baru>`.

#### Terminal 2: Menjalankan Bob (Responder)
```bash
python responder.py
```
1. Masukkan Master Key Bob: `kunci_bob_123456`
2. Bob akan aktif mendengarkan koneksi dari Alice pada port `8002`.
3. Jika ingin mengganti kunci Bob saat standby, tekan `Ctrl+C` lalu pilih opsi `[2]`.

#### Terminal 3: Menjalankan Alice (Initiator)
```bash
python initiator.py
```
1. Masukkan Master Key Alice: `kunci_alice_1234`
2. Masukkan IP KDC:
   * Jika pada satu komputer pengujian lokal: `127.0.0.1`
   * Jika pada perangkat terpisah: Masukkan IP KDC (misal `192.168.1.10`)
3. Masukkan IP Bob:
   * Jika lokal: `127.0.0.1`
   * Jika perangkat terpisah: Masukkan IP Bob (misal `192.168.1.20`)
4. Pilih menu `[1] Mulai Handshake & Chat`.
5. Setelah 5 langkah otentikasi berhasil, kedua terminal dapat mengirim dan menerima pesan secara real-time. Ketik `/exit` untuk menutup sesi chat dan kembali ke menu utama.

---

## 5. Panduan Pengujian Wireshark

Sesuai ketentuan pengujian demonstrasi, Wireshark disiapkan untuk mengamati aliran paket data pada antarmuka jaringan yang aktif (*Wi-Fi / Ethernet Adapter*, atau *Npcap Loopback Adapter* jika diuji pada `localhost`).

### Konfigurasi Filter Wireshark:
Ketikkan filter ekspresi berikut pada bilah filter Wireshark:
```wireshark
tcp.port == 8000 or tcp.port == 8002
```

### Prosedur Observasi Paket:
1. **Langkah 1 (Handshake KDC)**:  
   Periksa paket pertama yang menuju ke port 8000. Klik kanan paket → **Follow** → **TCP Stream**.  
   Terlihat payload berupa teks JSON terang:
   ```json
   {"id_a": "Alice", "id_b": "Bob", "n1": 2557851354}
   ```
   Hal ini membuktikan permohonan sesi dikirimkan secara terbuka sesuai spesifikasi protokol.

2. **Langkah 2 (Respon KDC)**:  
   Paket balasan dari port 8000 ke Alice berupa untaian karakter Heksadesimal acak (Ciphertext terenkripsi `KA`). Tidak ada Master Key maupun plaintext tiket yang bocor pada jaringan.

3. **Langkah 3, 4, dan 5 (Otentikasi Alice dan Bob)**:  
   Periksa transmisi paket pada port 8002:
   * Alice mengirimkan tiket terenkripsi heksadesimal ke Bob.
   * Bob merespon dengan ciphertext `N2`.
   * Alice mengirimkan ciphertext balasan `f(N2)`.

4. **Sesi Komunikasi Interaktif (Chat)**:  
   Ketika pesan seperti `"Selamat Pagi"` dikirim dari Alice atau Bob, amati payload TCP pada Wireshark. Payload yang melintas di jaringan adalah string heksadesimal seperti:
   `d3f4a18902be76c819a...`  
   Hal ini memverifikasi bahwa plaintext dilindungi secara penuh oleh enkripsi AES-128-CBC dan tidak dapat dibaca oleh pihak ketiga (*eavesdropper*).

---

## 6. Rincian Teknis dan Landasan Algoritma

### A. Algoritma AES-128 (FIPS-197)

AES merupakan *symmetric block cipher* yang beroperasi pada blok berukuran 128 bit (16 byte) yang dipetakan ke dalam matriks status (*state array*) 4×4. Implementasi ini mencakup 10 ronde transformasi.

```
                    ALUR ENKRIPSI DAN DEKRIPSI AES-128
                    
          ENKRIPSI                                     DEKRIPSI
  +----------------------+                      +----------------------+
  | Plaintext (16 Byte)  |                      | Ciphertext (16 Byte) |
  +----------------------+                      +----------------------+
             |                                             |
             v                                             v
     [ AddRoundKey 0 ]                             [ AddRoundKey 10 ]
             |                                             |
  +----------+-----------+                      +----------+-----------+
  |  Ronde 1 s/d 9:      |                      |  Ronde 9 s/d 1:      |
  |  1. SubBytes         |                      |  1. InvShiftRows     |
  |  2. ShiftRows        |  (Proses Berulang)   |  2. InvSubBytes      |
  |  3. MixColumns       |                      |  3. AddRoundKey r    |
  |  4. AddRoundKey r    |                      |  4. InvMixColumns    |
  +----------+-----------+                      +----------+-----------+
             |                                             |
             v                                             v
  +----------------------+                      +----------------------+
  |  Ronde 10 (Final):   |                      |  Ronde 0 (Final):    |
  |  1. SubBytes         |                      |  1. InvShiftRows     |
  |  2. ShiftRows        |                      |  2. InvSubBytes      |
  |  3. AddRoundKey 10   |                      |  3. AddRoundKey 0    |
  +----------------------+                      +----------------------+
             |                                             |
             v                                             v
  +----------------------+                      +----------------------+
  | Ciphertext (16 Byte) |                      | Plaintext (16 Byte)  |
  +----------------------+                      +----------------------+
```

Rincian 4 transformasi pada setiap ronde AES:

1. **Key Expansion**:
   Kunci masukan 16 byte diperluas menjadi array berisi 44 *words* (masing-masing 4 byte) menggunakan operasi substitusi kata (*SubWord* dengan tabel S-Box), pergeseran kata (*RotWord*), serta penambahan konstanta ronde (*Rcon*).
2. **SubBytes**:
   Transformasi substitusi non-linear di mana setiap byte pada state digantikan oleh byte padanannya pada tabel substitusi (S-Box) yang diturunkan dari invers perkalian pada medan Galois GF(2^8) dikombinasikan dengan transformasi afin.
3. **ShiftRows**:
   Transformasi permutasi siklik terhadap baris matriks status:
   * Baris 0: Tidak digeser
   * Baris 1: Digeser ke kiri sebesar 1 byte
   * Baris 2: Digeser ke kiri sebesar 2 byte
   * Baris 3: Digeser ke kiri sebesar 3 byte
4. **MixColumns**:
   Operasi perkalian matriks modulo polinomial tereduksi x^4 + 1 di mana setiap kolom matriks status diperlakukan sebagai polinomial berderajat empat di atas GF(2^8). Perkalian dilakukan melalui fungsi perkalian Galois manual (`gmul`) terhadap konstanta polinomial irreducible `0x11B`. Transformasi ini ditiadakan pada ronde ke-10.
5. **AddRoundKey**:
   Operasi aljabar bitwise XOR sederhana antara matriks status dengan sub-kunci ronde terkait.

### B. Dekripsi AES
Dekripsi dibangun melalui pembalikan urutan aljabar yang presisi:
* `InvShiftRows`: Menggeser siklik baris ke arah kanan dengan pergeseran 0, 1, 2, dan 3 byte.
* `InvSubBytes`: Menggunakan tabel inversi S-Box (`INV_SBOX`) yang dibangun melalui relasi bijektif `S^-1(S(x)) = x`.
* `InvMixColumns`: Perkalian terhadap koefisien matriks invers (`0x0E, 0x0B, 0x0D, 0x09`) pada medan GF(2^8).

### C. Mode Cipher Block Chaining (CBC) dan PKCS#7

```
                ALUR MODE OPERASI CBC (CIPHER BLOCK CHAINING)

ENKRIPSI:
   Plaintext P1            Plaintext P2            Plaintext Pn
        |                       |                       |
IV --->(XOR)            C1 ---->(XOR)           Cn-1 -->(XOR)
        |                       |                       |
  [AES Encrypt]           [AES Encrypt]           [AES Encrypt]
        |                       |                       |
        v                       v                       v
  Ciphertext C1           Ciphertext C2           Ciphertext Cn

DEKRIPSI:
  Ciphertext C1           Ciphertext C2           Ciphertext Cn
        |                       |                       |
  [AES Decrypt]           [AES Decrypt]           [AES Decrypt]
        |                       |                       |
IV --->(XOR)            C1 ---->(XOR)           Cn-1 -->(XOR)
        |                       |                       |
        v                       v                       v
   Plaintext P1            Plaintext P2            Plaintext Pn
```

* **Mode CBC**:
  Operasi enkripsi dan dekripsi untuk setiap blok ke-*i*:
  * Enkripsi: `C_i = E_K(P_i ⊕ C_{i-1})` dengan `C_0 = IV`
  * Dekripsi: `P_i = D_K(C_i) ⊕ C_{i-1}`

  IV (*Initialization Vector*) dibangkitkan secara kriptografis menggunakan `os.urandom(16)` dan ditempatkan pada 16 byte pertama ciphertext.
* **PKCS#7 Padding**:
  Panjang bantalan `pad_len = 16 - (panjang_data mod 16)`. Setiap byte bantalan bernilai `pad_len`. Saat dekripsi, fungsi memverifikasi keseragaman seluruh byte bantalan. Kegagalan bantalan secara matematis menandakan ketidakcocokan kunci (*wrong key detection*).

### D. Keamanan Nonce (`N1, N2`) dan Fungsi Transformasi `f(N2)`
* **Peran Nonce `N1`**: Memastikan kesegaran (*freshness*) tiket dan respon KDC kepada Alice, sehingga penyerang tidak dapat menyuntikkan tiket lama hasil rekaman lampau.
* **Peran Nonce `N2`**: Tantangan (*challenge*) yang dibangkitkan Bob untuk menguji keaslian pihak yang menghubungi.
* **Fungsi `f(N2) = N2 - 1`**: Merupakan bukti bahwa pihak pengirim mampu mendekripsi pesan dengan `Ks`, memanipulasi nilai Nonce sesuai aturan bersama, dan mengenkripsinya kembali. Hal ini memvalidasi kepemilikan kunci sesi (*proof of key possession*) tanpa membocorkan kunci itu sendiri.

---

## 7. Fitur Tambahan

1. **Manajemen Kunci Dinamis Tanpa Restart**:
   Pengguna dapat menguji berbagai skenario kesalahan kunci (*wrong key test cases*) secara langsung saat demonstrasi tanpa perlu menghentikan proses terminal dan mengeksekusi ulang berkas Python.
2. **Penyelarasan Panjang Kunci Otomatis**:
   Fungsi pembantu `format_key()` secara otomatis memastikan kunci bernilai tepat 16 byte ASCII (melalui pemotongan batas 16 karakter atau penambahan karakter penyeimbang) guna mencegah eksepsi panjang blok tidak seragam.
