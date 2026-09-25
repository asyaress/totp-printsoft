# TOTP Printsoft

Halaman login TOTP berbasis PHP native tanpa framework atau Composer. QR dibuat langsung di browser sehingga secret authenticator tidak dikirim ke layanan QR pihak ketiga.

## Fitur keamanan

- Password disimpan menggunakan `password_hash`.
- Secret TOTP dan isi session dienkripsi AES-256-GCM sebelum masuk database; ID session disimpan sebagai HMAC.
- Session serverless disimpan di PostgreSQL, bukan filesystem sementara.
- Replay counter TOTP memakai optimistic locking agar satu kode tidak diterima dua kali.
- CSRF protection, rate limiting per session, cookie `HttpOnly`, `Secure`, dan `SameSite=Strict`.
- Content Security Policy dan security headers.
- `.totp-storage.php` dan file environment tidak pernah masuk Git/Vercel.

## Menjalankan secara lokal dengan file fallback

```powershell
php -S localhost:8000
```

Buka `http://localhost:8000`. Khusus localhost, kredensial instalasi awal adalah `admin` / `Admin@123`.

## Menjalankan jalur database secara lokal

Gunakan PostgreSQL, atau SQLite hanya untuk pengembangan lokal:

```powershell
$env:DATABASE_URL = 'sqlite:D:/path/to/project/.totp-local.sqlite'
$env:TOTP_ENCRYPTION_KEY = php -r "echo base64_encode(random_bytes(32));"
$env:TOTP_ADMIN_PASSWORD = 'ganti-dengan-password-kuat'
php -S localhost:8000
```

## Deploy ke Vercel

### 1. Import repository

1. Buka Vercel Dashboard lalu pilih **Add New → Project**.
2. Import repository GitHub `asyaress/totp-printsoft`.
3. Biarkan **Framework Preset** sebagai `Other` dan **Root Directory** sebagai root repository.
4. Jangan deploy sebelum database dan environment variables selesai dikonfigurasi.

### 2. Tambahkan PostgreSQL

1. Di konfigurasi project Vercel, buka **Storage** atau **Marketplace**.
2. Tambahkan integrasi **Neon Postgres** dan hubungkan ke project ini.
3. Dengan custom prefix `DATABASE`, integrasi akan membuat `DATABASE_POSTGRES_URL`. Aplikasi juga menerima `DATABASE_URL` atau `POSTGRES_URL`.

Tabel `totp_app_state` dan `totp_sessions` dibuat otomatis pada request pertama.

### 3. Tambahkan environment variables

Tambahkan melalui **Project → Settings → Environment Variables**:

| Nama | Nilai |
| --- | --- |
| `DATABASE_POSTGRES_URL` | Dibuat otomatis oleh integrasi Neon dengan prefix `DATABASE` |
| `TOTP_ENCRYPTION_KEY` | Kunci Base64 acak 32 byte |
| `TOTP_ADMIN_USER` | Username administrator |
| `TOTP_ADMIN_PASSWORD` | Password awal yang panjang dan unik |
| `TOTP_APP_NAME` | Nama yang tampil di authenticator |

Buat encryption key secara lokal:

```powershell
php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
```

Simpan key tersebut di password manager. Jangan menggantinya setelah perangkat TOTP ditambahkan karena secret dan session lama tidak akan dapat didekripsi.

### 4. Deploy

Klik **Deploy**. Jika environment variables ditambahkan setelah deployment pertama, buka **Deployments**, pilih deployment terbaru, lalu **Redeploy**.

Setelah deployment berhasil:

1. Buka URL production.
2. Login menggunakan `TOTP_ADMIN_USER` dan `TOTP_ADMIN_PASSWORD`.
3. Pindai QR dan verifikasi kode enam digit.
4. Login ulang dengan password dan kode authenticator.
5. Tambahkan perangkat authenticator cadangan dari dashboard.

## Catatan penting

- Deployment Vercel memakai community runtime `vercel-php@0.9.0` dengan PHP 8.5.
- Koneksi Neon otomatis meneruskan atau menurunkan Endpoint ID untuk kompatibilitas dengan libpq yang belum mendukung SNI.
- Produksi Vercel menolak SQLite dan menolak berjalan tanpa URL PostgreSQL Neon yang didukung.
- Data lokal lama di `.totp-storage.php` tidak otomatis dipindah ke database; deployment baru akan melakukan enrollment dari awal.
- Gunakan database Neon region yang dekat dengan Function Region Vercel untuk mengurangi latency.
