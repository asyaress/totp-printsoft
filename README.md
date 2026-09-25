# TOTP Printsoft

Halaman login TOTP berbasis PHP native tanpa framework atau Composer. QR dibuat langsung di browser sehingga secret authenticator tidak dikirim ke layanan QR pihak ketiga.

## Menjalankan secara lokal

```powershell
php -S localhost:8000
```

Buka `http://localhost:8000`. Khusus localhost, kredensial instalasi awal adalah:

- Username: `admin`
- Password: `Admin@123`

Setelah login pertama, pindai QR, verifikasi kode enam digit, lalu login ulang memakai kode authenticator.

## Konfigurasi produksi

Set environment variable berikut sebelum request pertama:

- `TOTP_ADMIN_USER`
- `TOTP_ADMIN_PASSWORD` (wajib pada server publik)
- `TOTP_APP_NAME`
- `TOTP_STORAGE_PATH` (sebaiknya berada di luar public web root)

File `.totp-storage.php` berisi password hash dan secret TOTP. File tersebut sudah dikecualikan dari Git dan Vercel; jangan pernah mengunggah atau membagikannya.

## Status deployment Vercel

Belum siap digunakan di Vercel apa adanya. PHP memerlukan community runtime `vercel-php`, sementara aplikasi ini masih memakai file lokal untuk penyimpanan persisten. Filesystem Vercel Functions bersifat read-only dan `/tmp` hanya bersifat sementara.

Sebelum deployment ke Vercel, pindahkan data akun, perangkat, dan replay counter TOTP ke database persisten seperti PostgreSQL. Jangan memakai `/tmp` untuk secret atau session login.
