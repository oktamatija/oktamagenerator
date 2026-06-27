# 🛡️ Automated DNS Blocklist Aggregator (adsblocker)

Repositori ini adalah sistem agregator otomatis yang mengumpulkan, membersihkan, dan menggabungkan berbagai daftar domain iklan (*DNS blocklist*), pelacak (*tracker*), dan telemetri populer dari seluruh dunia menjadi satu file master tunggal yang bersih dan bebas dari duplikasi.

Proyek ini berjalan sepenuhnya di *cloud* menggunakan **GitHub Actions** tanpa memerlukan server aktif 24/7.

## 🚀 Fitur Utama

- **Multi-Source Aggregation**: Menggabungkan daftar terpercaya dari **Firebog (AdguardDNS)**, **OISD**, dan **StevenBlack Hosts**.
- **Automated Update**: Diperbarui secara otomatis setiap hari pada pukul 03:00 UTC melalui GitHub Actions.
- **Clean Format**: Menghapus baris komentar, spasi kosong, karakter aneh, serta awalan IP (`0.0.0.0` atau `127.0.0.1`) sehingga menghasilkan format nama domain bersih (satu baris, satu domain).
- **Deduplicated & Sorted**: Secara otomatis menghapus domain ganda dan diurutkan secara alfabetis untuk efisiensi pembacaan memori pada aplikasi klien.

## 🔗 Tautan Langsung (Raw URL)

Bagi Anda yang ingin menggunakan daftar master ini langsung di aplikasi pemblokir DNS kustom, Pi-hole, AdGuard Home, atau perangkat jaringan lainnya, silakan gunakan tautan langsung (*raw link*) berikut:

```text
[https://raw.githubusercontent.com/oktamatija/adsblocker/main/master-blocklist.txt](https://raw.githubusercontent.com/oktamatija/adsblocker/main/master-blocklist.txt)
