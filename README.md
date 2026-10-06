# 🛡️ Automated DNS Blocklist Aggregator (oktamagenerator)

Repositori ini adalah sistem agregator otomatis cerdas yang mengumpulkan, membersihkan, dan menggabungkan berbagai daftar domain pemblokiran (*DNS blocklist*), iklan (*ads*), pelacak (*trackers*), telemetri, konten dewasa (*adult*), perjudian (*gambling*), malware, *threat intelligence feeds*, *phishing*, penipuan (*scam*), obat terlarang (*drugs*), dan kekerasan (*violence*) dari berbagai sumber terpercaya di seluruh dunia menjadi daftar bersih bebas duplikasi.

Proyek ini berjalan secara otomatis di *cloud* menggunakan **GitHub Actions** setiap hari pada pukul 02:00 UTC (09:00 WIB).

---

## 🚀 Fitur Utama

- **Cumulative Retention (Tidak Menghapus Daftar Lama)**: Mempertahankan daftar blokir sebelumnya dan hanya menambahkan domain baru yang ditemukan dari sumber teranyar (*union merge*). Perlindungan tidak akan menurun jika server penyedia sumber sementara sedang offline.
- **Bypass Bot/Scraper Blocking**: Dilengkapi *custom User-Agent* browser dan header modern untuk mencegah pemblokiran HTTP 403 / Cloudflare oleh penyedia sumber.
- **Enterprise-Grade Sources**: Menggabungkan berbagai sumber aktif & terverifikasi:
  - **Iklan & Pelacak**: HaGeZi Multi PRO+, OISD Big, StevenBlack, Firebog (AdguardDNS, Easylist, Admiral), Peter Lowe, Anudeep Adservers, AdGuard DNS Filter.
  - **Malware & Threats**: HaGeZi Threat Intelligence Feeds (TIF), URLhaus abuse.ch, ThreatFox abuse.ch, BlocklistProject Malware.
  - **Phishing & Scam**: Phishing Army, BlocklistProject Phishing, OpenPhish, DurableNapkin Scam.
  - **Konten Dewasa & Judi**: StevenBlack Adult/Gambling, BlocklistProject Porn/Gambling.
  - **Drugs & Violence**: BlocklistProject Drugs, BlocklistProject Abuse, StevenBlack Fakenews.
- **Clean Format**: Menghapus komentar (`#`, `!`), format hosts (`0.0.0.0`, `127.0.0.1`), format Adblock (`||domain^`), trailing port, dan karakter tidak valid.
- **Deduplicated & Sorted**: Menghapus domain duplikat dan diurutkan secara alfabetis (case-insensitive normalized).

---

## 🔗 Tautan Langsung (Raw Links)

Gunakan tautan langsung (*raw link*) berikut pada aplikasi pemblokir DNS seperti **OktamaDnsFilter**, Pi-hole, AdGuard Home, atau perangkat jaringan Anda:

| Kategori | Deskripsi | Tautan Langsung (Raw URL) |
| :--- | :--- | :--- |
| **Master All-In-One** | Gabungan perlindungan lengkap (Iklan, Malware, Phishing, Scam, Drugs, Violence) | [`master-blocklist.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/master-blocklist.txt) |
| **Ads & Trackers** | Iklan, pelacak, dan telemetri | [`ads.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/ads.txt) |
| **Malware & Threats** | Malware, spyware, ransomware, C2 server, dan threat intelligence | [`malware.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/malware.txt) |
| **Phishing** | Situs pancingan identitas & kredensial palsu | [`phishing.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/phishing.txt) |
| **Scam / Fraud** | Situs penipuan online & investasi bodong | [`scam.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/scam.txt) |
| **Adult / NSFW** | Konten pornografi & dewasa | [`adult.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/adult.txt) |
| **Gambling** | Situs judi online & kasino | [`gambling.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/gambling.txt) |
| **Drugs** | Pasar gelap obat terlarang & narkotika | [`drugs.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/drugs.txt) |
| **Violence / Abuse** | Situs kekerasan, pelecehan, dan hoax/fakenews | [`violence.txt`](https://raw.githubusercontent.com/oktamatija/oktamagenerator/main/violence.txt) |
