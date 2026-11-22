# 🛡️ TRJ-SOC-Toolkit

**TRJ-SOC-Toolkit**, SOC analistlerinin günlük çalışmalarında karşılaşabileceği Linux SSH kimlik doğrulama kayıtlarını incelemek için geliştirilmiş, Python tabanlı bir başlangıç aracıdır.

> Eğitim ve savunma amaçlıdır. Araç yalnızca belirtilen log dosyasını okur; sisteme müdahale etmez, IP engellemez ve ağ üzerinde tarama yapmaz.

## ✨ Özellikler

- Linux SSH loglarından başarısız parola denemelerini tespit eder.
- Kaynak IP adresine göre denemeleri gruplar.
- Belirlenen eşik değerine ulaşan IP adreslerini olası brute-force etkinliği olarak işaretler.
- Hedef kullanıcı adlarını ve ilk/son olay zamanlarını raporlar.
- Terminal, JSON ve CSV çıktısı üretir.
- Harici Python paketi gerektirmez.

## 📁 Proje yapısı

```text
TRJ-SOC-Toolkit/
├── main.py
├── requirements.txt
├── sample/
│   └── auth.log
├── tests/
│   └── test_parser.py
├── .gitignore
└── README.md
```

## ⚙️ Gereksinimler

- Python 3.10 veya üzeri
- Linux SSH kayıtları (ör. Ubuntu/Debian: `/var/log/auth.log`, RHEL tabanlı: `/var/log/secure`)

## 🚀 Kurulum ve kullanım

Depoyu klonla:

```bash
git clone https://github.com/SanaldunyaDONKISOTU/TRJ-SOC-Toolkit.git
cd TRJ-SOC-Toolkit
```

Örnek log dosyasıyla çalıştır:

```bash
python main.py --log sample/auth.log
```

Eşik değerini değiştir (varsayılan: aynı IP'den 5 veya daha fazla başarısız deneme):

```bash
python main.py --log sample/auth.log --threshold 3
```

JSON raporu oluştur:

```bash
python main.py --log sample/auth.log --json report.json
```

CSV raporu oluştur:

```bash
python main.py --log sample/auth.log --csv report.csv
```

Gerçek sistem logunu analiz etmek için (okuma izni gerekebilir):

```bash
sudo python main.py --log /var/log/auth.log --threshold 5
```

## 🧪 Testler

Proje kök dizininde:

```bash
python -m unittest discover -s tests -v
```

## 📊 Örnek çıktı

```text
[ALERT] Olası brute-force: 203.0.113.10 | 6 başarısız deneme | kullanıcılar: admin, root
[INFO] Toplam başarısız SSH denemesi: 8
[INFO] Eşik değerini aşan IP sayısı: 1
```

## ⚠️ Analiz notu

Bu araç bir ilk seviye tespit (triage) yardımcısıdır. Eşik değerinin aşılması tek başına saldırı kanıtı değildir. NAT, otomasyon, hatalı servis yapılandırması veya kullanıcı hataları da çok sayıda başarısız giriş oluşturabilir. Bulgular zaman aralığı, başarılı oturumlar, varlık kritiklik seviyesi ve diğer güvenlik kayıtlarıyla birlikte değerlendirilmelidir.

Örnek loglardaki IP adresleri dokümantasyon için ayrılmış TEST-NET aralıklarındandır; gerçek sistemlere ait değildir.

## 🗺️ Yol haritası

- [x] SSH başarısız giriş analizi
- [x] IP bazlı deneme sayımı ve eşik uyarısı
- [x] JSON / CSV raporlama
- [ ] Başarılı SSH oturumlarının korelasyonu
- [ ] Zaman penceresine göre brute-force tespiti
- [ ] Syslog ve journald desteği
- [ ] Daha kapsamlı IOC zenginleştirme entegrasyonu

## 👨‍💻 Geliştirici

**TRJ (SanaldunyaDONKISOTU)**

Siber güvenlik, SOC operasyonları, Python otomasyonu ve savunma odaklı güvenlik araçları üzerine çalışmalar.

---
⭐ Projeyi faydalı bulduysan yıldız bırakabilirsin.
