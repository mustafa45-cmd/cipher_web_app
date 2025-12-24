# 🔐 Kriptoloji - Şifreleme Uygulaması

Server ve Client sekmelerinden oluşan modern bir şifreleme/çözme web uygulaması.

## 📋 Özellikler

- **Server Sekmesi**: TCP sunucu durumu, gelen paket logları ve sunucu bilgileri
- **Client Sekmesi**: Çeşitli şifreleme algoritmaları ile şifreleme/çözme işlemleri
- Desteklenen Şifreleme Algoritmaları:
  - Caesar Cipher
  - Affine Cipher
  - Vigenère Cipher
  - Substitution Cipher
  - Rail Fence Cipher

## 🚀 Kurulum ve Çalıştırma

### 1. Gereksinimler

Python 3.7 veya üzeri yüklü olmalıdır.

### 2. Bağımlılıkları Yükleme

```powershell
pip install -r requirements.txt
```

veya manuel olarak:

```powershell
pip install flask flask-cors
```

### 3. Uygulamayı Çalıştırma

#### Yöntem 1: Otomatik Başlatma (Önerilen)

Windows'ta `run_all.ps1` dosyasına sağ tıklayıp "PowerShell ile Çalıştır" seçeneğini kullanın.

veya PowerShell'de:

```powershell
.\run_all.ps1
```

#### Yöntem 2: Manuel Başlatma

**Terminal 1 - TCP Server:**
```powershell
python server.py
```

**Terminal 2 - Flask API (Client API):**
```powershell
python client_api.py
```

### 4. Uygulamaya Erişim

Tarayıcınızda şu adresi açın:
```
http://127.0.0.1:5000
```

## 📖 Kullanım

### Server Sekmesi

- TCP sunucunun durumunu gösterir (Çalışıyor/Bağlantı yok)
- Gelen şifreli paketlerin loglarını görüntüler
- Logları temizlemek için "Logları Temizle" butonunu kullanabilirsiniz

### Client Sekmesi

1. **Şifreleme Türü** seçin
2. Gerekli parametreleri girin (ör: Caesar için shift değeri)
3. Metninizi girin
4. **Şifrele & Gönder** veya **Çöz** butonuna tıklayın
5. Sonuç alt kısımda görüntülenecektir

#### Otomatik Çözme Özelliği

- "Şifrelenen metni otomatik olarak çözme sekmesine aktar" seçeneğini işaretleyin
- Bir metin şifrelendiğinde, otomatik olarak Client sekmesine aktarılır

## 🏗️ Proje Yapısı

```
cipher_web_app/
├── server.py          # TCP Server (Port: 65432)
├── client_api.py      # Flask API Server (Port: 5000)
├── frontend/
│   ├── index.html     # Ana HTML dosyası
│   ├── script.js      # JavaScript kodları
│   └── style.css      # CSS stilleri
├── requirements.txt   # Python bağımlılıkları
├── run_all.ps1       # Otomatik başlatma scripti
└── README.md         # Bu dosya
```

## 🔧 Portlar

- **TCP Server**: 127.0.0.1:65432
- **Flask API**: 127.0.0.1:5000
- **Frontend**: Flask API üzerinden sunulur (http://127.0.0.1:5000)

## ⚠️ Sorun Giderme

### "Port zaten kullanımda" hatası

Eğer portlar zaten kullanılıyorsa:

1. Çalışan Python proseslerini kontrol edin:
```powershell
Get-Process python
```

2. Gerekirse eski prosesleri sonlandırın veya portları değiştirin

### TCP Server bağlantı hatası

- `server.py` dosyasının çalıştığından emin olun
- Port 65432'nin başka bir uygulama tarafından kullanılmadığını kontrol edin

### Flask API çalışmıyor

- Flask ve flask-cors modüllerinin yüklü olduğundan emin olun
- Port 5000'in kullanılabilir olduğunu kontrol edin

## 📝 Notlar

- Uygulama localhost üzerinde çalışır (sadece yerel erişim)
- Güvenlik için production ortamında ek önlemler alınmalıdır
- Tüm şifreleme işlemleri client-side'da da çalışabilir, ancak TCP server'a loglama için gönderilir

## 👨‍💻 Geliştirici Notları

- TCP Server ve Flask API ayrı prosesler olarak çalışır
- Server-Sent Events (SSE) kullanılarak gerçek zamanlı veri aktarımı sağlanır
- Frontend tek sayfa uygulaması (SPA) olarak tasarlanmıştır




