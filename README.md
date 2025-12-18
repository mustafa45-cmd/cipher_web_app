# Kriptoloji Server-Client Projesi

Bu proje, çeşitli şifreleme metodlarını destekleyen bir server-client uygulamasıdır.

## Desteklenen Şifreleme Metodları

### Klasik Şifreleme Metodları
1. **Sezar (Caesar)** - Kaydırmalı şifreleme
2. **Rail Fence** - Zigzag okuma şifreleme
3. **Vigenere** - Çoklu alfabe şifreleme
4. **Vernam** - One-Time Pad şifreleme
5. **Playfair** - İkili harf şifreleme
6. **Route** - Spiral okuma şifreleme
7. **Affine** - Doğrusal dönüşüm şifreleme
8. **Hill Cipher** - Matris tabanlı şifreleme
9. **Columnar** - Sütun transpozisyon şifreleme

### Modern Şifreleme Metodları
10. **AES (Kütüphaneli)** - Advanced Encryption Standard (PyCrypto kullanarak)
11. **AES (Kütüphanesiz)** - Basitleştirilmiş AES implementasyonu
12. **DES (Kütüphaneli)** - Data Encryption Standard (PyCrypto kullanarak)
13. **DES (Kütüphanesiz)** - Basitleştirilmiş DES implementasyonu

## Kurulum

1. Gerekli paketleri yükleyin:

**Windows için:**
```bash
python -m pip install -r requirements.txt
```
veya
```bash
py -m pip install -r requirements.txt
```

**Linux/Mac için:**
```bash
pip install -r requirements.txt
```

## Kullanım

### Server'ı Başlatma

```bash
python server.py [host] [port]
```

Varsayılan: `localhost:12345`

Örnek:
```bash
python server.py localhost 12345
```

### Client'ı Çalıştırma

```bash
python client.py [host] [port]
```

Varsayılan: `localhost:12345`

Örnek:
```bash
python client.py localhost 12345
```

## Kullanım Örnekleri

### Sezar Şifreleme
- Metin: "HELLO"
- Shift: 3
- Şifrelenmiş: "KHOOR"

### Vigenere Şifreleme
- Metin: "HELLO"
- Anahtar: "KEY"
- Şifrelenmiş: "RIJVS"

### AES Şifreleme
- Metin: "Hello World"
- Anahtar: "mysecretkey"
- Şifrelenmiş: (hex formatında)

## Proje Yapısı

```
kriptoloji/
├── server.py              # Server uygulaması
├── client.py              # Client uygulaması
├── ciphers/
│   ├── __init__.py
│   ├── classical.py       # Klasik şifreleme metodları
│   └── modern.py          # Modern şifreleme metodları
├── requirements.txt       # Python bağımlılıkları
└── README.md             # Bu dosya
```

## Notlar

- **Vernam Cipher**: Anahtar uzunluğu metin uzunluğuna eşit olmalıdır.
- **Hill Cipher**: 3x3 matris kullanılır. Matris determinantı 26 ile aralarında asal olmalıdır.
- **Affine Cipher**: 'a' parametresi 26 ile aralarında asal olmalıdır.
- **AES/DES Kütüphanesiz**: Basitleştirilmiş implementasyonlardır, eğitim amaçlıdır.
- **AES/DES Kütüphaneli**: PyCrypto kütüphanesi kullanılarak tam implementasyon.

## Lisans

Bu proje eğitim amaçlıdır.

