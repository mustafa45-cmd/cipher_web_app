# ============================================================================
# client_api.py
# Flask API Backend - Şifreleme/Çözme ve Modern Kriptografi Fonksiyonları
# ============================================================================
# Bu dosya, web arayüzünden gelen şifreleme/çözme isteklerini işleyen Flask
# API'sini içerir. Klasik ve modern şifreleme algoritmalarını destekler.
# ============================================================================

# Flask web framework ve gerekli kütüphaneleri import et
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS  # Cross-Origin Resource Sharing için
import socket, json, string, threading, queue
from math import gcd  # En büyük ortak bölen hesaplama için
import time  # Zaman ölçümü için
import base64  # Binary verileri string'e çevirmek için
import hashlib  # Hash fonksiyonları için (SHA256, MD5)

# PyCryptodome kütüphanesini import etmeye çalış (modern şifreleme için)
# Eğer yüklü değilse, kütüphaneli şifreleme fonksiyonları çalışmayacak
try:
    from Crypto.Cipher import AES as CryptoAES, DES as CryptoDES  # AES ve DES şifreleme
    from Crypto.Util.Padding import pad, unpad  # Blok şifreleme için padding
    from Crypto.Random import get_random_bytes  # Rastgele byte üretimi
    from Crypto.PublicKey import RSA, DSA, ECC  # Asimetrik şifreleme anahtarları
    from Crypto.Cipher import PKCS1_OAEP  # RSA için padding şeması
    from Crypto.Hash import SHA256  # SHA-256 hash fonksiyonu
    from Crypto.Signature import DSS, pkcs1_15, eddsa, eddsa  # Dijital imza
    CRYPTO_AVAILABLE = True  # Kütüphane başarıyla yüklendi
except ImportError:
    CRYPTO_AVAILABLE = False  # Kütüphane yüklü değil

# Flask uygulamasını başlat
# static_folder: Frontend dosyalarının bulunduğu klasör
app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)  # Tüm origin'lerden gelen isteklere izin ver (CORS hatası önlemek için)

# İngilizce alfabesi (büyük harfler)
ALPHABET = string.ascii_uppercase

# ============================================================================
# KLASİK ŞİFRELEME ALGORİTMALARI
# ============================================================================

def caesar_encrypt(text, shift):
    """
    Caesar Şifreleme - Her harfi belirli bir miktar kaydırarak şifreleme
    
    Args:
        text: Şifrelenecek metin
        shift: Kaydırma miktarı (pozitif sayı)
    
    Returns:
        Şifrelenmiş metin
    """
    def map_char(c):
        # Sadece harfleri şifrele, diğer karakterleri olduğu gibi bırak
        if c.isalpha():
            is_lower = c.islower()  # Küçük harf mi kontrol et
            base = ord('a') if is_lower else ord('A')  # Alfabe başlangıcı
            # Harfi kaydır ve mod 26 ile alfabe içinde tut
            return chr((ord(c) - base + shift) % 26 + base)
        return c  # Harf değilse olduğu gibi döndür
    return ''.join(map_char(c) for c in text)

def caesar_decrypt(text, shift):
    """Caesar Çözme - Shift'i negatif yaparak encrypt fonksiyonunu kullan"""
    return caesar_encrypt(text, -shift)

def affine_encrypt(text, a, b):
    """
    Affine Şifreleme - E(x) = (a*x + b) mod 26 formülü ile şifreleme
    
    Args:
        text: Şifrelenecek metin
        a: 26 ile aralarında asal olması gereken sayı
        b: Kaydırma değeri
    """
    if gcd(a, 26) != 1:  # a, 26 ile aralarında asal olmalı
        raise ValueError('a must be coprime with 26')
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            x = ord(c) - base  # Harfin alfabedeki konumu (0-25)
            # Affine dönüşüm: (a*x + b) mod 26
            return chr((a * x + b) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def modinv(a, m):
    """Modüler ters (modular inverse) hesapla - Affine çözme için gerekli"""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:  # a*x ≡ 1 (mod m)
            return x
    raise ValueError('No modular inverse')

def affine_decrypt(text, a, b):
    """Affine Çözme - D(y) = a^(-1) * (y - b) mod 26"""
    inv = modinv(a, 26)  # a'nın mod 26'ya göre tersi
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            y = ord(c) - base  # Şifreli harfin konumu
            # Ters affine dönüşüm
            return chr((inv * (y - b)) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def vigenere_encrypt(text, key):
    """
    Vigenère Şifreleme - Değişken kaydırma ile şifreleme
    
    Args:
        text: Şifrelenecek metin
        key: Şifreleme anahtarı (kelime)
    """
    key = ''.join(k for k in key if k.isalpha())  # Sadece harfleri al
    res = []
    ki = 0  # Anahtar indeksi
    for c in text:
        if c.isalpha():
            k = key[ki % len(key)]  # Anahtarı döngüsel olarak kullan
            shift = ord(k.lower()) - ord('a')  # Anahtar harfinin sayısal değeri
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            # Caesar şifreleme ama her harf için farklı shift
            res.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            res.append(c)  # Harf değilse olduğu gibi ekle
    return ''.join(res)

def vigenere_decrypt(text, key):
    """Vigenère Çözme - Shift'i negatif yaparak encrypt mantığını kullan"""
    key = ''.join(k for k in key if k.isalpha())
    res = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = key[ki % len(key)]
            shift = ord(k.lower()) - ord('a')
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            res.append(chr((ord(c) - base - shift) % 26 + base))  # -shift ile çöz
            ki += 1
        else:
            res.append(c)
    return ''.join(res)

def substitution_encrypt(text, substitution_key):
    """
    Substitution Şifreleme - Her harfi başka bir harfle değiştirme
    
    Args:
        text: Şifrelenecek metin
        substitution_key: 26 harfli permütasyon (A-Z yerine kullanılacak harfler)
    """
    if len(substitution_key) != 26:
        raise ValueError('Substitution key must be 26 letters')
    # Büyük ve küçük harfler için mapping oluştur
    mapping_upper = {ALPHABET[i]: substitution_key[i].upper() for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k,v in mapping_upper.items()}
    def map_char(c):
        if c.isupper():
            return mapping_upper.get(c, c)  # Mapping varsa değiştir
        elif c.islower():
            return mapping_lower.get(c, c)
        return c
    return ''.join(map_char(c) for c in text)

def substitution_decrypt(text, substitution_key):
    """Substitution Çözme - Ters mapping kullanarak çözme"""
    if len(substitution_key) != 26:
        raise ValueError('Substitution key must be 26 letters')
    # Ters mapping: şifreli harf -> orijinal harf
    mapping_upper = {substitution_key[i].upper(): ALPHABET[i] for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k,v in mapping_upper.items()}
    def map_char(c):
        if c.isupper():
            return mapping_upper.get(c, c)
        elif c.islower():
            return mapping_lower.get(c, c)
        return c
    return ''.join(map_char(c) for c in text)

def railfence_encrypt(text, rails):
    """
    Rail Fence Şifreleme - Metni zigzag deseninde yazdırma
    
    Args:
        text: Şifrelenecek metin
        rails: Ray sayısı (desenin yüksekliği)
    """
    if rails <= 1:
        return text
    fence = ['' for _ in range(rails)]  # Her ray için bir string
    rail = 0  # Mevcut ray
    dir = 1  # Yön (1: aşağı, -1: yukarı)
    for c in text:
        fence[rail] += c  # Karakteri ilgili raya ekle
        rail += dir  # Bir sonraki raya geç
        # Üst veya alt raya ulaşırsa yönü değiştir
        if rail == 0 or rail == rails - 1:
            dir *= -1
    return ''.join(fence)  # Tüm rayları birleştir

def railfence_decrypt(cipher, rails):
    """Rail Fence Çözme - Deseni yeniden oluşturup karakterleri yerleştirme"""
    if rails <= 1:
        return cipher
    # Zigzag desenini oluştur (0,1,2,...,rails-1,rails-2,...,1)
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    patlen = len(pattern)
    # Her rayda kaç karakter olduğunu hesapla
    counts = [0] * rails
    for i in range(len(cipher)):
        counts[pattern[i % patlen]] += 1
    # Şifreli metni raylara böl
    parts = []
    idx = 0
    for c in counts:
        parts.append(cipher[idx:idx+c])
        idx += c
    # Orijinal sırayı yeniden oluştur
    res = []
    pointers = [0]*rails  # Her ray için okuma indeksi
    for i in range(len(cipher)):
        r = pattern[i % patlen]  # Hangi raydan oku
        res.append(parts[r][pointers[r]])  # Karakteri al
        pointers[r] += 1  # İlgili rayın indeksini artır
    return ''.join(res)

# ============================================================================
# MODERN ŞİFRELEME ALGORİTMALARI - AES
# ============================================================================

def aes_lib_encrypt(text, key):
    """
    AES Şifreleme (Kütüphaneli) - PyCryptodome kütüphanesi ile AES-256-CBC
    
    Args:
        text: Şifrelenecek metin
        key: Şifreleme anahtarı (string, SHA256 ile hash'lenir)
    
    Returns:
        Base64 kodlanmış şifreli metin (IV + ciphertext)
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    # Key'i SHA256 ile hash'le ve 32 byte'a indir (AES-256 için)
    key_hash = hashlib.sha256(key.encode()).digest()[:32]
    cipher = CryptoAES.new(key_hash, CryptoAES.MODE_CBC)  # CBC modunda AES
    # Metni UTF-8'e çevir, padding ekle ve şifrele
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), CryptoAES.block_size))
    iv = cipher.iv  # Initialization Vector (rastgele üretilir)
    # IV ve şifreli metni birleştirip base64 ile kodla
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def aes_lib_decrypt(ciphertext, key):
    """AES Çözme (Kütüphaneli) - IV'yi ayırıp şifreli metni çöz"""
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        enc = base64.b64decode(ciphertext)  # Base64'ten decode et
        iv = enc[:16]  # İlk 16 byte IV
        ct = enc[16:]  # Geri kalan şifreli metin
        key_hash = hashlib.sha256(key.encode()).digest()[:32]
        cipher = CryptoAES.new(key_hash, CryptoAES.MODE_CBC, iv)  # Aynı IV ile
        pt = unpad(cipher.decrypt(ct), CryptoAES.block_size)  # Padding'i kaldır ve çöz
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

def aes_simple_encrypt(text, key):
    """
    AES Basit Şifreleme (Kütüphanesiz) - Eğitim amaçlı XOR tabanlı
    
    NOT: Bu gerçek AES değil, sadece eğitim ve performans karşılaştırması için!
    """
    key_hash = hashlib.sha256(key.encode()).digest()  # Key'i hash'le
    text_bytes = text.encode('utf-8')
    result = []
    for i in range(len(text_bytes)):
        # XOR işlemi ile şifreleme (basit ama gerçek AES değil)
        encrypted_byte = text_bytes[i] ^ key_hash[i % len(key_hash)]
        result.append(encrypted_byte)
    # Base64 ile encode et
    return base64.b64encode(bytes(result)).decode('utf-8')

def aes_simple_decrypt(ciphertext, key):
    """AES Basit Çözme (Kütüphanesiz) - XOR tersine çevrilebilir olduğu için aynı işlem"""
    try:
        key_hash = hashlib.sha256(key.encode()).digest()
        enc_bytes = base64.b64decode(ciphertext)
        result = []
        for i in range(len(enc_bytes)):
            # XOR ile çözme (XOR kendi tersidir: A XOR B XOR B = A)
            decrypted_byte = enc_bytes[i] ^ key_hash[i % len(key_hash)]
            result.append(decrypted_byte)
        return bytes(result).decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

# ============================================================================
# MODERN ŞİFRELEME ALGORİTMALARI - DES
# ============================================================================

def des_lib_encrypt(text, key):
    """
    DES Şifreleme (Kütüphaneli) - PyCryptodome ile DES-CBC
    
    Args:
        text: Şifrelenecek metin
        key: Şifreleme anahtarı (MD5 hash ile 8 byte'a indirilir)
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    # DES key'i 8 byte olmalı (MD5'ten ilk 8 byte'ı al)
    key_bytes = hashlib.md5(key.encode()).digest()[:8]
    cipher = CryptoDES.new(key_bytes, CryptoDES.MODE_CBC)  # DES-CBC modu
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), CryptoDES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def des_lib_decrypt(ciphertext, key):
    """DES Çözme (Kütüphaneli)"""
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        enc = base64.b64decode(ciphertext)
        iv = enc[:8]  # DES için IV 8 byte
        ct = enc[8:]
        key_bytes = hashlib.md5(key.encode()).digest()[:8]
        cipher = CryptoDES.new(key_bytes, CryptoDES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), CryptoDES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

def des_simple_encrypt(text, key):
    """
    DES Basit Şifreleme (Kütüphanesiz) - Eğitim amaçlı XOR tabanlı
    
    NOT: Bu gerçek DES değil, sadece eğitim ve performans karşılaştırması için!
    """
    key_hash = hashlib.md5(key.encode()).digest()[:8]  # 8 byte key
    text_bytes = text.encode('utf-8')
    result = []
    for i in range(len(text_bytes)):
        encrypted_byte = text_bytes[i] ^ key_hash[i % len(key_hash)]
        result.append(encrypted_byte)
    return base64.b64encode(bytes(result)).decode('utf-8')

def des_simple_decrypt(ciphertext, key):
    """DES Basit Çözme (Kütüphanesiz)"""
    try:
        key_hash = hashlib.md5(key.encode()).digest()[:8]
        enc_bytes = base64.b64decode(ciphertext)
        result = []
        for i in range(len(enc_bytes)):
            decrypted_byte = enc_bytes[i] ^ key_hash[i % len(key_hash)]
            result.append(decrypted_byte)
        return bytes(result).decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

# ============================================================================
# ASİMETRİK ŞİFRELEME - RSA
# ============================================================================

def generate_rsa_keys():
    """
    RSA Anahtar Çifti Oluştur - 2048 bit güvenlik seviyesi
    
    Returns:
        (private_key, public_key) tuple - PEM formatında
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    key = RSA.generate(2048)  # 2048 bit RSA anahtarı üret
    private_key = key.export_key()  # Private key'i PEM formatında export et
    public_key = key.publickey().export_key()  # Public key'i export et
    return private_key.decode(), public_key.decode()

def rsa_encrypt(text, public_key_pem):
    """
    RSA Şifreleme - Public key ile şifreleme (PKCS1_OAEP padding)
    
    NOT: RSA sadece kısa mesajlar için uygundur (~190 karakter)
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # Public key'i PEM formatından yükle
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)  # OAEP padding ile
        # RSA sadece kısa mesajlar için (OAEP padding ile ~190 byte'a kadar)
        text_bytes = text.encode('utf-8')
        if len(text_bytes) > 190:
            raise ValueError('RSA ile şifrelenecek metin çok uzun (max ~190 karakter). Daha kısa bir metin kullanın.')
        encrypted = cipher.encrypt(text_bytes)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        raise ValueError(f'Şifreleme hatası: {str(e)}')

def rsa_decrypt(ciphertext, private_key_pem):
    """RSA Çözme - Private key ile çözme"""
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # Private key'i yükle
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        enc_bytes = base64.b64decode(ciphertext)
        decrypted = cipher.decrypt(enc_bytes)
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

# ============================================================================
# DİJİTAL İMZA - DSA (Digital Signature Algorithm)
# ============================================================================

def generate_dsa_keys():
    """
    DSA Anahtar Çifti Oluştur - 2048 bit güvenlik seviyesi
    
    Returns:
        (private_key, public_key) tuple - PEM formatında
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        key = DSA.generate(2048)  # 2048 bit DSA anahtarı
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key.decode(), public_key.decode()
    except Exception as e:
        raise ValueError(f'DSA anahtarı oluşturma hatası: {str(e)}')

def dsa_sign(message, private_key_pem):
    """
    DSA İmzalama - Mesajı private key ile imzala
    
    Args:
        message: İmzalanacak mesaj
        private_key_pem: PEM formatında private key
    
    Returns:
        JSON string: {"message": "...", "signature": "..."}
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # Private key'i yükle
        private_key = DSA.import_key(private_key_pem)
        # Mesajın SHA-256 hash'ini al
        hash_obj = SHA256.new(message.encode('utf-8'))
        # FIPS-186-3 standardına göre imzala
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        # Base64 ile encode et
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        # Mesaj ve imzayı JSON formatında döndür
        return json.dumps({
            'message': message,
            'signature': signature_b64
        })
    except Exception as e:
        raise ValueError(f'İmzalama hatası: {str(e)}')

def dsa_verify(signed_data_json, public_key_pem):
    """
    DSA Doğrulama - İmzayı public key ile doğrula
    
    Args:
        signed_data_json: JSON formatında {"message": "...", "signature": "..."}
        public_key_pem: PEM formatında public key
    
    Returns:
        Doğrulama sonucu string'i
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # JSON'dan mesaj ve imzayı al
        data = json.loads(signed_data_json)
        message = data.get('message', '')
        signature_b64 = data.get('signature', '')
        
        if not message or not signature_b64:
            raise ValueError('Geçersiz imza formatı')
        
        # Public key'i yükle
        public_key = DSA.import_key(public_key_pem)
        # Mesajın hash'ini al
        hash_obj = SHA256.new(message.encode('utf-8'))
        # İmzayı decode et
        signature = base64.b64decode(signature_b64)
        # İmzayı doğrula
        verifier = DSS.new(public_key, 'fips-186-3')
        verifier.verify(hash_obj, signature)  # Hata fırlatırsa imza geçersiz
        # Doğrulama başarılı
        return f'✅ İmza doğrulandı! Mesaj: {message}'
    except Exception as e:
        raise ValueError(f'Doğrulama hatası: {str(e)}')

# ============================================================================
# DİJİTAL İMZA - ECC (Elliptic Curve Cryptography)
# ============================================================================

def generate_ecc_keys():
    """
    ECC Anahtar Çifti Oluştur - P-256 eğrisi (256 bit güvenlik)
    
    Returns:
        (private_key, public_key) tuple - PEM formatında
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        key = ECC.generate(curve='P-256')  # P-256 eğrisi ile ECC anahtarı
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')
        return private_key, public_key
    except Exception as e:
        raise ValueError(f'ECC anahtarı oluşturma hatası: {str(e)}')

def ecc_sign(message, private_key_pem):
    """
    ECC İmzalama - ECDSA (Elliptic Curve Digital Signature Algorithm)
    
    Args:
        message: İmzalanacak mesaj
        private_key_pem: PEM formatında ECC private key
    
    Returns:
        JSON string: {"message": "...", "signature": "..."}
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # Private key'i yükle
        private_key = ECC.import_key(private_key_pem)
        # Mesajın SHA-256 hash'ini al
        hash_obj = SHA256.new(message.encode('utf-8'))
        # ECDSA ile imzala (FIPS-186-3 standardı)
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        # Base64 ile encode et
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        # Mesaj ve imzayı JSON formatında döndür
        return json.dumps({
            'message': message,
            'signature': signature_b64
        })
    except Exception as e:
        raise ValueError(f'İmzalama hatası: {str(e)}')

def ecc_verify(signed_data_json, public_key_pem):
    """
    ECC Doğrulama - ECDSA imzasını doğrula
    
    Args:
        signed_data_json: JSON formatında {"message": "...", "signature": "..."}
        public_key_pem: PEM formatında ECC public key
    
    Returns:
        Doğrulama sonucu string'i
    """
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # JSON'dan mesaj ve imzayı al
        data = json.loads(signed_data_json)
        message = data.get('message', '')
        signature_b64 = data.get('signature', '')
        
        if not message or not signature_b64:
            raise ValueError('Geçersiz imza formatı')
        
        # Public key'i yükle
        public_key = ECC.import_key(public_key_pem)
        # Mesajın hash'ini al
        hash_obj = SHA256.new(message.encode('utf-8'))
        # İmzayı decode et
        signature = base64.b64decode(signature_b64)
        # İmzayı doğrula
        verifier = DSS.new(public_key, 'fips-186-3')
        verifier.verify(hash_obj, signature)
        # Doğrulama başarılı
        return f'✅ İmza doğrulandı! Mesaj: {message}'
    except Exception as e:
        raise ValueError(f'Doğrulama hatası: {str(e)}')

# ============================================================================
# TCP SERVER İLETİŞİMİ
# ============================================================================

# TCP server bilgileri
TCP_HOST = '127.0.0.1'  # Localhost
TCP_PORT = 65432  # TCP server portu

def forward_to_tcp_server(payload):
    """
    Şifrelenmiş mesajı TCP server'a gönder (loglama için)
    
    Args:
        payload: Gönderilecek veri (dict)
    
    Returns:
        (success: bool, error: str veya None) tuple
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((TCP_HOST, TCP_PORT))  # TCP server'a bağlan
            s.sendall(json.dumps(payload).encode('utf-8'))  # JSON olarak gönder
        return True, None
    except Exception as e:
        return False, str(e)

# ============================================================================
# SERVER-SENT EVENTS (SSE) - Gerçek Zamanlı Mesaj Aktarımı
# ============================================================================

# SSE subscriber listesi (her client için bir queue)
subscribers = []
sub_lock = threading.Lock()  # Thread-safe erişim için lock

def publish_message(msg):
    """
    Şifrelenmiş mesajı tüm subscriber'lara (çözme sekmesi) gönder
    
    Args:
        msg: Gönderilecek mesaj (şifreli metin)
    """
    # Thread-safe: lock ile subscriber listesine eriş
    with sub_lock:
        for q in subscribers[:]:  # Liste kopyasını kullan
            try:
                q.put(msg, block=False)  # Non-blocking ekleme
            except Exception:
                pass  # Queue doluysa atla

@app.route('/stream')
def stream():
    """
    SSE endpoint - Client'lar bu endpoint'e bağlanarak gerçek zamanlı mesaj alır
    """
    def gen(q):
        """Generator function - SSE için sürekli mesaj gönderir"""
        try:
            while True:
                msg = q.get()  # Blocking: mesaj gelene kadar bekle
                # SSE formatında mesaj gönder
                yield f"data: {json.dumps({'ciphertext': msg})}\n\n"
        except GeneratorExit:
            pass  # Client bağlantısı kesildiğinde

    q = queue.Queue()  # Bu client için yeni queue oluştur
    with sub_lock:
        subscribers.append(q)  # Subscriber listesine ekle
    return Response(gen(q), mimetype='text/event-stream')  # SSE response

@app.route('/publish', methods=['POST'])
def publish():
    """
    Mesaj yayınlama endpoint'i - Şifrelenmiş mesajı yayınla
    """
    j = request.get_json() or {}
    ct = j.get('ciphertext','')
    publish_message(ct)  # Tüm subscriber'lara gönder
    return jsonify({'status':'ok'})

# ============================================================================
# API ENDPOINT'LERİ
# ============================================================================

@app.route('/server-status', methods=['GET'])
def server_status():
    """
    TCP server durumunu kontrol et
    
    Returns:
        JSON: {'status': 'online'/'offline', 'host': ..., 'port': ...}
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # 1 saniye timeout
            result = s.connect_ex((TCP_HOST, TCP_PORT))  # Bağlanmayı dene
            if result == 0:
                return jsonify({'status': 'online', 'host': TCP_HOST, 'port': TCP_PORT})
            else:
                return jsonify({'status': 'offline', 'host': TCP_HOST, 'port': TCP_PORT})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/generate-rsa-keys', methods=['GET'])
def generate_rsa_keys_endpoint():
    """RSA anahtar çifti oluşturma endpoint'i"""
    try:
        private_key, public_key = generate_rsa_keys()
        return jsonify({
            'status': 'ok',
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400

@app.route('/generate-dsa-keys', methods=['GET'])
def generate_dsa_keys_endpoint():
    """DSA anahtar çifti oluşturma endpoint'i"""
    try:
        private_key, public_key = generate_dsa_keys()
        return jsonify({
            'status': 'ok',
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400

@app.route('/generate-ecc-keys', methods=['GET'])
def generate_ecc_keys_endpoint():
    """ECC anahtar çifti oluşturma endpoint'i"""
    try:
        private_key, public_key = generate_ecc_keys()
        return jsonify({
            'status': 'ok',
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400

@app.route('/process', methods=['POST'])
def process():
    """
    Ana işlem endpoint'i - Şifreleme ve çözme isteklerini işler
    
    Request body:
        {
            "action": "encrypt" veya "decrypt",
            "cipher": Şifreleme türü (caesar, aes_lib, rsa, vb.),
            "params": Parametreler (shift, key, vb.),
            "text": İşlenecek metin
        }
    
    Returns:
        JSON: {
            "status": "ok",
            "result": Sonuç metni,
            "execution_time": Saniye cinsinden süre (AES/DES için),
            ...
        }
    """
    data = request.json or {}
    action = data.get('action')  # 'encrypt' veya 'decrypt'
    cipher = data.get('cipher')  # Şifreleme türü
    params = data.get('params') or {}  # Parametreler
    text = data.get('text','')  # İşlenecek metin

    try:
        execution_time = None  # Şifreleme süresi (saniye)
        
        if action == 'encrypt':
            # ŞİFRELEME İŞLEMİ
            start_time = time.perf_counter()  # Yüksek çözünürlüklü zaman ölçümü
            
            # Şifreleme türüne göre ilgili fonksiyonu çağır
            if cipher == 'caesar':
                result = caesar_encrypt(text, int(params.get('shift',0)))
            elif cipher == 'affine':
                result = affine_encrypt(text, int(params.get('a')), int(params.get('b')))
            elif cipher == 'vigenere':
                result = vigenere_encrypt(text, params.get('key',''))
            elif cipher == 'substitution':
                result = substitution_encrypt(text, params.get('key',''))
            elif cipher == 'railfence':
                result = railfence_encrypt(text, int(params.get('rails',2)))
            elif cipher == 'aes_lib':
                result = aes_lib_encrypt(text, params.get('key',''))
            elif cipher == 'aes_simple':
                result = aes_simple_encrypt(text, params.get('key',''))
            elif cipher == 'des_lib':
                result = des_lib_encrypt(text, params.get('key',''))
            elif cipher == 'des_simple':
                result = des_simple_encrypt(text, params.get('key',''))
            elif cipher == 'rsa':
                result = rsa_encrypt(text, params.get('public_key',''))
            elif cipher == 'dsa':
                # DSA için sign işlemi
                result = dsa_sign(text, params.get('private_key',''))
            elif cipher == 'ecc':
                # ECC için sign işlemi
                result = ecc_sign(text, params.get('private_key',''))
            else:
                return jsonify({'error':'unknown cipher'}), 400
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time  # Saniye cinsinden süre

            # TCP server'a loglama için gönder (güvenlik: key'leri gizle)
            log_params = params.copy()
            if 'public_key' in log_params:
                log_params['public_key'] = '[Public Key - Hidden]'
            if 'private_key' in log_params:
                log_params['private_key'] = '[Private Key - Hidden]'
            payload = {'cipher': cipher, 'params': log_params, 'ciphertext': result[:200]}  # İlk 200 karakter
            ok, err = forward_to_tcp_server(payload)

            # Çözme sekmesine (subscriber'lara) şifreli mesajı gönder (SSE ile)
            publish_message(result)

            # Response oluştur
            response_data = {'status':'ok','action':'encrypt','result':result,'forwarded':ok,'error':err}
            # AES ve DES için süre bilgisini ekle (performans karşılaştırması için)
            if cipher in ['aes_lib', 'aes_simple', 'des_lib', 'des_simple']:
                response_data['execution_time'] = execution_time
                response_data['execution_time_ms'] = execution_time * 1000  # Milisaniye
            
            return jsonify(response_data)

        elif action == 'decrypt':
            # ÇÖZME İŞLEMİ
            start_time = time.perf_counter()  # Çözme için de zaman ölçümü
            
            # Çözme türüne göre ilgili fonksiyonu çağır
            if cipher == 'caesar':
                result = caesar_decrypt(text, int(params.get('shift',0)))
            elif cipher == 'affine':
                result = affine_decrypt(text, int(params.get('a')), int(params.get('b')))
            elif cipher == 'vigenere':
                result = vigenere_decrypt(text, params.get('key',''))
            elif cipher == 'substitution':
                result = substitution_decrypt(text, params.get('key',''))
            elif cipher == 'railfence':
                result = railfence_decrypt(text, int(params.get('rails',2)))
            elif cipher == 'aes_lib':
                result = aes_lib_decrypt(text, params.get('key',''))
            elif cipher == 'aes_simple':
                result = aes_simple_decrypt(text, params.get('key',''))
            elif cipher == 'des_lib':
                result = des_lib_decrypt(text, params.get('key',''))
            elif cipher == 'des_simple':
                result = des_simple_decrypt(text, params.get('key',''))
            elif cipher == 'rsa':
                result = rsa_decrypt(text, params.get('private_key',''))
            elif cipher == 'dsa':
                # DSA için verify işlemi
                result = dsa_verify(text, params.get('public_key',''))
            elif cipher == 'ecc':
                # ECC için verify işlemi
                result = ecc_verify(text, params.get('public_key',''))
            else:
                return jsonify({'error':'unknown cipher'}), 400
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time

            # TCP server'a loglama için gönder (güvenlik: key'leri gizle)
            log_params = params.copy()
            if 'public_key' in log_params:
                log_params['public_key'] = '[Public Key - Hidden]'
            if 'private_key' in log_params:
                log_params['private_key'] = '[Private Key - Hidden]'
            payload = {'cipher': cipher, 'params': log_params, 'ciphertext': text[:200]}  # İlk 200 karakter
            ok, err = forward_to_tcp_server(payload)

            # Response oluştur
            response_data = {'status':'ok','action':'decrypt','result':result,'forwarded':ok,'error':err}
            # AES ve DES için süre bilgisini ekle
            if cipher in ['aes_lib', 'aes_simple', 'des_lib', 'des_simple']:
                response_data['execution_time'] = execution_time
                response_data['execution_time_ms'] = execution_time * 1000  # Milisaniye
            
            return jsonify(response_data)
        else:
            return jsonify({'error':'unknown action'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ============================================================================
# STATIK DOSYA SERVİSİ
# ============================================================================

@app.route('/')
def index():
    """Ana sayfa - Frontend HTML dosyasını göster"""
    return send_from_directory('frontend','index.html')

@app.route('/<path:p>')
def static_proxy(p):
    """Diğer static dosyalar (CSS, JS, vb.) için proxy"""
    return send_from_directory('frontend', p)

# ============================================================================
# UYGULAMA BAŞLATMA
# ============================================================================

if __name__ == '__main__':
    print("Flask API + SSE server running at http://127.0.0.1:5001")
    # Flask uygulamasını başlat
    # host='0.0.0.0': Tüm network interface'lerinden erişilebilir
    # port=5001: Port numarası
    # debug=True: Hata mesajlarını göster (geliştirme modu)
    # threaded=True: Çoklu thread desteği (eşzamanlı istekler için)
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)
