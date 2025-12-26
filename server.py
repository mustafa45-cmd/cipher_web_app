# ============================================================================
# server.py
# TCP Server - Şifreli Mesajları Loglama ve Çözme
# ============================================================================
# Bu dosya, Flask API'den gelen şifreli mesajları alıp loglayan bir TCP server
# içerir. Klasik şifreleme algoritmalarını çözerek sonuçları gösterir.
# Modern şifreler için sadece loglama yapar (çözme işlemi yapılmaz).
# ============================================================================

import socket
import json
import threading
import string
from math import gcd

# İngilizce alfabesi (büyük harfler)
ALPHABET = string.ascii_uppercase

# ============================================================================
# KLASİK ŞİFRE ÇÖZME FONKSİYONLARI
# ============================================================================

def caesar_decrypt(text, shift):
    """
    Caesar Şifresi Çözme - Her harfi shift miktarı kadar geriye kaydır
    
    Args:
        text: Çözülecek şifreli metin
        shift: Kaydırma miktarı
    """
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            # Geriye kaydırarak çöz
            return chr((ord(c) - base - shift) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def affine_decrypt(text, a, b):
    """
    Affine Şifresi Çözme - D(y) = a^(-1) * (y - b) mod 26
    
    Args:
        text: Çözülecek şifreli metin
        a: Şifreleme parametresi (26 ile aralarında asal olmalı)
        b: Şifreleme parametresi
    """
    def modinv(a, m):
        """Modüler ters hesapla"""
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:  # a*x ≡ 1 (mod m)
                return x
        raise ValueError('No modular inverse')
    
    inv = modinv(a, 26)  # a'nın mod 26'ya göre tersi
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            y = ord(c) - base
            # Ters affine dönüşüm
            return chr((inv * (y - b)) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def vigenere_decrypt(text, key):
    """
    Vigenère Şifresi Çözme - Değişken kaydırma ile çözme
    
    Args:
        text: Çözülecek şifreli metin
        key: Şifreleme anahtarı
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
            # Geriye kaydırarak çöz
            res.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            res.append(c)  # Harf değilse olduğu gibi ekle
    return ''.join(res)

def substitution_decrypt(text, substitution_key):
    """
    Substitution Şifresi Çözme - Ters mapping ile çözme
    
    Args:
        text: Çözülecek şifreli metin
        substitution_key: 26 harfli permütasyon (şifrelemede kullanılan)
    """
    if len(substitution_key) != 26:
        raise ValueError('Substitution key must be 26 letters')
    # Ters mapping oluştur: şifreli harf -> orijinal harf
    mapping_upper = {substitution_key[i].upper(): ALPHABET[i] for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k,v in mapping_upper.items()}
    def map_char(c):
        if c.isupper():
            return mapping_upper.get(c, c)
        elif c.islower():
            return mapping_lower.get(c, c)
        return c
    return ''.join(map_char(c) for c in text)

def railfence_decrypt(cipher, rails):
    """
    Rail Fence Şifresi Çözme - Zigzag desenini yeniden oluşturup çözme
    
    Args:
        cipher: Çözülecek şifreli metin
        rails: Ray sayısı
    """
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
# TCP SERVER KONFİGÜRASYONU
# ============================================================================

# Server adresi ve portu
HOST = '0.0.0.0'  # Tüm network interface'lerinden dinle
PORT = 65432  # TCP server portu

def handle_client(conn, addr):
    """
    Client bağlantısını işle - Şifreli mesajı al, çöz ve logla
    
    Args:
        conn: Socket bağlantısı
        addr: Client adresi (IP, port)
    """
    print(f'Connected by {addr}')  # Bağlanan client'ı logla
    
    with conn:
        # Veriyi tamamen almak için döngü
        data = b''  # Byte string olarak veri biriktir
        while True:
            packet = conn.recv(4096)  # 4096 byte'lık paketler halinde al
            if not packet:  # Paket yoksa bağlantı kesilmiş
                break
            data += packet  # Paketi veriye ekle
        
        try:
            # JSON formatındaki veriyi parse et
            payload = json.loads(data.decode('utf-8'))
        except Exception as e:
            print('JSON decode error:', e)
            return
        
        # Gelen veriyi logla
        print('\n--- Incoming Packet ---')
        print('Cipher:', payload.get('cipher'))  # Şifreleme türü
        print('Params:', payload.get('params'))  # Parametreler
        print('Ciphertext:', payload.get('ciphertext'))  # Şifreli metin
        
        try:
            cipher = payload.get('cipher')  # Şifreleme türü
            params = payload.get('params') or {}  # Parametreler
            ct = payload.get('ciphertext') or ''  # Şifreli metin
            
            # Şifreleme türüne göre çözme işlemi yap
            if cipher == 'caesar':
                pt = caesar_decrypt(ct, int(params.get('shift',0)))
            elif cipher == 'affine':
                pt = affine_decrypt(ct, int(params.get('a')), int(params.get('b')))
            elif cipher == 'vigenere':
                pt = vigenere_decrypt(ct, params.get('key',''))
            elif cipher == 'substitution':
                pt = substitution_decrypt(ct, params.get('key',''))
            elif cipher == 'railfence':
                pt = railfence_decrypt(ct, int(params.get('rails',2)))
            elif cipher in ['aes_lib', 'aes_simple', 'des_lib', 'des_simple', 'rsa', 'dsa', 'ecc']:
                # Modern şifreler için çözme yapılmaz (sadece loglama)
                pt = '<Modern şifre/İmza - çözme yapılmadı>'
            else:
                pt = '<unknown cipher>'
            
            # Çözülmüş metni logla
            print('Decrypted (server-side):', pt)
        except Exception as e:
            print('Decryption failed:', e)

def start_server():
    """
    TCP server'ı başlat ve client bağlantılarını dinle
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Socket seçeneklerini ayarla
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Port'u tekrar kullan
        s.bind((HOST, PORT))  # Server'ı belirtilen adres ve porta bağla
        s.listen()  # Bağlantıları dinlemeye başla
        
        print(f'Server listening on {HOST}:{PORT}')  # Server durumunu logla
        
        # Sonsuz döngü: sürekli client bağlantılarını kabul et
        while True:
            conn, addr = s.accept()  # Yeni bir client bağlantısı bekle (blocking)
            # Her client için ayrı thread başlat (eşzamanlı bağlantılar için)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# ============================================================================
# UYGULAMA BAŞLATMA
# ============================================================================

if __name__ == '__main__':
    start_server()  # Server'ı başlat
