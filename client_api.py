# client_api.py
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import socket, json, string, threading, queue
from math import gcd
import time
import base64
import hashlib

# Try to import pycryptodome for library-based encryption
try:
    from Crypto.Cipher import AES as CryptoAES, DES as CryptoDES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.PublicKey import RSA, DSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Signature import DSS, pkcs1_15
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

ALPHABET = string.ascii_uppercase

# --- (şifreleme/deşifreleme fonksiyonları aynı) ---
def caesar_encrypt(text, shift):
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            return chr((ord(c) - base + shift) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def affine_encrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError('a must be coprime with 26')
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            x = ord(c) - base
            return chr((a * x + b) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def modinv(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError('No modular inverse')

def affine_decrypt(text, a, b):
    inv = modinv(a, 26)
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            y = ord(c) - base
            return chr((inv * (y - b)) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def vigenere_encrypt(text, key):
    key = ''.join(k for k in key if k.isalpha())
    res = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = key[ki % len(key)]
            shift = ord(k.lower()) - ord('a')
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            res.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            res.append(c)
    return ''.join(res)

def vigenere_decrypt(text, key):
    key = ''.join(k for k in key if k.isalpha())
    res = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = key[ki % len(key)]
            shift = ord(k.lower()) - ord('a')
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            res.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            res.append(c)
    return ''.join(res)

def substitution_encrypt(text, substitution_key):
    if len(substitution_key) != 26:
        raise ValueError('Substitution key must be 26 letters')
    mapping_upper = {ALPHABET[i]: substitution_key[i].upper() for i in range(26)}
    mapping_lower = {k.lower(): v.lower() for k,v in mapping_upper.items()}
    def map_char(c):
        if c.isupper():
            return mapping_upper.get(c, c)
        elif c.islower():
            return mapping_lower.get(c, c)
        return c
    return ''.join(map_char(c) for c in text)

def substitution_decrypt(text, substitution_key):
    if len(substitution_key) != 26:
        raise ValueError('Substitution key must be 26 letters')
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
    if rails <= 1:
        return text
    fence = ['' for _ in range(rails)]
    rail = 0
    dir = 1
    for c in text:
        fence[rail] += c
        rail += dir
        if rail == 0 or rail == rails - 1:
            dir *= -1
    return ''.join(fence)

def railfence_decrypt(cipher, rails):
    if rails <= 1:
        return cipher
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    patlen = len(pattern)
    counts = [0] * rails
    for i in range(len(cipher)):
        counts[pattern[i % patlen]] += 1
    parts = []
    idx = 0
    for c in counts:
        parts.append(cipher[idx:idx+c])
        idx += c
    res = []
    pointers = [0]*rails
    for i in range(len(cipher)):
        r = pattern[i % patlen]
        res.append(parts[r][pointers[r]])
        pointers[r] += 1
    return ''.join(res)

# ==================== AES ŞİFRELEME ====================

# AES - Kütüphaneli (PyCryptodome)
def aes_lib_encrypt(text, key):
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    # Key'i 16, 24 veya 32 byte'a tamamla
    key_hash = hashlib.sha256(key.encode()).digest()[:32]  # AES-256 için 32 byte
    cipher = CryptoAES.new(key_hash, CryptoAES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), CryptoAES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def aes_lib_decrypt(ciphertext, key):
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        enc = base64.b64decode(ciphertext)
        iv = enc[:16]
        ct = enc[16:]
        key_hash = hashlib.sha256(key.encode()).digest()[:32]
        cipher = CryptoAES.new(key_hash, CryptoAES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), CryptoAES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

# AES - Kütüphanesiz (Basit XOR tabanlı blok şifreleme)
def aes_simple_encrypt(text, key):
    # Basit bir blok şifreleme (gerçek AES değil, eğitim amaçlı)
    key_hash = hashlib.sha256(key.encode()).digest()
    text_bytes = text.encode('utf-8')
    result = []
    for i in range(len(text_bytes)):
        # XOR işlemi ile şifreleme
        encrypted_byte = text_bytes[i] ^ key_hash[i % len(key_hash)]
        result.append(encrypted_byte)
    # Base64 ile encode et
    return base64.b64encode(bytes(result)).decode('utf-8')

def aes_simple_decrypt(ciphertext, key):
    try:
        key_hash = hashlib.sha256(key.encode()).digest()
        enc_bytes = base64.b64decode(ciphertext)
        result = []
        for i in range(len(enc_bytes)):
            # XOR ile çözme (XOR tersine çevrilebilir)
            decrypted_byte = enc_bytes[i] ^ key_hash[i % len(key_hash)]
            result.append(decrypted_byte)
        return bytes(result).decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

# ==================== DES ŞİFRELEME ====================

# DES - Kütüphaneli (PyCryptodome)
def des_lib_encrypt(text, key):
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    # DES key'i 8 byte olmalı
    key_bytes = hashlib.md5(key.encode()).digest()[:8]
    cipher = CryptoDES.new(key_bytes, CryptoDES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), CryptoDES.block_size))
    iv = cipher.iv
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def des_lib_decrypt(ciphertext, key):
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        enc = base64.b64decode(ciphertext)
        iv = enc[:8]
        ct = enc[8:]
        key_bytes = hashlib.md5(key.encode()).digest()[:8]
        cipher = CryptoDES.new(key_bytes, CryptoDES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), CryptoDES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        raise ValueError(f'Çözme hatası: {str(e)}')

# DES - Kütüphanesiz (Basit XOR tabanlı)
def des_simple_encrypt(text, key):
    # Basit bir şifreleme (gerçek DES değil, eğitim amaçlı)
    key_hash = hashlib.md5(key.encode()).digest()[:8]  # 8 byte key
    text_bytes = text.encode('utf-8')
    result = []
    for i in range(len(text_bytes)):
        encrypted_byte = text_bytes[i] ^ key_hash[i % len(key_hash)]
        result.append(encrypted_byte)
    return base64.b64encode(bytes(result)).decode('utf-8')

def des_simple_decrypt(ciphertext, key):
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

# ==================== RSA ŞİFRELEME ====================

# RSA Key Generation (2048 bit)
def generate_rsa_keys():
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode(), public_key.decode()

# RSA - Encrypt
def rsa_encrypt(text, public_key_pem):
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # Public key'i yükle
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        # RSA sadece kısa mesajlar için (OAEP padding ile ~190 byte'a kadar)
        text_bytes = text.encode('utf-8')
        if len(text_bytes) > 190:
            raise ValueError('RSA ile şifrelenecek metin çok uzun (max ~190 karakter). Daha kısa bir metin kullanın.')
        encrypted = cipher.encrypt(text_bytes)
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        raise ValueError(f'Şifreleme hatası: {str(e)}')

# RSA - Decrypt
def rsa_decrypt(ciphertext, private_key_pem):
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

# ==================== DSA (DIGITAL SIGNATURE ALGORITHM) ====================

# DSA Key Generation (2048 bit)
def generate_dsa_keys():
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        key = DSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key.decode(), public_key.decode()
    except Exception as e:
        raise ValueError(f'DSA anahtarı oluşturma hatası: {str(e)}')

# DSA - Sign (İmzalama)
def dsa_sign(message, private_key_pem):
    if not CRYPTO_AVAILABLE:
        raise ValueError('pycryptodome kütüphanesi yüklü değil. pip install pycryptodome')
    try:
        # Private key'i yükle
        private_key = DSA.import_key(private_key_pem)
        # Mesajın hash'ini al
        hash_obj = SHA256.new(message.encode('utf-8'))
        # İmzala
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hash_obj)
        # Base64 ile encode et
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        # Mesaj ve imzayı birlikte döndür (JSON formatında)
        return json.dumps({
            'message': message,
            'signature': signature_b64
        })
    except Exception as e:
        raise ValueError(f'İmzalama hatası: {str(e)}')

# DSA - Verify (Doğrulama)
def dsa_verify(signed_data_json, public_key_pem):
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
        # Doğrula
        verifier = DSS.new(public_key, 'fips-186-3')
        verifier.verify(hash_obj, signature)
        # Doğrulama başarılı
        return f'✅ İmza doğrulandı! Mesaj: {message}'
    except Exception as e:
        raise ValueError(f'Doğrulama hatası: {str(e)}')

# --- TCP forward ---
TCP_HOST = '127.0.0.1'
TCP_PORT = 65432

def forward_to_tcp_server(payload):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((TCP_HOST, TCP_PORT))
            s.sendall(json.dumps(payload).encode('utf-8'))
        return True, None
    except Exception as e:
        return False, str(e)

# --- Simple pub/sub for notifying decrypt-tab clients (SSE) ---
subscribers = []
sub_lock = threading.Lock()

def publish_message(msg):
    # push msg to all subscriber queues
    with sub_lock:
        for q in subscribers[:]:
            try:
                q.put(msg, block=False)
            except Exception:
                pass

@app.route('/stream')
def stream():
    def gen(q):
        try:
            while True:
                msg = q.get()  # blocking
                yield f"data: {json.dumps({'ciphertext': msg})}\n\n"
        except GeneratorExit:
            pass

    q = queue.Queue()
    with sub_lock:
        subscribers.append(q)
    return Response(gen(q), mimetype='text/event-stream')

@app.route('/publish', methods=['POST'])
def publish():
    j = request.get_json() or {}
    ct = j.get('ciphertext','')
    publish_message(ct)
    return jsonify({'status':'ok'})

# --- Main process endpoint (encrypt/decrypt) ---
@app.route('/server-status', methods=['GET'])
def server_status():
    """Check if TCP server is running"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((TCP_HOST, TCP_PORT))
            if result == 0:
                return jsonify({'status': 'online', 'host': TCP_HOST, 'port': TCP_PORT})
            else:
                return jsonify({'status': 'offline', 'host': TCP_HOST, 'port': TCP_PORT})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/generate-rsa-keys', methods=['GET'])
def generate_rsa_keys_endpoint():
    """Generate RSA key pair"""
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
    """Generate DSA key pair"""
    try:
        private_key, public_key = generate_dsa_keys()
        return jsonify({
            'status': 'ok',
            'private_key': private_key,
            'public_key': public_key
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
@app.route('/process', methods=['POST'])
def process():
    data = request.json or {}
    action = data.get('action')
    cipher = data.get('cipher')
    params = data.get('params') or {}
    text = data.get('text','')

    try:
        execution_time = None  # Şifreleme süresi (saniye)
        
        if action == 'encrypt':
            start_time = time.perf_counter()  # Yüksek çözünürlüklü zaman ölçümü
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
            else:
                return jsonify({'error':'unknown cipher'}), 400
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time  # Saniye cinsinden

            # forward to TCP server for logging (RSA/DSA key'leri göndermeyelim)
            log_params = params.copy()
            if 'public_key' in log_params:
                log_params['public_key'] = '[Public Key - Hidden]'
            if 'private_key' in log_params:
                log_params['private_key'] = '[Private Key - Hidden]'
            payload = {'cipher': cipher, 'params': log_params, 'ciphertext': result[:200]}  # İlk 200 karakter
            ok, err = forward_to_tcp_server(payload)

            # publish ciphertext to subscribers (decrypt tab)
            publish_message(result)

            # AES ve DES için süre bilgisini ekle
            response_data = {'status':'ok','action':'encrypt','result':result,'forwarded':ok,'error':err}
            if cipher in ['aes_lib', 'aes_simple', 'des_lib', 'des_simple']:
                response_data['execution_time'] = execution_time
                response_data['execution_time_ms'] = execution_time * 1000  # Milisaniye
            
            return jsonify(response_data)

        elif action == 'decrypt':
            start_time = time.perf_counter()  # Çözme için de zaman ölçümü
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
            else:
                return jsonify({'error':'unknown cipher'}), 400
            
            end_time = time.perf_counter()
            execution_time = end_time - start_time

            # forward decrypted attempt to TCP server for logging (RSA/DSA key'leri göndermeyelim)
            log_params = params.copy()
            if 'public_key' in log_params:
                log_params['public_key'] = '[Public Key - Hidden]'
            if 'private_key' in log_params:
                log_params['private_key'] = '[Private Key - Hidden]'
            payload = {'cipher': cipher, 'params': log_params, 'ciphertext': text[:200]}  # İlk 200 karakter
            ok, err = forward_to_tcp_server(payload)

            # AES ve DES için süre bilgisini ekle
            response_data = {'status':'ok','action':'decrypt','result':result,'forwarded':ok,'error':err}
            if cipher in ['aes_lib', 'aes_simple', 'des_lib', 'des_simple']:
                response_data['execution_time'] = execution_time
                response_data['execution_time_ms'] = execution_time * 1000  # Milisaniye
            
            return jsonify(response_data)
        else:
            return jsonify({'error':'unknown action'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# serve frontend files
@app.route('/')
def index():
    return send_from_directory('frontend','index.html')

@app.route('/<path:p>')
def static_proxy(p):
    return send_from_directory('frontend', p)

if __name__ == '__main__':
    print("Flask API + SSE server running at http://127.0.0.1:5001")
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)
