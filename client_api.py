# client_api.py
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import socket, json, string, threading, queue
from math import gcd
import time

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
@app.route('/process', methods=['POST'])
def process():
    data = request.json or {}
    action = data.get('action')
    cipher = data.get('cipher')
    params = data.get('params') or {}
    text = data.get('text','')

    try:
        if action == 'encrypt':
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
            else:
                return jsonify({'error':'unknown cipher'}), 400

            # forward to TCP server for logging
            payload = {'cipher': cipher, 'params': params, 'ciphertext': result}
            ok, err = forward_to_tcp_server(payload)

            # publish ciphertext to subscribers (decrypt tab)
            publish_message(result)

            return jsonify({'status':'ok','action':'encrypt','result':result,'forwarded':ok,'error':err})

        elif action == 'decrypt':
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
            else:
                return jsonify({'error':'unknown cipher'}), 400

            # forward decrypted attempt to TCP server for logging
            payload = {'cipher': cipher, 'params': params, 'ciphertext': text}
            ok, err = forward_to_tcp_server(payload)

            return jsonify({'status':'ok','action':'decrypt','result':result,'forwarded':ok,'error':err})
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
    print("Flask API + SSE server running at http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
