import socket
import json
import threading
import string
from math import gcd

ALPHABET = string.ascii_uppercase

def caesar_decrypt(text, shift):
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            return chr((ord(c) - base - shift) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

def affine_decrypt(text, a, b):
    def modinv(a, m):
        a = a % m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        raise ValueError('No modular inverse')
    inv = modinv(a, 26)
    def map_char(c):
        if c.isalpha():
            is_lower = c.islower()
            base = ord('a') if is_lower else ord('A')
            y = ord(c) - base
            return chr((inv * (y - b)) % 26 + base)
        return c
    return ''.join(map_char(c) for c in text)

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

HOST = '0.0.0.0'
PORT = 65432

def handle_client(conn, addr):
    print(f'Connected by {addr}')
    with conn:
        data = b''
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            data += packet
        try:
            payload = json.loads(data.decode('utf-8'))
        except Exception as e:
            print('JSON decode error:', e)
            return
        print('\n--- Incoming Packet ---')
        print('Cipher:', payload.get('cipher'))
        print('Params:', payload.get('params'))
        print('Ciphertext:', payload.get('ciphertext'))
        try:
            cipher = payload.get('cipher')
            params = payload.get('params') or {}
            ct = payload.get('ciphertext') or ''
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
            else:
                pt = '<unknown cipher>'
            print('Decrypted (server-side):', pt)
        except Exception as e:
            print('Decryption failed:', e)

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f'Server listening on {HOST}:{PORT}')
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    start_server()
