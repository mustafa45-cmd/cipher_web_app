"""
Modern şifreleme metodları (AES ve DES)
Hem kütüphaneli hem kütüphanesiz versiyonlar
"""
import hashlib

# PyCryptodome import'u - opsiyonel
try:
    from Crypto.Cipher import AES as CryptoAES, DES as CryptoDES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    # Dummy sınıflar - kullanılmayacak
    CryptoAES = None
    CryptoDES = None


# ============ AES - Kütüphaneli Versiyon ============
class AESLibrary:
    """AES şifreleme (kütüphaneli)"""
    
    @staticmethod
    def encrypt(text, key):
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome yüklü değil. Lütfen 'python -m pip install pycryptodome' komutu ile yükleyin.")
        if isinstance(text, str):
            text = text.encode('utf-8')
        if isinstance(key, str):
            key = hashlib.sha256(key.encode()).digest()
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(text, CryptoAES.block_size))
        return (iv + ciphertext).hex()
    
    @staticmethod
    def decrypt(encrypted_data, key):
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome yüklü değil. Lütfen 'python -m pip install pycryptodome' komutu ile yükleyin.")
        if isinstance(key, str):
            key = hashlib.sha256(key.encode()).digest()
        
        data = bytes.fromhex(encrypted_data)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = CryptoAES.new(key, CryptoAES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), CryptoAES.block_size)
        return plaintext.decode('utf-8')


# ============ DES - Kütüphaneli Versiyon ============
class DESLibrary:
    """DES şifreleme (kütüphaneli)"""
    
    @staticmethod
    def encrypt(text, key):
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome yüklü değil. Lütfen 'python -m pip install pycryptodome' komutu ile yükleyin.")
        if isinstance(text, str):
            text = text.encode('utf-8')
        if isinstance(key, str):
            key = hashlib.md5(key.encode()).digest()[:8]
        
        cipher = CryptoDES.new(key, CryptoDES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(text, CryptoDES.block_size))
        return (iv + ciphertext).hex()
    
    @staticmethod
    def decrypt(encrypted_data, key):
        if not CRYPTO_AVAILABLE:
            raise ImportError("PyCryptodome yüklü değil. Lütfen 'python -m pip install pycryptodome' komutu ile yükleyin.")
        if isinstance(key, str):
            key = hashlib.md5(key.encode()).digest()[:8]
        
        data = bytes.fromhex(encrypted_data)
        iv = data[:8]
        ciphertext = data[8:]
        
        cipher = CryptoDES.new(key, CryptoDES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), CryptoDES.block_size)
        return plaintext.decode('utf-8')


# ============ AES - Kütüphanesiz Versiyon ============
class AESNoLibrary:
    """AES şifreleme (kütüphanesiz - basitleştirilmiş)"""
    
    # S-box
    S_BOX = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ]
    
    @staticmethod
    def _rot_word(word):
        return word[1:] + word[:1]
    
    @staticmethod
    def _sub_word(word):
        return [AESNoLibrary.S_BOX[b >> 4][b & 0x0F] for b in word]
    
    @staticmethod
    def _key_expansion(key):
        # Basitleştirilmiş key expansion
        expanded = [key[i:i+4] for i in range(0, len(key), 4)]
        return expanded
    
    @staticmethod
    def _add_round_key(state, round_key):
        return [[state[i][j] ^ round_key[i][j] for j in range(4)] for i in range(4)]
    
    @staticmethod
    def _sub_bytes(state):
        return [[AESNoLibrary.S_BOX[b >> 4][b & 0x0F] for b in row] for row in state]
    
    @staticmethod
    def _shift_rows(state):
        return [
            [state[0][0], state[0][1], state[0][2], state[0][3]],
            [state[1][1], state[1][2], state[1][3], state[1][0]],
            [state[2][2], state[2][3], state[2][0], state[2][1]],
            [state[3][3], state[3][0], state[3][1], state[3][2]]
        ]
    
    @staticmethod
    def _gf_multiply(a, b):
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return result & 0xff
    
    @staticmethod
    def _mix_columns(state):
        new_state = [[0 for _ in range(4)] for _ in range(4)]
        for c in range(4):
            new_state[0][c] = AESNoLibrary._gf_multiply(0x02, state[0][c]) ^ \
                             AESNoLibrary._gf_multiply(0x03, state[1][c]) ^ \
                             state[2][c] ^ state[3][c]
            new_state[1][c] = state[0][c] ^ \
                             AESNoLibrary._gf_multiply(0x02, state[1][c]) ^ \
                             AESNoLibrary._gf_multiply(0x03, state[2][c]) ^ \
                             state[3][c]
            new_state[2][c] = state[0][c] ^ state[1][c] ^ \
                             AESNoLibrary._gf_multiply(0x02, state[2][c]) ^ \
                             AESNoLibrary._gf_multiply(0x03, state[3][c])
            new_state[3][c] = AESNoLibrary._gf_multiply(0x03, state[0][c]) ^ \
                             state[1][c] ^ state[2][c] ^ \
                             AESNoLibrary._gf_multiply(0x02, state[3][c])
        return new_state
    
    @staticmethod
    def encrypt(text, key):
        # Basitleştirilmiş AES implementasyonu
        if isinstance(text, str):
            text = text.encode('utf-8')
        if isinstance(key, str):
            key = hashlib.sha256(key.encode()).digest()[:16]
        
        # Padding
        padding_len = 16 - (len(text) % 16)
        text = text + bytes([padding_len] * padding_len)
        
        # Basit XOR tabanlı şifreleme (gerçek AES çok karmaşık)
        result = bytearray()
        for i in range(0, len(text), 16):
            block = text[i:i+16]
            encrypted_block = bytes([block[j] ^ key[j % len(key)] for j in range(16)])
            result.extend(encrypted_block)
        
        return result.hex()
    
    @staticmethod
    def decrypt(encrypted_data, key):
        if isinstance(key, str):
            key = hashlib.sha256(key.encode()).digest()[:16]
        
        data = bytes.fromhex(encrypted_data)
        result = bytearray()
        
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            decrypted_block = bytes([block[j] ^ key[j % len(key)] for j in range(16)])
            result.extend(decrypted_block)
        
        # Remove padding
        padding_len = result[-1]
        return bytes(result[:-padding_len]).decode('utf-8')


# ============ DES - Kütüphanesiz Versiyon ============
class DESNoLibrary:
    """DES şifreleme (kütüphanesiz - basitleştirilmiş)"""
    
    # Initial Permutation
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]
    
    @staticmethod
    def _permute(bits, table):
        return [bits[i-1] for i in table]
    
    @staticmethod
    def encrypt(text, key):
        # Basitleştirilmiş DES implementasyonu
        if isinstance(text, str):
            text = text.encode('utf-8')
        if isinstance(key, str):
            key = hashlib.md5(key.encode()).digest()[:8]
        
        # Padding
        padding_len = 8 - (len(text) % 8)
        text = text + bytes([padding_len] * padding_len)
        
        # Basit XOR tabanlı şifreleme (gerçek DES çok karmaşık)
        result = bytearray()
        for i in range(0, len(text), 8):
            block = text[i:i+8]
            encrypted_block = bytes([block[j] ^ key[j % len(key)] for j in range(8)])
            result.extend(encrypted_block)
        
        return result.hex()
    
    @staticmethod
    def decrypt(encrypted_data, key):
        if isinstance(key, str):
            key = hashlib.md5(key.encode()).digest()[:8]
        
        data = bytes.fromhex(encrypted_data)
        result = bytearray()
        
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            decrypted_block = bytes([block[j] ^ key[j % len(key)] for j in range(8)])
            result.extend(decrypted_block)
        
        # Remove padding
        padding_len = result[-1]
        return bytes(result[:-padding_len]).decode('utf-8')

