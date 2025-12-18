"""
Kriptoloji Client
Server'a bağlanarak şifreleme işlemleri yapar
"""
import socket
import json
import sys


class CipherClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
    
    def connect(self):
        """Server'a bağlan"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Server'a bağlandı: {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Bağlantı hatası: {e}")
            return False
    
    def disconnect(self):
        """Server bağlantısını kapat"""
        if hasattr(self, 'socket'):
            self.socket.close()
    
    def send_request(self, method, text, cipher_type, params=None):
        """Server'a istek gönder"""
        if not hasattr(self, 'socket'):
            if not self.connect():
                return None
        
        request = {
            'method': method,
            'text': text,
            'cipher_type': cipher_type,
            'params': params or {}
        }
        
        try:
            self.socket.send(json.dumps(request).encode('utf-8'))
            response_data = self.socket.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            return response
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def encrypt(self, text, cipher_type, params=None):
        """Metni şifrele"""
        return self.send_request('encrypt', text, cipher_type, params)
    
    def decrypt(self, text, cipher_type, params=None):
        """Metnin şifresini çöz"""
        return self.send_request('decrypt', text, cipher_type, params)


def print_menu():
    """Menüyü yazdır"""
    print("\n" + "="*50)
    print("ŞİFRELEME METODLARI")
    print("="*50)
    print("1.  Sezar (Caesar)")
    print("2.  Rail Fence")
    print("3.  Vigenere")
    print("4.  Vernam")
    print("5.  Playfair")
    print("6.  Route")
    print("7.  Affine")
    print("8.  Hill Cipher")
    print("9.  Columnar")
    print("10. AES (Kütüphaneli)")
    print("11. AES (Kütüphanesiz)")
    print("12. DES (Kütüphaneli)")
    print("13. DES (Kütüphanesiz)")
    print("0.  Çıkış")
    print("="*50)


def get_cipher_params(cipher_type):
    """Şifreleme metoduna göre parametreleri al"""
    params = {}
    
    if cipher_type == 'caesar':
        shift = input("Shift değeri (varsayılan: 3): ").strip()
        params['shift'] = int(shift) if shift else 3
    
    elif cipher_type == 'rail_fence':
        rails = input("Ray sayısı (varsayılan: 3): ").strip()
        params['rails'] = int(rails) if rails else 3
    
    elif cipher_type == 'vigenere':
        key = input("Anahtar (varsayılan: KEY): ").strip()
        params['key'] = key if key else 'KEY'
    
    elif cipher_type == 'vernam':
        key = input("Anahtar (metin uzunluğunda olmalı): ").strip()
        if not key:
            print("Hata: Vernam için anahtar gereklidir!")
            return None
        params['key'] = key
    
    elif cipher_type == 'playfair':
        key = input("Anahtar (varsayılan: MONARCHY): ").strip()
        params['key'] = key if key else 'MONARCHY'
    
    elif cipher_type == 'route':
        rows = input("Satır sayısı (varsayılan: 4): ").strip()
        cols = input("Sütun sayısı (varsayılan: 4): ").strip()
        params['rows'] = int(rows) if rows else 4
        params['cols'] = int(cols) if cols else 4
    
    elif cipher_type == 'affine':
        a = input("a değeri (varsayılan: 5): ").strip()
        b = input("b değeri (varsayılan: 8): ").strip()
        params['a'] = int(a) if a else 5
        params['b'] = int(b) if b else 8
    
    elif cipher_type == 'hill':
        print("Hill Cipher için 3x3 matris girin (her satır için 3 sayı):")
        matrix = []
        for i in range(3):
            row = input(f"Satır {i+1}: ").strip().split()
            if len(row) == 3:
                matrix.append([int(x) for x in row])
            else:
                print("Varsayılan matris kullanılıyor")
                matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
                break
        params['key_matrix'] = matrix
    
    elif cipher_type == 'columnar':
        key = input("Anahtar (varsayılan: KEYWORD): ").strip()
        params['key'] = key if key else 'KEYWORD'
    
    elif cipher_type in ['aes_library', 'aes_no_library', 'des_library', 'des_no_library']:
        key = input("Anahtar (varsayılan: secretkey): ").strip()
        params['key'] = key if key else 'secretkey'
    
    return params


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
    
    client = CipherClient(host, port)
    
    cipher_map = {
        '1': 'caesar',
        '2': 'rail_fence',
        '3': 'vigenere',
        '4': 'vernam',
        '5': 'playfair',
        '6': 'route',
        '7': 'affine',
        '8': 'hill',
        '9': 'columnar',
        '10': 'aes_library',
        '11': 'aes_no_library',
        '12': 'des_library',
        '13': 'des_no_library'
    }
    
    while True:
        print_menu()
        choice = input("\nSeçiminiz: ").strip()
        
        if choice == '0':
            print("Çıkılıyor...")
            client.disconnect()
            break
        
        if choice not in cipher_map:
            print("Geçersiz seçim!")
            continue
        
        cipher_type = cipher_map[choice]
        
        print("\nİşlem seçin:")
        print("1. Şifrele")
        print("2. Şifre Çöz")
        operation = input("Seçiminiz: ").strip()
        
        if operation not in ['1', '2']:
            print("Geçersiz işlem!")
            continue
        
        method = 'encrypt' if operation == '1' else 'decrypt'
        
        text = input(f"\n{'Şifrelenecek' if method == 'encrypt' else 'Şifresi çözülecek'} metin: ").strip()
        if not text:
            print("Metin boş olamaz!")
            continue
        
        params = get_cipher_params(cipher_type)
        if params is None:
            continue
        
        # Vernam için özel kontrol
        if cipher_type == 'vernam' and method == 'encrypt':
            if len(text) != len(params.get('key', '')):
                print("Uyarı: Vernam için anahtar uzunluğu metin uzunluğuna eşit olmalıdır!")
                # Anahtarı metin uzunluğuna göre ayarla
                key = params.get('key', '')
                if len(key) < len(text):
                    key = (key * ((len(text) // len(key)) + 1))[:len(text)]
                elif len(key) > len(text):
                    key = key[:len(text)]
                params['key'] = key
        
        print("\nİşlem yapılıyor...")
        
        if method == 'encrypt':
            response = client.encrypt(text, cipher_type, params)
        else:
            response = client.decrypt(text, cipher_type, params)
        
        if response and response.get('status') == 'success':
            print(f"\n{'Şifrelenmiş' if method == 'encrypt' else 'Çözülmüş'} metin:")
            print(f"  {response['result']}")
        else:
            print(f"\nHata: {response.get('message', 'Bilinmeyen hata') if response else 'Bağlantı hatası'}")


if __name__ == '__main__':
    main()

