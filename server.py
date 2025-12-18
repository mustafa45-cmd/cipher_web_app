"""
Kriptoloji Server
Tüm şifreleme metodlarını destekler
"""
import socket
import json
import sys
from ciphers.classical import (
    CaesarCipher, RailFenceCipher, VigenereCipher, VernamCipher,
    PlayfairCipher, RouteCipher, AffineCipher, HillCipher, ColumnarCipher
)
from ciphers.modern import (
    AESLibrary, DESLibrary, AESNoLibrary, DESNoLibrary
)


class CipherServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        
    def start(self):
        """Server'ı başlat"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"Server {self.host}:{self.port} adresinde dinleniyor...")
            print("Bağlantı bekleniyor...")
            
            while True:
                client_socket, address = self.socket.accept()
                print(f"\n{address} adresinden bağlantı kabul edildi")
                
                try:
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"Hata: {e}")
                finally:
                    client_socket.close()
                    print(f"{address} bağlantısı kapatıldı\n")
                    
        except KeyboardInterrupt:
            print("\nServer kapatılıyor...")
        except Exception as e:
            print(f"Server hatası: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def handle_client(self, client_socket):
        """Client ile iletişimi yönet"""
        while True:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                request = json.loads(data)
                response = self.process_request(request)
                
                client_socket.send(json.dumps(response).encode('utf-8'))
                
            except json.JSONDecodeError:
                response = {"status": "error", "message": "Geçersiz JSON formatı"}
                client_socket.send(json.dumps(response).encode('utf-8'))
            except Exception as e:
                response = {"status": "error", "message": str(e)}
                client_socket.send(json.dumps(response).encode('utf-8'))
    
    def process_request(self, request):
        """İsteği işle ve sonucu döndür"""
        try:
            method = request.get('method')
            text = request.get('text', '')
            cipher_type = request.get('cipher_type')
            params = request.get('params', {})
            
            if method not in ['encrypt', 'decrypt']:
                return {"status": "error", "message": "Geçersiz metod"}
            
            result = self.apply_cipher(method, text, cipher_type, params)
            
            return {
                "status": "success",
                "result": result,
                "method": method,
                "cipher_type": cipher_type
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def apply_cipher(self, method, text, cipher_type, params):
        """Şifreleme metodunu uygula"""
        cipher_map = {
            'caesar': CaesarCipher,
            'rail_fence': RailFenceCipher,
            'vigenere': VigenereCipher,
            'vernam': VernamCipher,
            'playfair': PlayfairCipher,
            'route': RouteCipher,
            'affine': AffineCipher,
            'hill': HillCipher,
            'columnar': ColumnarCipher,
            'aes_library': AESLibrary,
            'aes_no_library': AESNoLibrary,
            'des_library': DESLibrary,
            'des_no_library': DESNoLibrary
        }
        
        if cipher_type not in cipher_map:
            raise ValueError(f"Desteklenmeyen şifreleme metodu: {cipher_type}")
        
        cipher_class = cipher_map[cipher_type]
        
        # Her şifreleme metodunun parametrelerini işle
        if cipher_type == 'caesar':
            shift = params.get('shift', 3)
            return getattr(cipher_class, method)(text, shift)
        
        elif cipher_type == 'rail_fence':
            rails = params.get('rails', 3)
            return getattr(cipher_class, method)(text, rails)
        
        elif cipher_type == 'vigenere':
            key = params.get('key', 'KEY')
            return getattr(cipher_class, method)(text, key)
        
        elif cipher_type == 'vernam':
            key = params.get('key', '')
            if not key:
                raise ValueError("Vernam için key gereklidir")
            return getattr(cipher_class, method)(text, key)
        
        elif cipher_type == 'playfair':
            key = params.get('key', 'MONARCHY')
            return getattr(cipher_class, method)(text, key)
        
        elif cipher_type == 'route':
            rows = params.get('rows', 4)
            cols = params.get('cols', 4)
            return getattr(cipher_class, method)(text, rows, cols)
        
        elif cipher_type == 'affine':
            a = params.get('a', 5)
            b = params.get('b', 8)
            return getattr(cipher_class, method)(text, a, b)
        
        elif cipher_type == 'hill':
            key_matrix = params.get('key_matrix', [[6, 24, 1], [13, 16, 10], [20, 17, 15]])
            return getattr(cipher_class, method)(text, key_matrix)
        
        elif cipher_type == 'columnar':
            key = params.get('key', 'KEYWORD')
            return getattr(cipher_class, method)(text, key)
        
        elif cipher_type in ['aes_library', 'aes_no_library', 'des_library', 'des_no_library']:
            key = params.get('key', 'secretkey')
            return getattr(cipher_class, method)(text, key)
        
        else:
            raise ValueError(f"Parametreler işlenemedi: {cipher_type}")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
    
    server = CipherServer(host, port)
    server.start()


if __name__ == '__main__':
    main()

