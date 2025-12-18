"""
Klasik şifreleme metodları
"""
import re
import math


class CaesarCipher:
    """Sezar şifreleme"""
    
    @staticmethod
    def encrypt(text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return result
    
    @staticmethod
    def decrypt(text, shift):
        return CaesarCipher.encrypt(text, -shift)


class RailFenceCipher:
    """Rail Fence şifreleme"""
    
    @staticmethod
    def encrypt(text, rails):
        if rails == 1:
            return text
        
        fence = [['\n' for _ in range(len(text))] for _ in range(rails)]
        direction = False
        row, col = 0, 0
        
        for char in text:
            if row == 0 or row == rails - 1:
                direction = not direction
            fence[row][col] = char
            col += 1
            row += 1 if direction else -1
        
        result = []
        for i in range(rails):
            for j in range(len(text)):
                if fence[i][j] != '\n':
                    result.append(fence[i][j])
        return ''.join(result)
    
    @staticmethod
    def decrypt(text, rails):
        if rails == 1:
            return text
        
        fence = [['\n' for _ in range(len(text))] for _ in range(rails)]
        direction = None
        row, col = 0, 0
        
        for i in range(len(text)):
            if row == 0:
                direction = True
            if row == rails - 1:
                direction = False
            fence[row][col] = '*'
            col += 1
            row += 1 if direction else -1
        
        index = 0
        for i in range(rails):
            for j in range(len(text)):
                if fence[i][j] == '*' and index < len(text):
                    fence[i][j] = text[index]
                    index += 1
        
        result = []
        row, col = 0, 0
        direction = None
        for i in range(len(text)):
            if row == 0:
                direction = True
            if row == rails - 1:
                direction = False
            if fence[row][col] != '*':
                result.append(fence[row][col])
            col += 1
            row += 1 if direction else -1
        
        return ''.join(result)


class VigenereCipher:
    """Vigenere şifreleme"""
    
    @staticmethod
    def encrypt(text, key):
        key = key.upper()
        key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]
        result = ""
        
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key_repeated[key_index % len(key_repeated)]) - 65
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result
    
    @staticmethod
    def decrypt(text, key):
        key = key.upper()
        key_repeated = (key * (len(text) // len(key) + 1))[:len(text)]
        result = ""
        
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key_repeated[key_index % len(key_repeated)]) - 65
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                key_index += 1
            else:
                result += char
        return result


class VernamCipher:
    """Vernam (One-Time Pad) şifreleme"""
    
    @staticmethod
    def encrypt(text, key):
        if len(key) != len(text):
            raise ValueError("Key uzunluğu metin uzunluğuna eşit olmalıdır")
        
        result = ""
        for i in range(len(text)):
            result += chr(ord(text[i]) ^ ord(key[i]))
        return result
    
    @staticmethod
    def decrypt(text, key):
        return VernamCipher.encrypt(text, key)  # XOR simetrik


class PlayfairCipher:
    """Playfair şifreleme"""
    
    @staticmethod
    def _prepare_key(key):
        key = key.upper().replace('J', 'I')
        key_matrix = []
        seen = set()
        
        for char in key:
            if char.isalpha() and char not in seen:
                key_matrix.append(char)
                seen.add(char)
        
        for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if char not in seen:
                key_matrix.append(char)
        
        return [key_matrix[i:i+5] for i in range(0, 25, 5)]
    
    @staticmethod
    def _find_position(matrix, char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j
        return None, None
    
    @staticmethod
    def _prepare_text(text):
        text = re.sub(r'[^A-Z]', '', text.upper().replace('J', 'I'))
        result = []
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                result.append(text[i] + 'X')
                i += 1
            elif text[i] == text[i+1]:
                result.append(text[i] + 'X')
                i += 1
            else:
                result.append(text[i] + text[i+1])
                i += 2
        return result
    
    @staticmethod
    def encrypt(text, key):
        matrix = PlayfairCipher._prepare_key(key)
        pairs = PlayfairCipher._prepare_text(text)
        result = []
        
        for pair in pairs:
            row1, col1 = PlayfairCipher._find_position(matrix, pair[0])
            row2, col2 = PlayfairCipher._find_position(matrix, pair[1])
            
            if row1 == row2:
                result.append(matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5])
            elif col1 == col2:
                result.append(matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2])
            else:
                result.append(matrix[row1][col2] + matrix[row2][col1])
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(text, key):
        matrix = PlayfairCipher._prepare_key(key)
        pairs = PlayfairCipher._prepare_text(text)
        result = []
        
        for pair in pairs:
            row1, col1 = PlayfairCipher._find_position(matrix, pair[0])
            row2, col2 = PlayfairCipher._find_position(matrix, pair[1])
            
            if row1 == row2:
                result.append(matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5])
            elif col1 == col2:
                result.append(matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2])
            else:
                result.append(matrix[row1][col2] + matrix[row2][col1])
        
        return ''.join(result)


class RouteCipher:
    """Route şifreleme (spiral okuma)"""
    
    @staticmethod
    def encrypt(text, rows, cols):
        text = text.upper().replace(' ', 'X')
        while len(text) < rows * cols:
            text += 'X'
        
        matrix = [list(text[i:i+cols]) for i in range(0, len(text), cols)]
        result = []
        
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        
        while top <= bottom and left <= right:
            for i in range(left, right + 1):
                result.append(matrix[top][i])
            top += 1
            
            for i in range(top, bottom + 1):
                result.append(matrix[i][right])
            right -= 1
            
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    result.append(matrix[bottom][i])
                bottom -= 1
            
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    result.append(matrix[i][left])
                left += 1
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(text, rows, cols):
        if len(text) != rows * cols:
            text = text.ljust(rows * cols, 'X')
        
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        text_list = list(text)
        
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        
        while top <= bottom and left <= right and text_list:
            for i in range(left, right + 1):
                if text_list:
                    matrix[top][i] = text_list.pop(0)
            top += 1
            
            for i in range(top, bottom + 1):
                if text_list:
                    matrix[i][right] = text_list.pop(0)
            right -= 1
            
            if top <= bottom:
                for i in range(right, left - 1, -1):
                    if text_list:
                        matrix[bottom][i] = text_list.pop(0)
                bottom -= 1
            
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    if text_list:
                        matrix[i][left] = text_list.pop(0)
                left += 1
        
        result = ''.join(''.join(row) for row in matrix)
        return result.rstrip('X')


class AffineCipher:
    """Affine şifreleme: E(x) = (ax + b) mod 26"""
    
    @staticmethod
    def _gcd(a, b):
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def _mod_inverse(a, m=26):
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None
    
    @staticmethod
    def encrypt(text, a, b):
        if AffineCipher._gcd(a, 26) != 1:
            raise ValueError("a ve 26 aralarında asal olmalıdır")
        
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                x = ord(char) - ascii_offset
                encrypted = (a * x + b) % 26
                result += chr(encrypted + ascii_offset)
            else:
                result += char
        return result
    
    @staticmethod
    def decrypt(text, a, b):
        a_inv = AffineCipher._mod_inverse(a)
        if a_inv is None:
            raise ValueError("a'nın modüler tersi bulunamadı")
        
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                y = ord(char) - ascii_offset
                decrypted = (a_inv * (y - b)) % 26
                result += chr(decrypted + ascii_offset)
            else:
                result += char
        return result


class HillCipher:
    """Hill şifreleme"""
    
    @staticmethod
    def _text_to_matrix(text, n):
        text = re.sub(r'[^A-Z]', '', text.upper())
        while len(text) % n != 0:
            text += 'X'
        
        matrix = []
        for i in range(0, len(text), n):
            row = [ord(char) - 65 for char in text[i:i+n]]
            matrix.append(row)
        return matrix
    
    @staticmethod
    def _matrix_to_text(matrix):
        result = ""
        for row in matrix:
            for val in row:
                result += chr(int(val % 26) + 65)
        return result
    
    @staticmethod
    def _matrix_multiply(A, B):
        """İki matrisi çarp"""
        rows_A, cols_A = len(A), len(A[0])
        rows_B, cols_B = len(B), len(B[0])
        
        if cols_A != rows_B:
            raise ValueError("Matris boyutları uyumsuz")
        
        result = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
        for i in range(rows_A):
            for j in range(cols_B):
                for k in range(cols_A):
                    result[i][j] += A[i][k] * B[k][j]
                result[i][j] %= 26
        return result
    
    @staticmethod
    def _matrix_determinant(matrix):
        """3x3 matris determinantı hesapla"""
        if len(matrix) != 3 or len(matrix[0]) != 3:
            raise ValueError("Sadece 3x3 matrisler destekleniyor")
        
        a, b, c = matrix[0]
        d, e, f = matrix[1]
        g, h, i = matrix[2]
        
        det = (a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)) % 26
        return det
    
    @staticmethod
    def _matrix_adjoint(matrix):
        """3x3 matris adjoint (ek matris) hesapla"""
        if len(matrix) != 3 or len(matrix[0]) != 3:
            raise ValueError("Sadece 3x3 matrisler destekleniyor")
        
        a, b, c = matrix[0]
        d, e, f = matrix[1]
        g, h, i = matrix[2]
        
        adj = [
            [(e * i - f * h) % 26, -(b * i - c * h) % 26, (b * f - c * e) % 26],
            [-(d * i - f * g) % 26, (a * i - c * g) % 26, -(a * f - c * d) % 26],
            [(d * h - e * g) % 26, -(a * h - b * g) % 26, (a * e - b * d) % 26]
        ]
        
        # Transpose al
        adj_transposed = [[adj[j][i] for j in range(3)] for i in range(3)]
        return adj_transposed
    
    @staticmethod
    def _mod_inverse_matrix(matrix, mod=26):
        """Matrisin modüler tersini hesapla"""
        det = HillCipher._matrix_determinant(matrix)
        det_inv = AffineCipher._mod_inverse(det, mod)
        if det_inv is None:
            raise ValueError("Matrisin determinantı modüler tersi yok")
        
        adj = HillCipher._matrix_adjoint(matrix)
        # Adjoint'i determinant tersi ile çarp
        result = [[(det_inv * adj[i][j]) % mod for j in range(len(adj[0]))] for i in range(len(adj))]
        return result
    
    @staticmethod
    def encrypt(text, key_matrix):
        n = len(key_matrix)
        # Key matrix'i mod 26'ya göre normalize et
        key = [[key_matrix[i][j] % 26 for j in range(n)] for i in range(n)]
        
        text_matrix = HillCipher._text_to_matrix(text, n)
        encrypted_matrix = HillCipher._matrix_multiply(text_matrix, key)
        return HillCipher._matrix_to_text(encrypted_matrix)
    
    @staticmethod
    def decrypt(text, key_matrix):
        n = len(key_matrix)
        # Key matrix'i mod 26'ya göre normalize et
        key = [[key_matrix[i][j] % 26 for j in range(n)] for i in range(n)]
        key_inv = HillCipher._mod_inverse_matrix(key)
        
        text_matrix = HillCipher._text_to_matrix(text, n)
        decrypted_matrix = HillCipher._matrix_multiply(text_matrix, key_inv)
        return HillCipher._matrix_to_text(decrypted_matrix)


class ColumnarCipher:
    """Columnar Transposition şifreleme"""
    
    @staticmethod
    def encrypt(text, key):
        text = text.upper().replace(' ', '')
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        
        cols = len(key)
        rows = math.ceil(len(text) / cols)
        
        while len(text) < rows * cols:
            text += 'X'
        
        matrix = [list(text[i:i+cols]) for i in range(0, len(text), cols)]
        
        result = []
        for col_idx in key_order:
            for row in matrix:
                result.append(row[col_idx])
        
        return ''.join(result)
    
    @staticmethod
    def decrypt(text, key):
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        cols = len(key)
        rows = len(text) // cols
        
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        text_idx = 0
        for col_idx in key_order:
            for row in range(rows):
                matrix[row][col_idx] = text[text_idx]
                text_idx += 1
        
        result = ''.join(''.join(row) for row in matrix)
        return result.rstrip('X')

