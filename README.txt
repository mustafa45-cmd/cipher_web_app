Cipher Web App - README
-----------------------

İçerik:
- server.py       : TCP server (alınan paketleri çözer ve konsola yazdırır)
- client_api.py   : Flask tabanlı HTTP API. Frontend bu API'ye POST atar; API şifreleme/deşifreleme yapar ve TCP server'a paket iletir.
- frontend/       : index.html, script.js, style.css

Çalıştırma:
1) Önce TCP server'i başlatın:
   python server.py

2) Sonra client API'yi çalıştırın (ayrı terminal):
   pip install flask flask-cors
   python client_api.py

3) Tarayıcıda frontend/index.html dosyasını açın (doğrudan dosyadan açabilirsiniz) veya basit bir static server kullanın.
   - Eğer CORS izinleri nedeniyle fetch çalışmazsa, frontend'i aynı makinede `python -m http.server 8000` ile serve edin:
     cd frontend
     python -m http.server 8000
     ve tarayıcıda http://127.0.0.1:8000 açın

Notlar:
- Bu proje eğitim amaçlıdır. Gerçek üretimde TLS/HTTPS ve güvenli anahtar yönetimi gereklidir.
- client_api.py gelen istekten sonra hem encrypt/decrypt sonucu JSON olarak döner hem de TCP server'a orijinal paket (ciphertext ve params) gönderir.
