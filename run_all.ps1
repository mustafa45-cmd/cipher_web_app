# run_all.ps1
# Tek tıkla Cipher Web App başlatma scripti

# --- 1. TCP Server ---
Start-Process powershell -ArgumentList "-NoExit","-Command & 'C:\Users\PC\Desktop\cipher_web_app\server.py'"

# --- 2. Flask API ---
Start-Process powershell -ArgumentList "-NoExit","-Command & 'C:\Users\PC\AppData\Local\Python\bin\python.exe' 'C:\Users\PC\Desktop\cipher_web_app\client_api.py'"

# --- 3. Frontend ---
Start-Process powershell -ArgumentList "-NoExit","-Command cd 'C:\Users\PC\Desktop\cipher_web_app\frontend'; python -m http.server 8000"