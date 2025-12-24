// Tab Management
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    const targetTab = btn.getAttribute('data-tab');
    
    // Remove active class from all tabs and contents
    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    
    // Add active class to clicked tab and corresponding content
    btn.classList.add('active');
    document.getElementById(`${targetTab}-tab`).classList.add('active');
  });
});

// ==================== ŞIFRELEME SEKMESI ====================

const encryptCipherSelect = document.getElementById('encrypt-cipher');
const encryptParamsDiv = document.getElementById('encrypt-params');
const encryptInputText = document.getElementById('encrypt-inputText');
const encryptResultArea = document.getElementById('encrypt-result');
const encryptBtn = document.getElementById('encryptBtn');
const encryptStatus = document.getElementById('encrypt-status');

function renderEncryptParams() {
  const c = encryptCipherSelect.value;
  encryptParamsDiv.innerHTML = '';
  if (c === 'caesar') {
    encryptParamsDiv.innerHTML = `<label>Shift Değeri</label><input id="encrypt_p_shift" type="number" value="3" />`;
  } else if (c === 'affine') {
    encryptParamsDiv.innerHTML = `<label>a (26 ile aralarında asal olmalı)</label><input id="encrypt_p_a" type="number" value="5" /><label>b</label><input id="encrypt_p_b" type="number" value="8" />`;
  } else if (c === 'vigenere') {
    encryptParamsDiv.innerHTML = `<label>Anahtar</label><input id="encrypt_p_key" value="SECRET" />`;
  } else if (c === 'substitution') {
    encryptParamsDiv.innerHTML = `<label>26 harfli anahtar</label><input id="encrypt_p_key" value="QWERTYUIOPASDFGHJKLZXCVBNM" placeholder="26 harf girilmelidir" />`;
  } else if (c === 'railfence') {
    encryptParamsDiv.innerHTML = `<label>Ray Sayısı</label><input id="encrypt_p_rails" type="number" value="3" min="2" />`;
  } else if (c === 'aes_lib' || c === 'aes_simple' || c === 'des_lib' || c === 'des_simple') {
    encryptParamsDiv.innerHTML = `
      <label>Anahtar (Key)</label>
      <input id="encrypt_p_key" type="text" value="mySecretKey123" placeholder="Şifreleme anahtarı" />
      <small style="color: var(--muted); font-size: 12px;">AES/DES için anahtar girin</small>
    `;
  } else if (c === 'rsa') {
    encryptParamsDiv.innerHTML = `
      <label>RSA Public Key (PEM formatında)</label>
      <textarea id="encrypt_p_public_key" rows="8" placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"></textarea>
      <div style="margin-top: 10px;">
        <button type="button" id="encrypt_generate_rsa_btn" class="btn-secondary" style="width: auto;">🔑 RSA Anahtar Çifti Oluştur</button>
      </div>
      <div id="encrypt_rsa_keys_display" style="margin-top: 10px; display: none;"></div>
    `;
    // RSA key generation button event
    setTimeout(() => {
      const genBtn = document.getElementById('encrypt_generate_rsa_btn');
      if (genBtn) {
        genBtn.addEventListener('click', generateRSAPairForEncrypt);
      }
    }, 100);
  }
}

encryptCipherSelect.addEventListener('change', renderEncryptParams);
renderEncryptParams();

// RSA Key Generation for Encrypt tab
async function generateRSAPairForEncrypt() {
  try {
    const res = await fetch('http://127.0.0.1:5001/generate-rsa-keys');
    const data = await res.json();
    if (data.status === 'ok') {
      document.getElementById('encrypt_p_public_key').value = data.public_key;
      const displayDiv = document.getElementById('encrypt_rsa_keys_display');
      displayDiv.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.1); padding: 12px; border-radius: 6px; margin-top: 10px;">
          <strong style="color: var(--success);">✅ RSA Anahtar Çifti Oluşturuldu</strong><br/>
          <small style="color: var(--muted);">Public Key yukarıya otomatik eklendi. Private Key'i çözme sekmesinde kullanacaksınız.</small>
          <details style="margin-top: 8px;">
            <summary style="cursor: pointer; color: var(--accent);">Private Key'i Göster (Çözme sekmesinde kullanılacak)</summary>
            <textarea readonly rows="6" style="width: 100%; margin-top: 8px; font-family: monospace; font-size: 11px;">${data.private_key}</textarea>
          </details>
        </div>
      `;
      displayDiv.style.display = 'block';
    }
  } catch (e) {
    alert('RSA anahtarları oluşturulamadı: ' + e.message);
  }
}

// Şifreleme işlemi
async function encryptAndSend() {
  const cipher = encryptCipherSelect.value;
  const params = {};
  
  if (cipher === 'caesar') {
    params.shift = parseInt(document.getElementById('encrypt_p_shift').value) || 0;
  } else if (cipher === 'affine') {
    params.a = parseInt(document.getElementById('encrypt_p_a').value) || 5;
    params.b = parseInt(document.getElementById('encrypt_p_b').value) || 8;
  } else if (cipher === 'vigenere' || cipher === 'substitution') {
    params.key = document.getElementById('encrypt_p_key').value || '';
  } else if (cipher === 'railfence') {
    params.rails = parseInt(document.getElementById('encrypt_p_rails').value) || 3;
  } else if (cipher === 'aes_lib' || cipher === 'aes_simple' || cipher === 'des_lib' || cipher === 'des_simple') {
    params.key = document.getElementById('encrypt_p_key').value || '';
    if (!params.key) {
      encryptResultArea.value = 'Lütfen anahtar girin!';
      encryptStatus.textContent = 'Hata: Anahtar boş';
      encryptStatus.className = 'result-status error';
      return;
    }
  } else if (cipher === 'rsa') {
    params.public_key = document.getElementById('encrypt_p_public_key').value || '';
    if (!params.public_key) {
      encryptResultArea.value = 'Lütfen RSA Public Key girin veya yeni anahtar çifti oluşturun!';
      encryptStatus.textContent = 'Hata: Public Key boş';
      encryptStatus.className = 'result-status error';
      return;
    }
  }

  const text = encryptInputText.value.trim();
  
  if (!text) {
    encryptResultArea.value = 'Lütfen şifrelenecek metni girin!';
    encryptStatus.textContent = 'Hata: Metin boş';
    encryptStatus.className = 'result-status error';
    return;
  }

  const payload = { action: 'encrypt', cipher, params, text };

  try {
    encryptStatus.textContent = 'Şifreleniyor ve gönderiliyor...';
    encryptStatus.className = 'result-status processing';
    
    const res = await fetch('http://127.0.0.1:5001/process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (data.error) {
      encryptResultArea.value = 'Hata: ' + data.error;
      encryptStatus.textContent = `Hata: ${data.error}`;
      encryptStatus.className = 'result-status error';
    } else if (data.result) {
      encryptResultArea.value = data.result;
      
      // AES ve DES için süre bilgisini göster
      let statusMessage = '✅ Şifreleme başarılı! Mesaj Çözme sekmesine gönderildi.';
      if (data.execution_time !== undefined && (cipher === 'aes_lib' || cipher === 'aes_simple' || cipher === 'des_lib' || cipher === 'des_simple')) {
        const timeMs = data.execution_time_ms.toFixed(3);
        const timeSec = data.execution_time.toFixed(6);
        const cipherName = cipher.includes('aes') ? 'AES' : 'DES';
        const methodType = cipher.includes('lib') ? 'Kütüphaneli' : 'Kütüphanesiz';
        statusMessage += ` ⏱️ ${cipherName} (${methodType}): ${timeMs} ms (${timeSec} s)`;
      }
      
      encryptStatus.textContent = statusMessage;
      encryptStatus.className = 'result-status success';
      
      // Çözme sekmesine parametreleri de gönder (şifreleme türü ve parametreler)
      sendToDecryptTab(data.result, cipher, params);
      
      // Otomatik olarak Çözme sekmesine geç
      setTimeout(() => {
        document.querySelector('[data-tab="decrypt"]').click();
      }, 500);
    } else {
      encryptResultArea.value = 'Bilinmeyen yanıt';
      encryptStatus.textContent = 'Bilinmeyen yanıt';
      encryptStatus.className = 'result-status error';
    }
  } catch (e) {
    encryptResultArea.value = 'Bağlantı hatası: ' + e.message;
    encryptStatus.textContent = `Bağlantı hatası: ${e.message}`;
    encryptStatus.className = 'result-status error';
  }
}

encryptBtn.addEventListener('click', encryptAndSend);

// ==================== ÇÖZME SEKMESI ====================

const decryptCipherSelect = document.getElementById('decrypt-cipher');
const decryptParamsDiv = document.getElementById('decrypt-params');
const decryptInputText = document.getElementById('decrypt-inputText');
const decryptResultArea = document.getElementById('decrypt-result');
const decryptBtn = document.getElementById('decryptBtn');
const autoDecryptBtn = document.getElementById('auto-decrypt-btn');
const decryptStatus = document.getElementById('decrypt-status');

// Çözme parametrelerini render et
function renderDecryptParams() {
  const c = decryptCipherSelect.value;
  decryptParamsDiv.innerHTML = '';
  if (c === 'caesar') {
    decryptParamsDiv.innerHTML = `<label>Shift Değeri</label><input id="decrypt_p_shift" type="number" value="3" />`;
  } else if (c === 'affine') {
    decryptParamsDiv.innerHTML = `<label>a (26 ile aralarında asal olmalı)</label><input id="decrypt_p_a" type="number" value="5" /><label>b</label><input id="decrypt_p_b" type="number" value="8" />`;
  } else if (c === 'vigenere') {
    decryptParamsDiv.innerHTML = `<label>Anahtar</label><input id="decrypt_p_key" value="SECRET" />`;
  } else if (c === 'substitution') {
    decryptParamsDiv.innerHTML = `<label>26 harfli anahtar</label><input id="decrypt_p_key" value="QWERTYUIOPASDFGHJKLZXCVBNM" placeholder="26 harf girilmelidir" />`;
  } else if (c === 'railfence') {
    decryptParamsDiv.innerHTML = `<label>Ray Sayısı</label><input id="decrypt_p_rails" type="number" value="3" min="2" />`;
  } else if (c === 'aes_lib' || c === 'aes_simple' || c === 'des_lib' || c === 'des_simple') {
    decryptParamsDiv.innerHTML = `
      <label>Anahtar (Key)</label>
      <input id="decrypt_p_key" type="text" value="mySecretKey123" placeholder="Şifreleme anahtarı" />
      <small style="color: var(--muted); font-size: 12px;">Şifreleme sırasında kullanılan aynı anahtarı girin</small>
    `;
  } else if (c === 'rsa') {
    decryptParamsDiv.innerHTML = `
      <label>RSA Private Key (PEM formatında)</label>
      <textarea id="decrypt_p_private_key" rows="8" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"></textarea>
      <small style="color: var(--muted); font-size: 12px;">Şifreleme sırasında oluşturulan private key'i girin</small>
    `;
  }
}

decryptCipherSelect.addEventListener('change', renderDecryptParams);
renderDecryptParams();

// Şifreleme sekmesinden gelen veriyi çözme sekmesine gönder
function sendToDecryptTab(ciphertext, cipher, params) {
  // Çözme sekmesindeki input'u doldur
  decryptInputText.value = ciphertext;
  
  // Çözme sekmesindeki şifreleme türünü ayarla
  decryptCipherSelect.value = cipher;
  renderDecryptParams();
  
  // Parametreleri doldur
  setTimeout(() => {
    if (cipher === 'caesar') {
      const shiftEl = document.getElementById('decrypt_p_shift');
      if (shiftEl) shiftEl.value = params.shift;
    } else if (cipher === 'affine') {
      const aEl = document.getElementById('decrypt_p_a');
      const bEl = document.getElementById('decrypt_p_b');
      if (aEl) aEl.value = params.a;
      if (bEl) bEl.value = params.b;
    } else if (cipher === 'vigenere' || cipher === 'substitution') {
      const keyEl = document.getElementById('decrypt_p_key');
      if (keyEl) keyEl.value = params.key;
    } else if (cipher === 'railfence') {
      const railsEl = document.getElementById('decrypt_p_rails');
      if (railsEl) railsEl.value = params.rails;
    } else if (cipher === 'aes_lib' || cipher === 'aes_simple' || cipher === 'des_lib' || cipher === 'des_simple') {
      const keyEl = document.getElementById('decrypt_p_key');
      if (keyEl) keyEl.value = params.key;
    }
    // RSA için parametreleri göndermeyiz (private key güvenlik nedeniyle)
  }, 100);
  
  // SSE ile de gönder (eski sistem uyumluluğu için)
  fetch('http://127.0.0.1:5001/publish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ciphertext })
  }).catch(err => console.error('SSE publish error', err));
}

// Çözme işlemi
async function decryptMessage() {
  const cipher = decryptCipherSelect.value;
  const params = {};
  
  if (cipher === 'caesar') {
    params.shift = parseInt(document.getElementById('decrypt_p_shift').value) || 0;
  } else if (cipher === 'affine') {
    params.a = parseInt(document.getElementById('decrypt_p_a').value) || 5;
    params.b = parseInt(document.getElementById('decrypt_p_b').value) || 8;
  } else if (cipher === 'vigenere' || cipher === 'substitution') {
    params.key = document.getElementById('decrypt_p_key').value || '';
  } else if (cipher === 'railfence') {
    params.rails = parseInt(document.getElementById('decrypt_p_rails').value) || 3;
  } else if (cipher === 'aes_lib' || cipher === 'aes_simple' || cipher === 'des_lib' || cipher === 'des_simple') {
    params.key = document.getElementById('decrypt_p_key').value || '';
    if (!params.key) {
      decryptResultArea.value = 'Lütfen anahtar girin!';
      decryptStatus.textContent = 'Hata: Anahtar boş';
      decryptStatus.className = 'result-status error';
      return;
    }
  } else if (cipher === 'rsa') {
    params.private_key = document.getElementById('decrypt_p_private_key').value || '';
    if (!params.private_key) {
      decryptResultArea.value = 'Lütfen RSA Private Key girin!';
      decryptStatus.textContent = 'Hata: Private Key boş';
      decryptStatus.className = 'result-status error';
      return;
    }
  }

  const text = decryptInputText.value.trim();
  
  if (!text) {
    decryptResultArea.value = 'Lütfen çözülecek metni girin!';
    decryptStatus.textContent = 'Hata: Metin boş';
    decryptStatus.className = 'result-status error';
    return;
  }

  const payload = { action: 'decrypt', cipher, params, text };

  try {
    decryptStatus.textContent = 'Çözülüyor...';
    decryptStatus.className = 'result-status processing';
    
    const res = await fetch('http://127.0.0.1:5001/process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (data.error) {
      decryptResultArea.value = 'Hata: ' + data.error;
      decryptStatus.textContent = `Hata: ${data.error}`;
      decryptStatus.className = 'result-status error';
    } else if (data.result) {
      decryptResultArea.value = data.result;
      
      // AES ve DES için süre bilgisini göster
      let statusMessage = '✅ Mesaj başarıyla çözüldü!';
      if (data.execution_time !== undefined && (cipher === 'aes_lib' || cipher === 'aes_simple' || cipher === 'des_lib' || cipher === 'des_simple')) {
        const timeMs = data.execution_time_ms.toFixed(3);
        const timeSec = data.execution_time.toFixed(6);
        const cipherName = cipher.includes('aes') ? 'AES' : 'DES';
        const methodType = cipher.includes('lib') ? 'Kütüphaneli' : 'Kütüphanesiz';
        statusMessage += ` ⏱️ ${cipherName} (${methodType}): ${timeMs} ms (${timeSec} s)`;
      }
      
      decryptStatus.textContent = statusMessage;
      decryptStatus.className = 'result-status success';
    } else {
      decryptResultArea.value = 'Bilinmeyen yanıt';
      decryptStatus.textContent = 'Bilinmeyen yanıt';
      decryptStatus.className = 'result-status error';
    }
  } catch (e) {
    decryptResultArea.value = 'Bağlantı hatası: ' + e.message;
    decryptStatus.textContent = `Bağlantı hatası: ${e.message}`;
    decryptStatus.className = 'result-status error';
  }
}

decryptBtn.addEventListener('click', decryptMessage);
autoDecryptBtn.addEventListener('click', () => {
  if (decryptInputText.value.trim()) {
    decryptMessage();
  } else {
    decryptStatus.textContent = 'Çözülecek metin yok!';
    decryptStatus.className = 'result-status error';
  }
});

// ==================== Server-Sent Events (SSE) - Otomatik Mesaj Aktarımı ====================

let eventSource = null;

function setupSSE() {
  if (eventSource) {
    eventSource.close();
  }
  
  try {
    eventSource = new EventSource('http://127.0.0.1:5001/stream');
    eventSource.onmessage = (e) => {
      try {
        const obj = JSON.parse(e.data);
        const ct = obj.ciphertext || '';
        if (ct) {
          // Çözme sekmesindeki input'u doldur
          decryptInputText.value = ct;
          decryptStatus.textContent = '✅ Yeni şifreli mesaj alındı!';
          decryptStatus.className = 'result-status success';
          
          // Otomatik olarak Çözme sekmesine geç
          setTimeout(() => {
            document.querySelector('[data-tab="decrypt"]').click();
          }, 300);
        }
      } catch (err) {
        console.error('SSE parse error', err);
      }
    };
    
    eventSource.onerror = (err) => {
      console.error('SSE error', err);
    };
  } catch (err) {
    console.error('SSE setup error', err);
  }
}

// SSE'yi başlat
setupSSE();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  if (eventSource) {
    eventSource.close();
  }
});