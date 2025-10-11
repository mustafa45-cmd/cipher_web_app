const cipherSelect = document.getElementById('cipher');
const paramsDiv = document.getElementById('params');
const inputText = document.getElementById('inputText');
const resultArea = document.getElementById('result');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');

function renderParams(){
  const c = cipherSelect.value;
  paramsDiv.innerHTML = '';
  if(c === 'caesar'){
    paramsDiv.innerHTML = `<label>Shift</label><input id="p_shift" value="3" />`;
  } else if(c === 'affine'){
    paramsDiv.innerHTML = `<label>a (coprime with 26)</label><input id="p_a" value="5" /><label>b</label><input id="p_b" value="8" />`;
  } else if(c === 'vigenere'){
    paramsDiv.innerHTML = `<label>Key</label><input id="p_key" value="SECRET" />`;
  } else if(c === 'substitution'){
    paramsDiv.innerHTML = `<label>26-letter key</label><input id="p_key" value="QWERTYUIOPASDFGHJKLZXCVBNM" />`;
  } else if(c === 'railfence'){
    paramsDiv.innerHTML = `<label>Rails</label><input id="p_rails" value="3" />`;
  }
}

cipherSelect.addEventListener('change', renderParams);
renderParams();

async function send(action){
  const cipher = cipherSelect.value;
  const params = {};
  if(cipher === 'caesar'){
    params.shift = document.getElementById('p_shift').value;
  } else if(cipher === 'affine'){
    params.a = document.getElementById('p_a').value;
    params.b = document.getElementById('p_b').value;
  } else if(cipher === 'vigenere' || cipher === 'substitution'){
    params.key = document.getElementById('p_key').value;
  } else if(cipher === 'railfence'){
    params.rails = document.getElementById('p_rails').value;
  }
  const text = inputText.value;
  const payload = { action, cipher, params, text };
  try{
    const res = await fetch('http://127.0.0.1:5000/process', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if(data.error) resultArea.value = 'Error: ' + data.error;
    else resultArea.value = JSON.stringify(data, null, 2);
  }catch(e){
    resultArea.value = 'Fetch error: ' + e.message;
  }
}

encryptBtn.addEventListener('click', ()=> send('encrypt'));
decryptBtn.addEventListener('click', ()=> send('decrypt'));
