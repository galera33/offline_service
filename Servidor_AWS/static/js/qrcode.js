function gerarQRCode() {
    const cpf = document.getElementById('cpf').value;
    if(!cpf || !/^\d{11}$/.test(cpf)) {
        alert('Por favor, digite um CPF válido (11 dígitos numéricos)');
        return;
    }
    
    const btn = document.querySelector('button');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Gerando...';
    
    fetch('/gerar-qrcode', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `cpf=${encodeURIComponent(cpf)}`
    })
    .then(response => response.json())
    .then(data => {
        if(data.error) {
            alert('Erro: ' + data.error);
        } else {
            const qrImg = document.getElementById('qrcode-img');
            qrImg.src = data.qrcode;
            document.getElementById('qrcode-container').style.display = 'block';
            
            const codeDiv = document.getElementById('codigo-criptografado');
            codeDiv.innerHTML = `<p><strong>Código criptografado:</strong></p><p>${data.encrypted_cpf}</p>`;
            codeDiv.style.display = 'block';
        }
    })
    .catch(error => {
        alert('Erro ao gerar QR Code: ' + error.message);
    })
    .finally(() => {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-qrcode"></i> Gerar QR Code';
    });
}