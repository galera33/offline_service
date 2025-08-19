document.addEventListener('DOMContentLoaded', function() {
    const video = document.getElementById('video');
    const resultDiv = document.getElementById('result');
    let scanning = true;

    // Verifica se o navegador suporta a API de mídia
    if (!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia)) {
        resultDiv.innerHTML = 'Seu navegador não suporta acesso à câmera ou você não deu permissão.';
        return;
    }

    // Configurações para a câmera
    const constraints = {
        video: {
            facingMode: 'environment', // Prefere a câmera traseira
            width: { ideal: 1280 },
            height: { ideal: 720 }
        }
    };

    // Inicia a câmera
    navigator.mediaDevices.getUserMedia(constraints)
        .then(function(stream) {
            video.srcObject = stream;
            video.play();
            requestAnimationFrame(tick);
        })
        .catch(function(err) {
            if (err.name === 'NotAllowedError') {
                resultDiv.innerHTML = 'Permissão para acessar a câmera foi negada.';
            } else if (err.name === 'NotFoundError') {
                resultDiv.innerHTML = 'Nenhuma câmera encontrada no dispositivo.';
            } else {
                resultDiv.innerHTML = 'Erro ao acessar a câmera: ' + err.message;
            }
        });

    function tick() {
        if (!scanning) return;
        
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
            // Cria um canvas temporário para capturar o frame
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            
            // Obtém os dados da imagem para o jsQR
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: 'dontInvert',
            });
            
            if (code) {
                // QR Code encontrado!
                resultDiv.innerHTML = `QR Code lido: <strong>${code.data}</strong>`;
                scanning = false;
                
                // Aqui você pode adicionar a lógica para processar o código lido
                // Por exemplo, redirecionar ou fazer uma requisição AJAX
                console.log("QR Code encontrado:", code.data);
                
                // Opcional: parar a câmera após a leitura
                // video.srcObject.getTracks().forEach(track => track.stop());
            }
        }
        
        requestAnimationFrame(tick);
    }

    // Opcional: adicionar botão para reiniciar a leitura
    const restartButton = document.createElement('button');
    restartButton.textContent = 'Ler outro QR Code';
    restartButton.addEventListener('click', function() {
        scanning = true;
        resultDiv.innerHTML = '';
    });
    resultDiv.after(restartButton);
});