// Máscaras para formulário
document.addEventListener('DOMContentLoaded', function() {
    // Máscara para CPF
    const cpfInput = document.getElementById('cpf');
    if (cpfInput) {
        cpfInput.addEventListener('input', function(e) {
            this.value = this.value.replace(/\D/g, '');
            if(this.value.length > 11) {
                this.value = this.value.slice(0, 11);
            }
        });
    }

    // Máscara para celular
    const celularInput = document.getElementById('celular');
    if (celularInput) {
        celularInput.addEventListener('input', function(e) {
            this.value = this.value.replace(/\D/g, '');
        });
    }
});