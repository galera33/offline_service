from pathlib import Path

# Diretório base
BASE_DIR = Path(__file__).parent

# Configurações de segurança
SECRET_KEY = "ZFK7kU1n0YkOqiXqTZAm"  # Substitua por uma chave segura

# Configurações de arquivos
ARQUIVO_JSON = BASE_DIR / "dados.json"
REGISTRO_JSON = BASE_DIR / "registro.json"

# Configurações HTTPS
SSL_CERTIFICATE = BASE_DIR / "certificados" / "server.crt"
SSL_KEY = BASE_DIR / "certificados" / "server.key"

# Configurações do sistema
QRCODE_SIZE = (10, 4)  # Tamanho do QR Code (box_size, border)

API_BASE_URL = "https://voudevolks.dev01.rpm.com.br/api"
API_TOKEN = "f8331af6befa173f8cec0bc46df542"   # Substitua por um token de autenticação válido
