import requests
import cv2
import json
import os
import re
from datetime import datetime
from hashlib import sha256
from base64 import b64decode
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Configurações da API
BASE_URL = "https://voudevolks.dev01.rpm.com.br/api"
API_TOKEN = "f8331af6befa173f8cec0bc46df542"  # Substitua pelo token válido
SECRET_KEY = "ZFK7kU1n0YkOqiXqTZAm"  # A ser fornecida por email

# Configuração de diretórios
DATA_DIR = "dados_cpf"
os.makedirs(DATA_DIR, exist_ok=True)

class VolksAPI:
    def __init__(self, base_url: str, api_token: str):
        self.base_url = base_url
        self.api_token = api_token

    def _headers(self):
        return {
            "Content-Type": "application/json",
            "Token": self.api_token
        }
    
    @staticmethod
    def formatar_cpf(cpf: str) -> str:
        """Formata o CPF no padrão 000.000.000-00"""
        cpf = re.sub(r'\D', '', cpf)
        return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:11]}" if len(cpf) == 11 else cpf

    @staticmethod
    def formatar_celular(celular: str) -> str:
        """Formata o celular no padrão (00) 00000-0000"""
        celular = re.sub(r'\D', '', celular)
        if len(celular) == 11:
            return f"({celular[:2]}) {celular[2:7]}-{celular[7:11]}"
        elif len(celular) == 10:
            return f"({celular[:2]}) {celular[2:6]}-{celular[6:10]}"
        return celular

    @staticmethod
    def validar_email(email: str) -> bool:
        """Valida o formato do email"""
        return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email))

    @staticmethod
    def save_cpf_to_file(cpf: str, operation: str):
        """Salva o CPF em arquivo específico para cada operação"""
        files = {
            "leitura": "cpf_lido.txt",
            "verificacao": "cpf_verificado.txt",
            "cadastro": "cpf_cadastrado.txt",
            "atividade": "cpf_atividade.txt"
        }
        filepath = Path(DATA_DIR) / files.get(operation, "cpf_generico.txt")
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()} - {cpf}\n")

    @staticmethod
    def ler_qrcode():
        """Captura QR Code pela câmera e retorna o CPF descriptografado"""
        print("\n" + "="*40)
        print("Posicione o QR Code na frente da câmera")
        print("Pressione 'q' para cancelar")
        
        cap = cv2.VideoCapture(0)
        detector = cv2.QRCodeDetector()
        cpf = None
        
        try:
            while True:
                ret, frame = cap.read()
                if not ret:
                    print("Erro ao capturar imagem da câmera")
                    break
                
                data, _, _ = detector.detectAndDecode(frame)
                cv2.imshow("Leitor de QR Code", frame)
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    print("Leitura cancelada pelo usuário")
                    break
                    
                if data:
                    try:
                        cpf = VolksAPI.decrypt_cpf(data)
                        print(f"\nCPF decodificado com sucesso: {cpf}")
                        VolksAPI.save_cpf_to_file(cpf, "leitura")
                        break
                    except Exception as e:
                        print(f"\nErro na decodificação: {e}")
                        continue
                        
        finally:
            cap.release()
            cv2.destroyAllWindows()
        
        return cpf

    @staticmethod
    def decrypt_cpf(encrypted_data: str) -> str:
        """Descriptografa o CPF usando AES-256-CBC"""
        try:
            raw = b64decode(encrypted_data)
            if len(raw) < 17:
                raise ValueError("Dado criptografado inválido")
            
            iv, ciphertext = raw[:16], raw[16:]
            key = sha256(SECRET_KEY.encode()).digest()
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Falha na descriptografia: {str(e)}")

    @staticmethod
    def verificar_cpf(cpf: str) -> str:
        """Verifica status do CPF e retorna a resposta completa da API"""
        try:
            cpf_formatado = VolksAPI.formatar_cpf(cpf)
            print(f"\nVerificando CPF: {cpf_formatado}")
            
            response = requests.post(
                f"{BASE_URL}/evento/cpf-status",
                json={"cpf": cpf_formatado},
                headers={
                    "Content-Type": "application/json",
                    "Token": API_TOKEN
                },
                timeout=10
            )
            
            VolksAPI.log_api_request("cpf-status", cpf_formatado, response)
            
            if response.status_code == 200:
                data = response.json()
                VolksAPI.save_cpf_to_file(cpf, "verificacao")
                existe = data.get('dados', {}).get('existe', None)
                return existe  # Retorna toda a resposta da API
                
            print(f"Erro na API: {response.status_code} - {response.text}")
            return {"sucesso": False, "erro": response.text}
            
        except requests.exceptions.RequestException as e:
            print(f"Erro de conexão: {e}")
            return {"sucesso": False, "erro": str(e)}

    @staticmethod
    def registrar_usuario(cpf: str, nome: str, email: str, celular: str) -> bool:
        """Realiza pré-cadastro com dados formatados"""
        try:
            cpf_formatado = VolksAPI.formatar_cpf(cpf)
            celular_formatado = VolksAPI.formatar_celular(celular)
            # Montagem do payload
            payload = {
                "nome": nome,
                "email": email,
                "cpf": cpf_formatado,
                "celular": celular_formatado
            }
            VolksAPI.verificar_cpf(cpf_formatado)
            
            # Envio para API
            response = requests.post(
                f"{BASE_URL}/evento/pre-cadastro",
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Token": API_TOKEN
                },
                timeout=15
            )
            
            VolksAPI.log_api_request("pre-cadastro", cpf_formatado, response)
            
            if response.status_code == 200:
                print("\nCadastro realizado com sucesso!")
                VolksAPI.save_cpf_to_file(cpf, "cadastro")
                return True
                
            if response.status_code == 400:
                errors = response.json().get('erros', {})
                print("\nErros no cadastro:")
                for field, msg in errors.items():
                    print(f"- {field}: {msg}")
            else:
                print(f"\nErro no cadastro: {response.status_code} - {response.text}")
                
            return False
            
        except Exception as e:
            print(f"\nErro durante o cadastro: {e}")
            return False

    @staticmethod
    def registrar_atividade(cpf: str, atividade: str) -> bool:
        """Registra atividade para o CPF informado"""
        try:
            
            cpf_formatado = VolksAPI.formatar_cpf(cpf)
            
            response = requests.post(
                f"{BASE_URL}/evento/atividade",
                json={
                    "cpf": cpf_formatado,
                    "atividade": atividade
                },
                headers={
                    "Content-Type": "application/json",
                    "Token": API_TOKEN
                },
                timeout=10
            )
            
            VolksAPI.log_api_request(atividade, cpf_formatado, response)
            
            if response.status_code == 200:
                data = response.json()
                print("\nAtividade registrada com sucesso!")
                resultado = data.get('sucesso')
                VolksAPI.save_cpf_to_file(cpf, "atividade")
                return resultado
            elif response.status_code == 400:
                data = response.json()
                print("\nCPF nao esta cadastrado para esta atividade.")
                resultado = data.get('sucesso')
                VolksAPI.save_cpf_to_file(cpf, "atividade")
                return resultado
                
            print(f"\nErro ao registrar atividade: {response.status_code} - {response.text}")
            return False
            
        except Exception as e:
            print(f"\nErro durante registro de atividade: {e}")
            return False

    @staticmethod
    def log_api_request(endpoint: str, cpf: str, response: requests.Response):
        """Registra todas as interações com a API"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "cpf": cpf,
            "status_code": response.status_code,
            "request": {
                "url": response.request.url,
                "method": response.request.method,
                "body": response.request.body.decode('utf-8') if response.request.body else None
            },
            "response": response.json() if response.content else None
        }
        
        log_file = Path(DATA_DIR) / "api_logs.json"
        with open(log_file, 'a', encoding="utf-8") as f:
            json.dump(log_entry, f, ensure_ascii=False, indent=2)
            f.write(",\n")

    @staticmethod
    def processar_qrcode():
        """Fluxo completo de processamento do QR Code"""
        cpf = VolksAPI.ler_qrcode()
        if not cpf:
            return
            
        if VolksAPI.verificar_cpf(cpf):
            VolksAPI.registrar_atividade(cpf)
        else:
            print("\nCPF não cadastrado. Por favor complete o cadastro.")
            if VolksAPI.registrar_usuario(cpf):
                VolksAPI.registrar_atividade(cpf)


# Exemplo de uso
if __name__ == "__main__":
    api = VolksAPI(BASE_URL, API_TOKEN)
    api.processar_qrcode()