# Versão do servidor FastAPI sem SSL para teste
# Use este arquivo temporariamente para testar se o problema é o certificado SSL

from fastapi import FastAPI, Request, Body
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
import base64
import os
import qrcode
from io import BytesIO
import datetime
from datetime import UTC
import json
import re
from pathlib import Path
import socket
from pydantic import BaseModel
from typing import Optional
from config import (
    SECRET_KEY, 
    ARQUIVO_JSON, 
    REGISTRO_JSON,
    BASE_DIR
)

app = FastAPI()

class CPFRequest(BaseModel):
    cpf: str

class AtividadeRequest(BaseModel):
    atividade: str
    cpf: str

# Configuração CORS para aceitar requisições do React Native
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",  # Em produção, especifique domínios específicos
        "http://192.168.0.34:8000",
        "https://192.168.0.34:8000",
        "http://localhost:8000",
        "https://localhost:8000",
        "http://localhost:3000",
        "http://localhost:8081",  # Expo dev server
        "http://192.168.0.0/16",  # Range de IPs locais
        "https://192.168.0.0/16",  # Range de IPs locais
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=[
        "*",
        "Content-Type",
        "Accept",
        "User-Agent",
        "Cache-Control",
        "Pragma",
        "Origin",
        "Authorization",
    ],
)

# Configuração de templates e arquivos estáticos
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
templates.env.globals.update(now=datetime.datetime.now)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Modelos Pydantic para validação
class CadastroModel(BaseModel):
    cpf: str
    nome: str
    email: str
    celular: str
    data_cadastro: Optional[str] = None

class QRCodeModel(BaseModel):
    qr_data: str

class CPFModel(BaseModel):
    cpf: str

# Funções auxiliares
def carregar_registros():
    """Carrega registros de atividades do arquivo JSON"""
    if REGISTRO_JSON.exists():
        with open(REGISTRO_JSON, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def salvar_registro(registro_data: dict):
    """Salva um novo registro de atividade"""
    registros = carregar_registros()
    registros.append(registro_data)
    with open(REGISTRO_JSON, "w", encoding="utf-8") as f:
        json.dump(registros, f, ensure_ascii=False, indent=4)

def carregar_dados(arquivo):
    """Carrega dados de cadastro do arquivo JSON"""
    if arquivo.exists():
        with open(arquivo, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def salvar_dados(dados: list, arquivo):
    """Salva dados de cadastro no arquivo JSON"""
    with open(arquivo, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)

def decrypt_cpf(encrypted_base64: str) -> str:
    try:
        raw = base64.b64decode(encrypted_base64)
        if len(raw) < 17:
            raise ValueError("Base64 inválido ou muito curto")

        iv = raw[:16]
        ct_b64_ascii = raw[16:]
        ciphertext = base64.b64decode(ct_b64_ascii)

        key_hex = sha256(SECRET_KEY.encode('utf-8')).hexdigest()
        key = key_hex[:32].encode('ascii')

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()

        return data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Falha na descriptografia: {str(e)}")

def encrypt_cpf(cpf: str) -> str:
    try:
        iv = os.urandom(16)
        key_hex = sha256(SECRET_KEY.encode('utf-8')).hexdigest()
        key = key_hex[:32].encode('ascii')
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(cpf.encode('utf-8')) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        ct_b64 = base64.b64encode(ciphertext).decode('ascii')
        combined = iv + ct_b64.encode('ascii')
        return base64.b64encode(combined).decode('ascii')
    except Exception as e:
        raise ValueError(f"Falha na criptografia: {str(e)}")

def formatar_cpf(cpf: str) -> str:
    """Formata o CPF removendo caracteres não numéricos"""
    return re.sub(r'\D', '', cpf)

def verificar_cpf(cpf: str,arquivo) -> dict:
    """Verifica se o CPF existe na base de dados"""
    cpf_formatado = formatar_cpf(cpf)
    
    if not re.match(r'^\d{11}$', cpf_formatado):
        return {"status": "error", "message": "CPF inválido - deve conter 11 dígitos"}
    
    dados = carregar_dados(arquivo)
    
    # Procura o CPF na base de dados
    usuario_encontrado = None
    for usuario in dados:
        if usuario.get('cpf') == cpf_formatado:
            usuario_encontrado = usuario
            break
    
    if usuario_encontrado:
        return {
            "status": "success", 
            "message": "CPF encontrado na base de dados",
            "usuario": usuario_encontrado
        }
    else:
        return {
            "status": "error", 
            "message": "CPF não encontrado na base de dados"
        }
def verificar_atividade(cpf: str, atividade,arquivo) -> dict:
    """Verifica se o CPF possui atividades registradas"""
    cpf_formatado = formatar_cpf(cpf)
    if not re.match(r'^\d{11}$', cpf_formatado):
        return {"status": "error", "message": "CPF inválido - deve conter 11 dígitos"}
    
    dados = carregar_dados(arquivo)
    
    # Procura o CPF na base de dados
    usuario_encontrado = None
    for usuario in dados:
        if usuario.get('cpf') == cpf_formatado and usuario.get('atividade') == atividade:
            usuario_encontrado = usuario
            break
    
    if usuario_encontrado:
        return {
            "status": "success", 
            "message": "CPF encontrado na base de dados",
            "usuario": usuario_encontrado
        }
    else:
        return {
            "status": "error", 
            "message": "CPF não encontrado na base de dados"
        }
    
def registrar_atividade(cpf: str, atividade: str) -> dict:
    """Registra uma atividade para um CPF específico"""
    cpf_formatado = formatar_cpf(cpf)
    
    if not re.match(r'^\d{11}$', cpf_formatado):
        return {"status": "error", "message": "CPF inválido - deve conter 11 dígitos"}
    
    if not atividade or atividade.strip() == "":
        return {"status": "error", "message": "Atividade não pode estar vazia"}
    
    # Verifica se o CPF existe na base de dados
    resultado_verificacao = verificar_atividade(cpf_formatado, atividade.strip(), REGISTRO_JSON)
    if resultado_verificacao["status"] == "error":
        # Cria o registro da atividade
        novo_registro = {
            "cpf": cpf_formatado,
            "atividade": atividade.strip(),
            "data_hora": datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Salva o registro
        salvar_registro(novo_registro)
        
        return {
            "status": "success", 
            "message": "Atividade registrada com sucesso",
            #"registro": novo_registro
        }
    
    if resultado_verificacao["status"] == "success":
        
        return {
            "status": "error", 
            "message": "Atividade ja visitada",
        }

# Rotas
@app.get("/", response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/cadastro", response_class=HTMLResponse)
async def form_page(request: Request):
    return templates.TemplateResponse("cadastro.html", {"request": request})

@app.post("/cadastrar")
async def cadastrar(usuario: CadastroModel, request: Request):
    # Validação do CPF
    if not re.match(r'^\d{11}$', usuario.cpf):
        return JSONResponse(
            status_code=400,
            content={
                "error": "CPF inválido",
                "message": "CPF deve conter exatamente 11 dígitos numéricos"
            }
        )
    
    dados = carregar_dados(ARQUIVO_JSON)
    
    # Verifica se CPF já existe
    if any(u['cpf'] == usuario.cpf for u in dados):
        return JSONResponse(
            status_code=400,
            content={
                "error": "CPF já cadastrado",
                "message": "Este CPF já está registrado em nosso sistema"
            }
        )
    
    # Se data não foi enviada, usa a atual
    if usuario.data_cadastro is None:
        usuario.data_cadastro = datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    
    novo_usuario = usuario.dict()
    dados.append(novo_usuario)
    salvar_dados(dados, ARQUIVO_JSON)
    
    return {
        "status": "success",
        "message": "Cadastro realizado com sucesso",
    }

@app.get("/verificar-cpf", response_class=HTMLResponse)
async def verificar_cpf_page(request: Request):
    """Exibe o formulário de verificação de CPF"""
    return templates.TemplateResponse("verificar-cpf.html", {"request": request})

@app.post("/verificar-cpf")
async def verificar_cpf_endpoint(cpf_request: CPFRequest, request: Request):
    """Endpoint para verificar se um CPF está cadastrado"""
    resultado = verificar_cpf(cpf_request.cpf, ARQUIVO_JSON)
    
    if resultado["status"] == "success":
        return JSONResponse(
            content=resultado
        )
    else:
        return JSONResponse(
            content=resultado
        )

@app.get("/registrar_atividade", response_class=HTMLResponse)
async def registrar_atividade_page(request: Request):
    """Exibe o formulário de registro de atividade"""
    return templates.TemplateResponse("registrar_atividade.html", {"request": request})

@app.post("/registrar_atividade")
async def registrar_atividade_endpoint(atividade_request: AtividadeRequest, request: Request):
    """Endpoint para registrar uma atividade"""
    resultado = registrar_atividade(atividade_request.cpf, atividade_request.atividade)
    
    if resultado["status"] == "success":
        return JSONResponse(
            content=resultado
        )
    else:
        return JSONResponse(
            content=resultado
        )

@app.get("/camera", response_class=HTMLResponse)
async def camera_page(request: Request):
    return templates.TemplateResponse("camera.html", {"request": request})

@app.post("/process-qrcode")
async def process_qrcode(qr_data: QRCodeModel):
    try:
        # 1. Descriptografa o CPF
        cpf = decrypt_cpf(qr_data.qr_data)

        # 2. Valida CPF
        if not re.match(r'^\d{11}$', cpf):
            return JSONResponse(
                status_code=400,
                content={"status": "error", "message": "CPF inválido no QR Code"}
            )

        # 3. Define a atividade
        atividade = "skyline"

        # 4. Registra a atividade (se ainda não registrada)
        resultado = registrar_atividade(cpf, atividade)

        # 5. Sempre retorna JSON válido
        return JSONResponse(content=resultado)

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Falha ao processar QRCode: {str(e)}"}
        )

 

@app.get("/static/img/{image_name}")
async def get_image(image_name: str):
    image_path = BASE_DIR / "static" / "img" / image_name
    if image_path.exists():
        return FileResponse(image_path)
    return JSONResponse(status_code=404, content={"message": "Imagem não encontrada"})

if __name__ == "__main__":
    import uvicorn
    
    try:
        # Obtém o IP local
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        print(f"\n{'='*50}")
        print(f"{' SERVIDOR HTTP INICIADO ':=^50}")
        print(f"{'='*50}")
        print(f"\nAcesse:")
        print(f"Local:     http://localhost:8000")
        print(f"Rede:      http://{local_ip}:8000")
        print(f"\n{'='*50}\n")
        
        # RODA SEM SSL - APENAS PARA TESTE
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=8000
            # SEM SSL - APENAS PARA TESTE
        )
    except PermissionError:
        print("\nERRO: Permissão negada. Verifique se a porta 8000 está disponível.")
    except Exception as e:
        print(f"\nERRO: {str(e)}")
    finally:
        print("\nServidor encerrado.")