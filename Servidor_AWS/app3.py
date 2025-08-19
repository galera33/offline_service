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
from volks_api import VolksAPI
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

BASE_URL = "https://voudevolks.dev01.rpm.com.br/api"
API_TOKEN = "f8331af6befa173f8cec0bc46df542"
app = FastAPI()
volks_api = VolksAPI(base_url=BASE_URL, api_token=API_TOKEN)
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

class CPFRequest(BaseModel):
    cpf: str

class AtividadeRequest(BaseModel):
    atividade: str
    cpf: str

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

# Funções auxiliares (mantidas iguais)
def carregar_registros():
    if REGISTRO_JSON.exists():
        with open(REGISTRO_JSON, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def salvar_registro(cpf: str):
    registros = carregar_registros()
    novo_registro = {
        "cpf": cpf,
        "data_hora": datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    }
    registros.append(novo_registro)
    with open(REGISTRO_JSON, "w", encoding="utf-8") as f:
        json.dump(registros, f, ensure_ascii=False, indent=4)

def carregar_dados():
    if ARQUIVO_JSON.exists():
        with open(ARQUIVO_JSON, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def salvar_dados(dados: list):
    with open(ARQUIVO_JSON, "w", encoding="utf-8") as f:
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
    
    dados = carregar_dados()
    volks_api.registrar_usuario(usuario.cpf, usuario.nome, usuario.email, usuario.celular)
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
    salvar_dados(dados)
    
    return {
        "status": "success",
        "message": "Cadastro realizado com sucesso",
        "data": novo_usuario
    }
@app.get("/verificar-cpf", response_class=HTMLResponse)
async def verificar_cpf_page(request: Request):
    """Exibe o formulário de verificação de CPF"""
    return templates.TemplateResponse("verificar-cpf.html", {"request": request})

# Endpoint para processar a verificação
@app.post("/verificar-cpf")
async def verificar_cpf(cpf_request: CPFRequest, request: Request):

    #cpf_formatado = volks_api.formatar_cpf(cpf_request.cpf)
    dados = carregar_dados()
    data = volks_api.verificar_cpf(cpf_request.cpf)

    return {
        dados: data,
    }
    
@app.get("/registrar_atividade", response_class=HTMLResponse)
async def registrar_atividade_page(request: Request):
    """Exibe o formulário de registro de atividade"""
    return templates.TemplateResponse("registrar_atividade.html", {"request": request})

# Endpoint para processar a verificação

@app.post("/registrar_atividade")
async def registrar_atividade(atividade_request: AtividadeRequest, request: Request):
    
    # Registrar a atividade
    resultado = volks_api.registrar_atividade(atividade_request.cpf, atividade_request.atividade)
    dados = carregar_dados()
    return {
        "status": resultado,
    }

        
       
    
@app.get("/camera", response_class=HTMLResponse)
async def camera_page(request: Request):
    return templates.TemplateResponse("camera.html", {"request": request})

@app.post("/process-qrcode")
async def process_qrcode(qr_data: QRCodeModel):
    try:
        cpf = decrypt_cpf(qr_data.qr_data)
        
        if not re.match(r'^\d{11}$', cpf):
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "CPF inválido no QR Code"}
            )
        
        salvar_registro(cpf)
        return {"success": True, "cpf": cpf}
        
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": str(e)}
        )

@app.get("/gerar-qrcode", response_class=HTMLResponse)
async def gerar_qrcode_page(request: Request):
    return templates.TemplateResponse("gerar_qrcode.html", {"request": request})

@app.post("/gerar-qrcode")
async def gerar_qrcode(cpf_data: CPFModel):
    try:
        cpf = cpf_data.cpf
        if not re.match(r'^\d{11}$', cpf):
            raise ValueError("CPF deve conter exatamente 11 dígitos numéricos")
        
        encrypted_cpf = encrypt_cpf(cpf)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(encrypted_cpf)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()
        
        return {
            "success": True,
            "qrcode": img_str,
            "encrypted_cpf": encrypted_cpf
        }
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": str(e)}
        )

@app.get("/registros", response_class=HTMLResponse)
async def ver_registros(request: Request):
    registros = carregar_registros()
    return templates.TemplateResponse("registros.html", {
        "request": request,
        "registros": registros
    })

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