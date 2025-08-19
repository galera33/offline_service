# Sistema de Cadastro Offline com FastAPI

Este projeto é um servidor web desenvolvido em Python utilizando FastAPI, voltado para cadastro de usuários, verificação de CPF, registro de atividades e leitura/geração de QR Code. O sistema foi pensado para funcionar offline, facilitando o uso em eventos, aplicativos móveis e ambientes sem conexão constante com a internet.

## Funcionalidades

- Cadastro de usuários com CPF, nome, e-mail e celular
- Verificação de CPF cadastrado
- Registro de atividades por CPF
- Leitura de QR Code via câmera do dispositivo
- Interface web para visualização e testes
- Compatível com integração para aplicativos móveis (React Native, Expo, etc.)

## Estrutura de Pastas

- **app2.py**: Código principal do servidor FastAPI
- **config.py**: Configurações do sistema e caminhos de arquivos
- **dados.json**: Base de dados dos usuários cadastrados
- **registro.json**: Registros de atividades realizadas
- **static/**: Arquivos estáticos (CSS, JS, imagens)
- **templates/**: Templates HTML para interface web

## Como executar

1. Instale as dependências:
    ```sh
    pip install -r requirements.txt
    ```

2. Execute o servidor:
    ```sh
    python app2.py
    ```

3. Acesse a interface web:
    - [http://localhost:8000](http://localhost:8000)
    - [http://localhost{IP_Adress}:8000](http://localhost{IP_Adress}:8000)

## Observações

- O sistema não utiliza SSL por padrão (apenas para testes locais).
- Os endpoints aceitam requisições JSON, facilitando integração com apps.
- Os dados são armazenados em arquivos `.json` locais.

