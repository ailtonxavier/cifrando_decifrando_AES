import os
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Carrega as variáveis do ambiente
load_dotenv()
senha = os.getenv("ENCRYPTION_PASSWORD")

if not senha:
    raise ValueError("A variável de ambiente ENCRYPTION_PASSWORD não foi encontrada!")

# Gera a chave AES a partir da senha
salt = b'meu_salt_fixo_de_seguranca' 
key = PBKDF2(senha, salt, dkLen=32, count=1000000)

# Definição correta das 3 pastas
dir_original = "original"
dir_cifrado = "cifrado"
dir_decifrado = "decifrado"

# Garante que as pastas de saída existam
os.makedirs(dir_cifrado, exist_ok=True)
os.makedirs(dir_decifrado, exist_ok=True)

extensoes_validas = (".jpg", ".jpeg", ".png", ".bmp", ".webp")
arquivos = os.listdir(dir_original)

if not arquivos:
    print("Nenhum arquivo encontrado na pasta 'original'.")
else:
    print("--- INICIANDO PROCESSO DE CIFRAGEM ---")
    for arquivo in arquivos:
        caminho_orig = os.path.join(dir_original, arquivo)

        if os.path.isdir(caminho_orig) or not arquivo.lower().endswith(extensoes_validas):
            continue

        print(f"Cifrando: {arquivo}...")
        
        # 1. Lê a imagem original
        with open(caminho_orig, "rb") as f:
            dados_originais = f.read()

        # 2. Cifra os dados
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(dados_originais)
        nonce = cipher.nonce

        # 3. Salva na pasta 'cifrado'
        caminho_cif = os.path.join(dir_cifrado, f"{arquivo}.enc")
        with open(caminho_cif, "wb") as f:
            f.write(nonce)  # Primeiros 16 bytes
            f.write(tag)    # Próximos 16 bytes
            f.write(ciphertext)

        print(f" -> Salvo em cifrado: {arquivo}.enc")

    print("\n--- INICIANDO PROCESSO DE DECIFRAGEM ---")
    arquivos_cifrados = os.listdir(dir_cifrado)
    
    for arquivo_cif in arquivos_cifrados:
        if not arquivo_cif.endswith(".enc"):
            continue

        caminho_cif = os.path.join(dir_cifrado, arquivo_cif)
        # Remove o '.enc' para recuperar o nome original
        nome_original = arquivo_cif[:-4] 
        caminho_dec = os.path.join(dir_decifrado, nome_original)

        print(f"Decifrando: {arquivo_cif}...")

        # 1. Lê o arquivo cifrado
        with open(caminho_cif, "rb") as f:
            conteudo = f.read()

        # Extrai o nonce, a tag e o texto cifrado
        nonce = conteudo[:16]
        tag = conteudo[16:32]
        ciphertext = conteudo[32:]

        # 2. Descriptografa e valida a autenticidade
        try:
            cipher_dec = AES.new(key, AES.MODE_EAX, nonce=nonce)
            dados_restaurados = cipher_dec.decrypt_and_verify(ciphertext, tag)

            # 3. Salva na pasta 'decifrado'
            with open(caminho_dec, "wb") as f:
                f.write(dados_restaurados)

            print(f" -> Restaurado com sucesso em decifrado: {nome_original}")
        except ValueError:
            print(f" ERRO: O arquivo {arquivo_cif} foi corrompido ou a senha está incorreta!")

    print("\nProcessamento completo das 3 pastas finalizado!")