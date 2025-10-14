import socket, json, base64, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_HOST = 'localhost'
SERVER_PORT = 9999


def solicitar_clave_simetrica(victim_id):
    """Solicita la clave simétrica al servidor atacante (simula pago)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        # Recibir public key (no la usamos aquí, pero protocolo requiere intercambio)
        _ = s.recv(4096)
        request = {'action': 'recover', 'victim_id': victim_id}
        s.send(json.dumps(request).encode('utf-8'))
        resp = s.recv(8192).decode('utf-8')
        s.close()
        data = json.loads(resp)
        if data.get('status') == 'OK' and 'clave_simetrica' in data:
            clave_simetrica = base64.b64decode(data['clave_simetrica'])
            print('Clave simétrica recibida del atacante')
            return clave_simetrica
        else:
            print('Error al recuperar la clave:', data.get('message'))
    except Exception as e:
        print('Error conectando al atacante:', e)
    return None


def descifrar_archivo(cipher_path, plain_path, clave_simetrica):
    with open(cipher_path, 'rb') as f:
        contenido = f.read()
    iv = contenido[:16]
    ciphertext = contenido[16:]
    cipher = Cipher(algorithms.AES(clave_simetrica), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    plaintext = padded[:-pad_len]
    os.makedirs(os.path.dirname(plain_path), exist_ok=True)
    with open(plain_path, 'wb') as f:
        f.write(plaintext)


def recover_all(victim_id, carpeta_cipher=None, carpeta_plain=None):
    """Recupera todos los archivos cifrados para victim_id y los escribe en carpeta_plain."""
    if carpeta_cipher is None:
        carpeta_cipher = os.path.join('lab', 'sample_cipher')
    if carpeta_plain is None:
        carpeta_plain = os.path.join('lab', 'sample_recovered')

    clave = solicitar_clave_simetrica(victim_id)
    if not clave:
        print('No se obtuvo la clave. Abortando recuperación.')
        return False

    os.makedirs(carpeta_plain, exist_ok=True)

    for archivo in os.listdir(carpeta_cipher):
        if archivo == 'ransom_note.txt':
            continue
        ruta_cipher = os.path.join(carpeta_cipher, archivo)
        nombre_salida = archivo.replace('.enc', '')
        ruta_plain = os.path.join(carpeta_plain, nombre_salida)
        try:
            descifrar_archivo(ruta_cipher, ruta_plain, clave)
            print(f'Descifrado: {archivo} -> {nombre_salida}')
        except Exception as e:
            print(f'Error descifrando {archivo}:', e)
    print('Proceso de recuperación finalizado.')
    return True


if __name__ == '__main__':
    victim_id = 'victima'
    clave = solicitar_clave_simetrica(victim_id)
    if not clave:
        print('No se obtuvo la clave. Abortando.')
        exit(1)

    carpeta_cipher = os.path.join('lab', 'sample_cipher')
    carpeta_plain = os.path.join('lab', 'sample_plain')
    os.makedirs(carpeta_plain, exist_ok=True)

    for archivo in os.listdir(carpeta_cipher):
        if archivo == 'ransom_note.txt':
            continue
        ruta_cipher = os.path.join(carpeta_cipher, archivo)
        nombre_salida = archivo.replace('.enc', '')
        ruta_plain = os.path.join(carpeta_plain, nombre_salida)
        try:
            descifrar_archivo(ruta_cipher, ruta_plain, clave)
            print(f'Descifrado: {archivo} -> {nombre_salida}')
        except Exception as e:
            print(f'Error descifrando {archivo}:', e)

    print('Proceso de recuperación finalizado.')
