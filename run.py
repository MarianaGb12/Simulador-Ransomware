import threading
import time
from atacante import servidorAtacante
from victima import clienteVictima
from recover_and_decrypt import recover_all

def ejecutar_atacante():
    """Ejecuta el servidor atacante en un hilo separado"""
    print("Iniciando servidor atacante...")
    servidor = servidorAtacante()
    servidor.iniciar_servidor()

def ejecutar_victima():
    """Ejecuta el cliente victima en un hilo separado"""
    time.sleep(3)
    print("Iniciando cliente victima...")
    victima = clienteVictima()
    victima.ejecutar_ataque()

def main():
    """Funcion principal que ejecuta ambos sockets simultaneamente"""
    print("=" * 60)
    print("SIMULACION DE RANSOMWARE - SISTEMA COMPLETO")
    print("=" * 60)
    print("Iniciando ambos sockets...")
    print("Presiona Ctrl+C para detener ambos procesos")
    print("=" * 60)
    try:
        # Crear hilos para ejecutar ambos procesos
        hilo_atacante = threading.Thread(target=ejecutar_atacante, daemon=True)
        hilo_victima = threading.Thread(target=ejecutar_victima, daemon=True)

        # Iniciar el servidor atacante y la victima
        hilo_atacante.start()
        hilo_victima.start()

        # Esperar a que la víctima termine (hilo_victima es daemon en el original,
        # así que esperaremos un tiempo razonable para que complete el cifrado)
        hilo_victima.join(timeout=20)

        # Dar tiempo para que la clave sea liberada por el atacante (auto-release)
        print('Esperando a que la clave se libere (si está configurado auto-release)...')
        time.sleep(6)

        # Llamar al flujo de recuperación para restaurar archivos en lab/sample_plain
        print('Iniciando proceso de recuperación (simulación de pago)...')
        success = recover_all('victima')
        if success:
            print('Archivos recuperados en lab/sample_recovered/')
        else:
            print('No se pudo recuperar los archivos.')

        # Mantener el servidor atacante en ejecución hasta que el usuario lo detenga
        hilo_atacante.join()

    except KeyboardInterrupt:
        print("\nDeteniendo ambos procesos...")
        print("Procesos detenidos correctamente")
        print("\nDeteniendo ambos procesos...")
        print("Procesos detenidos correctamente")

if __name__ == "__main__":
    main()
