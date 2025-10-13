import threading
import time
from atacante import servidorAtacante
from victima import clienteVictima

def ejecutar_atacante():
    """Ejecuta el servidor atacante en un hilo separado"""
    print("Iniciando servidor atacante...")
    servidor = servidorAtacante()
    servidor.iniciar_servidor()

def ejecutar_victima():
    """Ejecuta el cliente victima en un hilo separado"""
    # Esperar un poco para que el servidor se inicie primero
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
    
    # Crear hilos para ejecutar ambos procesos
    hilo_atacante = threading.Thread(target=ejecutar_atacante, daemon=True)
    hilo_victima = threading.Thread(target=ejecutar_victima, daemon=True)
    
    try:
        # Iniciar ambos hilos
        hilo_atacante.start()
        hilo_victima.start()
        
        # Esperar a que ambos hilos terminen
        hilo_atacante.join()
        hilo_victima.join()
        
    except KeyboardInterrupt:
        print("\nDeteniendo ambos procesos...")
        print("Procesos detenidos correctamente")

if __name__ == "__main__":
    main()
