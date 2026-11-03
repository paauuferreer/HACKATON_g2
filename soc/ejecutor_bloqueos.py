"""Entrada compatible para el ejecutor seguro Node.js (requiere Node >=22.13).

Solo procesa BLOQUEAR/USUARIO/AUTOMATICO. No ejecuta IP, servidores o liberaciones.
Modo real: BLOQUEO_AUTO_ACTIVO=1 + AUTOMATION_START_AT + contrato completo.
--dry-run siempre es de solo lectura. --una-vez hace un ciclo; por defecto cada 60 s.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def main():
    args = [x for x in sys.argv[1:] if x in ("--dry-run", "--una-vez")]
    command = ["node", "--env-file-if-exists=.env", "soc/run-automation.mjs", *args]
    while True:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode or "--una-vez" in args:
            return result.returncode
        time.sleep(max(10, int(os.getenv("INTERVALO_SEGUNDOS", "60"))))

if __name__ == "__main__":
    sys.exit(main())
