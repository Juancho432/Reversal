#!/usr/bin/env bash
set -euo pipefail

# Arranque del servicio SSH dentro del contenedor "server"
SSHD_BIN="/usr/sbin/sshd"

# Función de limpieza al recibir señal
_cleanup() {
  echo "==> server: señal recibida, deteniendo servicios..."
  # matar procesos hijos si siguen corriendo
  pkill -P $$ || true
  # si sshd fue lanzado en background y sigue, matarlo por nombre
  if pgrep -x "$(basename "$SSHD_BIN")" >/dev/null 2>&1; then
    pkill -TERM -x "$(basename "$SSHD_BIN")" || true
  fi
  wait
  echo "==> server: limpieza finalizada."
  exit 0
}

trap _cleanup INT TERM EXIT

# Preparar entorno minimo
mkdir -p /var/run/sshd
chown root:root /var/run/sshd || true
usermod -aG sudo sysadmin

# Asegurar que los archivos cypher estén en /home/sysadmin/cypher y permisos correctos
if [ -d /home/sysadmin/cypher ]; then
  chown -R sysadmin:sysadmin /home/sysadmin/cypher || true
  # Si cypher es ejecutable, asegurar permiso
  if [ -f /home/sysadmin/cypher/cypher ]; then
    chmod +x /home/sysadmin/cypher/cypher || true
    /home/sysadmin/cypher/cypher
  fi
fi

# Iniciar sshd en background (no -D para poder controlarlo y recibir señales)
echo "==> server: arrancando sshd..."
$SSHD_BIN -D &
SSHD_PID=$!

# Esperar al proceso sshd (y cualquier otro hijo). El trap hará la limpieza.
wait $SSHD_PID
