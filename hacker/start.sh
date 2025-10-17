#!/usr/bin/env bash
set -euo pipefail

SSHD_BIN="/usr/sbin/sshd"
HTTP_PORT=8000
WEB_DIR="/home/hacker23/web"
HTTP_LOG="/home/hacker23/http.log"

# Limpieza al recibir señal
_cleanup() {
  echo "==> hacker: señal recibida, deteniendo servicios..."
  # matar procesos hijos
  pkill -P $$ || true

  # intentar matar sshd si sigue activo
  if pgrep -x "$(basename "$SSHD_BIN")" >/dev/null 2>&1; then
    pkill -TERM -x "$(basename "$SSHD_BIN")" || true
  fi

  # intentar matar procesos python http.server
  pkill -f "python3 -m http.server $HTTP_PORT" || true

  wait
  echo "==> hacker: limpieza finalizada."
  exit 0
}

trap _cleanup INT TERM EXIT

# Preparar entorno
mkdir -p /var/run/sshd
chown root:root /var/run/sshd || true

# Asegurar web dir y permisos
if [ -d "$WEB_DIR" ]; then
  chown -R hacker23:hacker23 "$WEB_DIR" || true
else
  mkdir -p "$WEB_DIR"
  chown hacker23:hacker23 "$WEB_DIR"
fi

# Asegurar ~/.ssh/authorized_keys existe y permisos correctos
mkdir -p /home/hacker23/.ssh
chown -R hacker23:hacker23 /home/hacker23/.ssh || true
chmod 700 /home/hacker23/.ssh || true
[ -f /home/hacker23/.ssh/authorized_keys ] && chmod 600 /home/hacker23/.ssh/authorized_keys || true

# Iniciar sshd en background
echo "==> hacker: arrancando sshd..."
$SSHD_BIN -D &
SSHD_PID=$!

# Iniciar servidor HTTP desde el directorio web como usuario hacker23
echo "==> hacker: arrancando servidor HTTP en puerto $HTTP_PORT desde $WEB_DIR..."
# redirigir logs a archivo; iniciarlo como usuario hacker23
su - hacker23 -c "cd '$WEB_DIR' && nohup python3 -m http.server $HTTP_PORT > '$HTTP_LOG' 2>&1 & echo \$!" >/tmp/http_pid
HTTP_PID=$(cat /tmp/http_pid) || true

# Algunas imágenes pueden no devolver PID por el método anterior; intentar detectarlo
if [ -z "${HTTP_PID:-}" ]; then
  HTTP_PID=$(pgrep -f "python3 -m http.server $HTTP_PORT" || true)
fi

# Esperar procesos; trap manejará señales
# Esperar ambos (si existen)
if [ -n "${HTTP_PID:-}" ]; then
  wait "$SSHD_PID" "$HTTP_PID" 2>/dev/null || true
else
  wait "$SSHD_PID"
fi
