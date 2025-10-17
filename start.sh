#!/usr/bin/env bash
set -euo pipefail

# ----------------------------
# Configuración (ajusta si requieres)
# ----------------------------
NET_NAME="reversal"
BRIDGE_NAME="br-$NET_NAME"
SUBNET="172.28.100.0/24"
GATEWAY="172.28.100.1"
HOST_BRIDGE_IP="172.28.100.254/24"

SERVER_CONTAINER_NAME="pentest_server"
HACKER_CONTAINER_NAME="pentest_hacker"

COMPOSE_FILE="docker-compose.yml"

# ----------------------------
# Variables internas
# ----------------------------
CREATED_NET=0
CLEANED=0

# ----------------------------
# Helpers
# ----------------------------
log() { printf '\033[1;32m[i] \033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!] \033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[X] \033[0m %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "El comando '$1' no está disponible. Instálalo o ponlo en PATH."; exit 1; }
}

ip_has_addr() {
  local dev="$1"; local addr="${2%/*}"
  ip -o -4 addr show dev "$dev" 2>/dev/null | awk '{print $4}' | grep -q "^${addr}/" || return 1
}

docker_container_ip() {
  local cname="$1"
  # Obtiene la IP de la primera red docker del contenedor
  docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cname" 2>/dev/null || true
}

# ----------------------------
# Cleanup function (trap)
# ----------------------------
cleanup() {
  if [ "$CLEANED" -eq 1 ]; then
    return
  fi
  CLEANED=1

  log "Ejecutando limpieza..."

  # Bajar contenedores (si existe docker-compose y el archivo)
  if [ -f "$COMPOSE_FILE" ] && command -v docker-compose >/dev/null 2>&1; then
    log "Deteniendo contenedores (docker-compose down)..."
    docker-compose down || warn "docker-compose down devolvió error (tal vez ya estaban parados)."
  else
    warn "No se encontró docker-compose o $COMPOSE_FILE; omitiendo docker-compose down."
  fi

  # Quitar IP del bridge en el host si existe y está asignada
  if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    if ip_has_addr "$BRIDGE_NAME" "$HOST_BRIDGE_IP"; then
      log "Eliminando IP ${HOST_BRIDGE_IP%/*} de la interfaz $BRIDGE_NAME..."
      sudo ip addr del "$HOST_BRIDGE_IP" dev "$BRIDGE_NAME" || warn "No se pudo eliminar la IP (permiso o ya eliminada)."
    else
      log "La IP ${HOST_BRIDGE_IP%/*} no estaba asignada a $BRIDGE_NAME; nada que quitar."
    fi
  else
    log "La interfaz $BRIDGE_NAME no existe; no hay IP que quitar."
  fi

  # Si el script creó la red, eliminarla
  if [ "$CREATED_NET" -eq 1 ]; then
    if docker network inspect "$NET_NAME" >/dev/null 2>&1; then
      log "Eliminando red Docker $NET_NAME (fue creada por este script)..."
      docker network rm "$NET_NAME" || warn "No se pudo eliminar la red $NET_NAME."
    else
      log "La red $NET_NAME ya no existe."
    fi
  else
    log "No se eliminará la red $NET_NAME (no fue creada por este script)."
  fi

  log "Limpieza completada."
}

# Atrapar señales
trap 'log "SIGINT recibido."; cleanup; exit 130' INT
trap 'log "SIGTERM recibido."; cleanup; exit 143' TERM
trap 'log "EXIT." ; cleanup' EXIT

# ----------------------------
# Comprobaciones previas
# ----------------------------
require_cmd docker
require_cmd docker-compose
require_cmd ip

log "Script iniciado: forzando bridge '$BRIDGE_NAME' para la red Docker '$NET_NAME'."

# ----------------------------
# Crear la red si no existe
# ----------------------------
if docker network inspect "$NET_NAME" >/dev/null 2>&1; then
  log "La red Docker '$NET_NAME' ya existe."
else
  log "Creando la red Docker '$NET_NAME' con bridge forzado '$BRIDGE_NAME'..."
  # --opt com.docker.network.bridge.name fuerza el nombre de la interfaz creada
  docker network create \
    --driver bridge \
    --opt "com.docker.network.bridge.name=$BRIDGE_NAME" \
    --subnet "$SUBNET" \
    --gateway "$GATEWAY" \
    "$NET_NAME"

  CREATED_NET=1
  log "Red '$NET_NAME' creada y se solicitó bridge '$BRIDGE_NAME'."
fi

# Confirmar que la interfaz bridge existe (esperar un poco si es necesario)
if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
  warn "La interfaz $BRIDGE_NAME no existe inmediatamente. Esperando hasta 5 segundos para que Docker la cree..."
  sleep 1
  for i in {1..5}; do
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
  err "No se encontró la interfaz bridge '$BRIDGE_NAME'. Comprueba que Docker permite crear bridges con nombre forzado en tu sistema."
  err "Salida de interfaces actuales:"
  ip -o link show
  exit 1
fi

log "Interfaz bridge encontrada: $BRIDGE_NAME"

# ----------------------------
# Asignar IP al host (si no está ya asignada)
# ----------------------------
if ip_has_addr "$BRIDGE_NAME" "$HOST_BRIDGE_IP"; then
  log "La IP ${HOST_BRIDGE_IP%/*} ya está asignada a $BRIDGE_NAME."
else
  log "Asignando IP ${HOST_BRIDGE_IP} a $BRIDGE_NAME..."
  sudo ip addr add "$HOST_BRIDGE_IP" dev "$BRIDGE_NAME" || {
    err "No se pudo asignar la IP ${HOST_BRIDGE_IP}. Asegúrate de ejecutar el script con permisos (sudo)."
    exit 1
  }
  log "IP asignada correctamente."
fi

# ----------------------------
# Construir y arrancar contenedores
# ----------------------------
if [ ! -f "$COMPOSE_FILE" ]; then
  err "No se encuentra $COMPOSE_FILE en el directorio actual ($(pwd)). Saliendo."
  exit 1
fi

log "Construyendo imágenes y arrancando contenedores con docker-compose..."
docker-compose build --pull
docker-compose up -d

log "Contenedores lanzados. Esperando unos segundos para que se inicialicen servicios..."
sleep 3

# ----------------------------
# Obtener IPs dinámicamente desde docker (las IPs deben estar definidas en docker-compose)
# ----------------------------
log "Obteniendo IPs de los contenedores desde Docker..."

SERVER_IP="$(docker_container_ip "$SERVER_CONTAINER_NAME" || true)"
HACKER_IP="$(docker_container_ip "$HACKER_CONTAINER_NAME" || true)"

if [ -z "$SERVER_IP" ]; then
  warn "No se pudo obtener la IP del contenedor servidor ($SERVER_CONTAINER_NAME). Comprueba que existe y está en ejecución."
fi

if [ -z "$HACKER_IP" ]; then
  warn "No se pudo obtener la IP del contenedor atacante ($HACKER_CONTAINER_NAME). Comprueba que existe y está en ejecución."
fi

# ----------------------------
# Ping a ambos contenedores (mostrar resultado para servidor con IP, para atacante solo OK/FAIL)
# ----------------------------
if [ -n "$SERVER_IP" ]; then
  log "Ping al servidor ($SERVER_CONTAINER_NAME -> $SERVER_IP) ..."
  if ping -c 2 "$SERVER_IP" >/dev/null 2>&1; then
    log "Ping al servidor OK."
  else
    warn "Ping al servidor falló (tal vez SSH todavía arrancando o firewall dentro del contenedor)."
  fi
else
  warn "Omitiendo ping al servidor porque no se obtuvo su IP."
fi

# Ping al atacante, pero sin revelar su IP en la salida
if [ -n "$HACKER_IP" ]; then
  log "Ping al contenedor atacante (oculto) ..."
  if ping -c 2 "$HACKER_IP" >/dev/null 2>&1; then
    log "Ping al atacante: OK."
  else
    warn "Ping al atacante: FALLÓ."
  fi
else
  warn "Omitiendo ping al atacante porque no se obtuvo su IP."
fi

cat <<EOF

Laboratorio levantado:
  - Red Docker: $NET_NAME
  - Bridge (host): $BRIDGE_NAME
  - IP host en bridge: ${HOST_BRIDGE_IP%/*}
  - Servidor: $SERVER_CONTAINER_NAME -> ${SERVER_IP:-(desconocida)} -> sysadmin:anguila45

Para terminar y limpiar, presiona Ctrl+C.
EOF

# Mantener script corriendo esperando señales.
while true; do
  sleep 86400 & wait $!
done
