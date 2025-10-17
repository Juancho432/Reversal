FROM ubuntu:latest

# Evitar prompts
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends sudo binutils default-jdk openssh-server ca-certificates \
    libssh2-1 libcurl4-openssl-dev iputils-ping curl && \
    rm -rf /var/lib/apt/lists/*

# Crear usuario y preparar SSH
RUN useradd -m -s /bin/bash sysadmin && echo "sysadmin:anguila45" | chpasswd

# Crear directorio para sshd
RUN mkdir -p /var/run/sshd

# Copiar archivos cypher al home del usuario
COPY cypher/cypher /home/sysadmin/cypher/cypher
COPY cypher/clients.csv /home/sysadmin/cypher/clients.csv
RUN chown -R sysadmin:sysadmin /home/sysadmin/cypher && chmod -R 644 /home/sysadmin/cypher/* || true
# Si cypher es ejecutable (binario), dar permiso:
RUN chmod +x /home/sysadmin/cypher/cypher || true

# Ajustes de sshd para permitir password auth (útil en lab)
RUN sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
RUN sed -i 's/^PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config || true

# Copiar script de arranque
COPY start.sh /start.sh
RUN chmod +x /start.sh

USER root
CMD ["/start.sh"]
