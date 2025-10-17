FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl openssh-server python3 python3-pip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Crear usuario atacante
RUN useradd -m -s /bin/bash hacker23 && echo "hacker23:vulnpass23" | chpasswd

# Preparar sshd
RUN mkdir -p /var/run/sshd /home/hacker23/.ssh
RUN chown -R hacker23:hacker23 /home/hacker23/.ssh

# Copiar clave pública (id_rsa.pub) al authorized_keys
COPY id_rsa.pub /tmp/id_rsa.pub
RUN mkdir -p /home/hacker23/.ssh && \
    mkdir -p /home/hacker23/hacked/ && \
    cat /tmp/id_rsa.pub > /home/hacker23/.ssh/authorized_keys && \
    chown -R hacker23:hacker23 /home/hacker23/.ssh && \
    chmod 700 /home/hacker23/.ssh && chmod 600 /home/hacker23/.ssh/authorized_keys

# Copiar contenido web
COPY web/ /home/hacker23/web/
RUN chown -R hacker23:hacker23 /home/hacker23/web

# Habilitar password auth para pruebas (opcional)
# RUN sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config || true

# Copiar script de arranque
COPY start.sh /start.sh
RUN chmod +x /start.sh

USER root
CMD ["/start.sh"]
