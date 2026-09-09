FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    unzip \
    wget \
    curl \
    adb \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# jadx
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar \
    && chmod +x /usr/local/bin/apktool

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

# Download matching frida-server for Redroid (x86_64)
RUN FRIDA_VER=$(pip3 show frida | grep ^Version: | awk '{print $2}') && \
    echo "Downloading frida-server ${FRIDA_VER}..." && \
    wget "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-x86_64.xz" -O /opt/frida-server.xz && \
    unxz /opt/frida-server.xz && \
    chmod +x /opt/frida-server

COPY *.py .
COPY dynamic/ ./dynamic/

# Isolation reminder: this container gets NO network access at runtime.
# Build-time network access above is fine (pulling tools); runtime is not.
ENTRYPOINT ["python3", "orchestrator.py"]
