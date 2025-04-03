FROM zaproxy/zap-stable AS builder

FROM debian:bookworm-slim AS final

ARG DEBIAN_FRONTEND=noninteractive

# Install necessary packages
RUN apt-get update && apt-get install -q -y --fix-missing \
	make \
	automake \
	autoconf \
	gcc g++ \
	openjdk-17-jdk \
	wget \
	curl \
	xmlstarlet \
	unzip \
	git \
	openbox \
	xterm \
	net-tools \
	python-is-python3 \
    firefox-esr \
    curl \
    python3.11 \
    python3.11-dev \
    python3-pip \
    wireguard-tools \
    openresolv \
    iproute2 \
    xvfb \
    x11vnc \
    virtualenv && \
	rm -rf /var/lib/apt/lists/*

RUN useradd -u 1000 -d /home/zap -m -s /bin/bash zap
RUN echo zap:zap | chpasswd
RUN mkdir /zap && chown zap:zap /zap

WORKDIR /zap

#Change to the zap user so things get done as the right person (apart from copy)
USER zap

COPY requirement.txt .
RUN python3.11 -m virtualenv -p python3.11 /home/zap/venv
RUN /home/zap/venv/bin/python3.11 -m pip install --upgrade pip
RUN /home/zap/venv/bin/python3.11 -m pip install -r requirement.txt


RUN mkdir /home/zap/.vnc

# Copy stable release
COPY --from=builder --chown=1000:1000 /zap .
COPY  --from=builder --chown=1000:1000 /zap/webswing /zap/webswing

ARG TARGETARCH
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-$TARGETARCH
ENV PATH=/home/zap/venv/bin:$JAVA_HOME/bin:/zap/:$PATH
ENV ZAP_PATH=/zap/zap.sh


# Default port for use with health check
ENV ZAP_PORT=8080
ENV IS_CONTAINERIZED=true
ENV HOME=/home/zap/
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

COPY --from=builder --chown=1000:1000 /home/zap/.ZAP/policies /home/zap/.ZAP/policies/
COPY --from=builder --chown=1000:1000 /root/.ZAP/policies /root/.ZAP/policies/
# The scan script loads the scripts from dev home dir.
COPY --from=builder --chown=1000:1000 /home/zap/.ZAP_D/scripts /home/zap/.ZAP_D/scripts/
COPY --from=builder --chown=1000:1000 /home/zap/.xinitrc /home/zap/

RUN chmod a+x /home/zap/.xinitrc

HEALTHCHECK CMD curl --silent --output /dev/null --fail http://localhost:$ZAP_PORT/ || exit 1

USER root

RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
RUN mkdir -p /zap/wrk

# Set permissions for /zap and /home/zap directories
RUN chown -R zap:zap /zap && \
    chmod -R 777 /zap && \
    chmod -R 777 /app && \
    chmod -R 777 /home/zap

# Set /zap as the working directory
WORKDIR /zap

# Switch back to the zap user
USER zap

CMD ["/venv/bin/python3.11", "/app/agent/zap_agent.py"]