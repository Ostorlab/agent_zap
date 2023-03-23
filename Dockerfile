FROM ubuntu:22.04

# Install necessary packages
RUN apt-get update && apt-get install -y wget openjdk-11-jre curl python3.10 python3.10-dev python3-pip wireguard-tools openresolv iproute2

# Install ZAP proxy
ARG ZAP_VERSION=2.12.0
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v$ZAP_VERSION/ZAP_"$ZAP_VERSION"_Linux.tar.gz -O /tmp/zap.tar.gz
RUN tar -xzf /tmp/zap.tar.gz -C /opt
RUN ln -s /opt/ZAP_$ZAP_VERSION/zap.sh /usr/local/bin/zap

# Set Python 3.10 as the default Python version
RUN ln -s /usr/bin/python3.10 /usr/bin/python

COPY requirement.txt .
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install -r requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/zap_agent.py"]
