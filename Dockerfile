FROM owasp/zap2docker-stable
RUN mkdir -p /zap/wrk
USER root
RUN apt-get update -y
RUN apt-get install wget build-essential libreadline-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev -y
RUN wget -c https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tar.xz
RUN tar -Jxvf Python-3.10.0.tar.xz
WORKDIR Python-3.10.0
RUN ./configure --enable-optimizations
RUN make -j 4
RUN make altinstall
RUN update-alternatives --install /usr/bin/python python /usr/local/bin/python3.10 1
RUN update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.10 1
WORKDIR /zap
RUN rm -r Python-3.10.0
COPY requirement.txt .
RUN python3 -m pip install -r requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/zap_agent.py"]
