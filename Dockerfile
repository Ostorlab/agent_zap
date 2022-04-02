FROM owasp/zap2docker-stable
USER root
COPY requirement.txt .
RUN pip install -r requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/zap_agent.py"]
