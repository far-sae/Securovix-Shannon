# In-house deterministic JWT weak-secret prober image for broker e2e tests (no GPL deps).
FROM python:3.12-slim
COPY jwt_probe.py /usr/local/bin/jwt-probe
RUN chmod +x /usr/local/bin/jwt-probe
ENTRYPOINT []
