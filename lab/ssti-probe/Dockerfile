# In-house deterministic SSTI prober image for broker e2e tests (no GPL deps).
FROM python:3.12-slim
COPY ssti_probe.py /usr/local/bin/ssti-probe
RUN chmod +x /usr/local/bin/ssti-probe
# Invoked by the broker sandbox as:  ssti-probe <url-with-INJECT>
ENTRYPOINT []
