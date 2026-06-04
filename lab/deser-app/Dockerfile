# Deliberately-vulnerable insecure-deserialization (pickle) target. Local lab only.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3
COPY app.py .
EXPOSE 5000
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz')"
CMD ["python", "app.py"]
