FROM python:3.12-slim

WORKDIR /app
COPY cert_checker.py .

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/cert_checker.py"]
# Defaults used by the Compose demo; override with your own --config / --out.
CMD ["--config", "/config/domains.yml", "--out", "/reports"]
