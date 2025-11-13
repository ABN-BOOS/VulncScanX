FROM python:3.9-alpine

LABEL name="VulnScanX"
LABEL version="2.1.0"
LABEL description="Advanced Security Scanner"

RUN apk add --no-cache git

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

VOLUME ["/app/Result"]

ENTRYPOINT ["python", "vulnscanx.py"]
CMD ["--help"]
