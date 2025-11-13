FROM python:3.9-alpine
LABEL name="VulnScanX"
LABEL version="2.0.0"
LABEL description="Advanced Security Scanner"
LABEL maintainer="ABN BOOS"

RUN apk add --no-cache git

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir requests

VOLUME ["/app/Result"]
ENTRYPOINT ["python", "vulnscanx.py"]
CMD ["--help"]