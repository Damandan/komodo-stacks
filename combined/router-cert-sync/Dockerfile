FROM python:3.12-alpine

RUN apk add --no-cache openssh-client openssl

WORKDIR /app
COPY sync.py /app/sync.py

CMD ["python", "-u", "/app/sync.py"]
