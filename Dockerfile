FROM python:3.14-alpine AS builder

WORKDIR /app

ENV CONFIG_DIR=/app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.14-alpine

RUN apk upgrade --no-cache
RUN apk add libstdc++ gcompat --no-cache

WORKDIR /app

RUN addgroup -g 977 -S vism && adduser -u 977 -S vism -G vism

COPY --from=builder /install /usr/local
COPY --chown=vism:vism . .

USER vism

CMD ["python", "main.py", "ca", "start"]
