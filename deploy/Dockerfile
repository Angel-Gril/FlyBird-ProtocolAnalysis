# syntax=docker/dockerfile:1
# apex-fetch 镜像：纯协议抓取，无需 root、无需客户端二进制
#
# 构建（在仓库根目录）：
#   docker build -f deploy/Dockerfile -t apex-fetch:latest .
#
# 运行：
#   docker run --rm -v $PWD/certs:/certs:ro -v $PWD/output:/output \
#     -e APEX_EMAIL=... -e APEX_PASSWORD=... apex-fetch:latest
FROM python:3.12-slim

LABEL org.opencontainers.image.title="apex-fetch" \
      org.opencontainers.image.description="FlyBird/飞鸟 订阅纯协议抓取（APXS v2 解密）" \
      org.opencontainers.image.source="https://github.com/Angel-Gril/FlyBird-ProtocolAnalysis" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OUT=/output/sub.yaml \
    CERT_DIR=/certs \
    INTERVAL=21600 \
    RETRY=300 \
    ONCE=0 \
    APEX_CONF=/tmp/apex-fetch.conf

# 运行依赖：pyyaml 做严格校验，pycryptodome 做 AES-CTR（无则回退 openssl）
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && pip install --no-cache-dir pyyaml pycryptodome \
 && rm -rf /var/lib/apt/lists/*

# 非 root 运行（uid 1000，便于挂载卷写权限）
RUN useradd -u 1000 -m -s /usr/sbin/nologin apex

WORKDIR /app
COPY src/apex_fetch.py /app/apex_fetch.py
COPY src/apxs_decrypt.py /app/apxs_decrypt.py
COPY deploy/docker-entrypoint.sh /app/entrypoint.sh
COPY deploy/healthcheck.py /app/healthcheck.py
RUN chmod +x /app/entrypoint.sh && chown -R apex:apex /app

USER apex

HEALTHCHECK --interval=10m --timeout=20s --start-period=2m --retries=3 \
  CMD ["python3", "/app/healthcheck.py"]

ENTRYPOINT ["/app/entrypoint.sh"]
