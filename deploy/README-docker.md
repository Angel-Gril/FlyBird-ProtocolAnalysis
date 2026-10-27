# Docker 部署

> 目标：**不需要 root、不往系统里装任何东西**，一条 `docker compose up -d` 起服务。

---

## 一、准备

```
deploy/
├── certs/            # 需自备：api.crt api.key sub.crt sub.key
├── output/           # 产物：sub.yaml
├── .env              # 账号（600）
├── Dockerfile
├── docker-compose.yml
└── docker-entrypoint.sh
```

```bash
mkdir -p certs output

# 从你自己的客户端安装目录导出：
#   profile5_api_client.{crt,key}.pem          -> api.crt / api.key
#   profile5_subscription_client.{crt,key}.pem -> sub.crt / sub.key
cp /path/to/profile5_api_client.crt.pem          certs/api.crt
cp /path/to/profile5_api_client.key.pem          certs/api.key
cp /path/to/profile5_subscription_client.crt.pem certs/sub.crt
cp /path/to/profile5_subscription_client.key.pem certs/sub.key
chmod 600 certs/*.key

cp .env.example .env && chmod 600 .env
$EDITOR .env        # 填 APEX_EMAIL / APEX_PASSWORD
```

## 二、启动

```bash
docker compose up -d --build
docker compose logs -f
```

预期：

```
2026-10-27 22:10:35 登录成功，access_key=***
2026-10-27 22:10:37 下载成功：26891B
2026-10-27 22:10:37 解密成功：aesID=1 signID=1 明文 26786B
2026-10-27 22:10:37 校验通过：74 节点 / 3 分组 / 14 条规则
2026-10-27 22:10:37 已发布：/output/sub.yaml（26786B）
2026-10-27 22:10:37 [apex] 成功：74 个节点
```

产物在 `deploy/output/sub.yaml`（权限 600）。

## 三、单次运行（cron / k8s Job）

```bash
docker run --rm \
  -v $PWD/certs:/certs:ro \
  -v $PWD/output:/output \
  -e APEX_EMAIL=... -e APEX_PASSWORD=... -e ONCE=1 \
  apex-fetch:latest
```

k8s Job 片段：

```yaml
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: apex-fetch
          image: ghcr.io/<you>/apex-fetch:latest
          env:
            - name: ONCE
              value: "1"
            - name: APEX_EMAIL
              valueFrom: { secretKeyRef: { name: apex, key: email } }
            - name: APEX_PASSWORD
              valueFrom: { secretKeyRef: { name: apex, key: password } }
          volumeMounts:
            - { name: certs, mountPath: /certs, readOnly: true }
            - { name: out,   mountPath: /output }
      volumes:
        - name: certs
          secret: { secretName: apex-certs }
        - name: out
          emptyDir: {}
```

## 四、环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `APEX_EMAIL` / `APEX_PASSWORD` | — | **必填** |
| `CERT_DIR` | `/certs` | 证书目录（需 api/sub 各一对） |
| `OUT` | `/output/sub.yaml` | 产物路径 |
| `INTERVAL` | `21600` | 循环间隔（秒） |
| `RETRY` | `300` | 失败重试（秒） |
| `ONCE` | `0` | `1` = 只跑一次退出 |
| `API_BASE` / `SUB_BASE` | 官方端点 | 覆盖端点 |
| `MIN_NODES` | `20` | 少于该值不发布 |

## 五、安全设计

| 措施 | 说明 |
|---|---|
| 非 root | 镜像内 `USER apex`（uid 1000） |
| rootfs 只读 | `read_only: true`，仅 `/tmp` 与挂载卷可写 |
| `cap_drop: ALL` | 不需要任何 capability |
| `no-new-privileges` | 禁止提权 |
| 口令不落盘 | 容器内配置写在 `/tmp`，退出即删 |
| 证书只读挂载 | `:ro` |
| 日志轮转 | `max-size: 5m, max-file: 3` |
| 健康检查 | 产物超过 `2×INTERVAL+1h` 未更新 → unhealthy |

## 六、排错

| 现象 | 原因 |
|---|---|
| 退出码 2，提示 `缺少证书` | `certs/` 里文件名不对，必须正好是 api.crt/api.key/sub.crt/sub.key |
| `登录失败：HTTP 404` | 证书与账号不匹配，或证书已轮换 |
| `permission denied` 写 `/output` | 宿主机目录属主不是 uid 1000：`sudo chown -R 1000:1000 output` |
| 容器 unhealthy | 长时间抓取失败，看 `docker compose logs` |

## 七、更新

```bash
git pull && cd deploy && docker compose up -d --build
```
