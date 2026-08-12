# 运维

[English](operations.md) | [文档索引](../README.zh-CN.md#文档)

本文描述预期运维边界。首个公开源码版本只有在签名发布证据完整后才能用于生产。

## 公网与私网端口

Nginx 是 Control 流量唯一公网监听。最小 UFW 策略示例：

```sh
ADMIN_CIDR='203.0.113.0/24'
SSH_PORT='22'
sudo ufw default deny incoming
sudo ufw allow from "$ADMIN_CIDR" to any port "$SSH_PORT" proto tcp \
  comment 'restricted administrative SSH'
sudo ufw allow 443/tcp comment 'HTTPS'
# 仅在 HTTP 跳转或 ACME 校验需要时启用：
sudo ufw allow 80/tcp comment 'HTTP redirect or ACME'
sudo ufw enable
sudo ufw status numbered
```

执行前必须替换文档示例网段和 SSH 端口，并保留宿主机其他明确需要的规则。不要为 `18090`、
`18091`、`18092`、`18093` 添加 UFW 放行；它们必须只绑定 `127.0.0.1`。不要开放 PostgreSQL
或 Redis。Connector 只需要出站 TCP `443`，不需要任何入站端口。

每次修改网络后同时核验监听地址和防火墙：

```sh
sudo ss -lntp
sudo ufw status verbose
```

## 健康与验收

回环检查分别验证进程存活和依赖就绪：

```sh
curl --fail --silent --show-error \
  http://127.0.0.1:18090/v1/health/live
curl --fail --silent --show-error \
  http://127.0.0.1:18090/v1/health/ready
curl --fail --silent --show-error \
  http://127.0.0.1:18091/codex/
```

ready 响应只是必要条件，不是生产验收。验收还必须覆盖真实同源会话交换、浏览器 WSS、设备
WSS、使用固定 Codex 版本的真实 Connector、允许的 RPC、审批默认拒绝、重连、撤销和注销。
按发布版本把证据保存在仓库外，且不要记录 token 或 cookie。

Metrics 位于回环 API 的 `/internal/metrics`，并要求独立 bearer token；不要把该路径代理到
公网。Connector metrics 写入私密 `state_dir/connector.prom`，应检查更新时间，不能只相信
最后一条 `up` 值。

## 日志与秘密

Nginx 应使用独立 JSON access log，其格式不记录查询串、Referer 和 User-Agent。日志应避开
宿主机宽泛的 logrotate 通配规则，并验证轮转和 Nginx reopen。应用日志不得包含 access token、
refresh 凭据、cookie、供应商密钥、配对码或秘密文件内容。

Compose 环境文件、生成的秘密文件、部署记录、发布证据和恢复材料应放在源码仓库外，并使用
尽可能严格的所有权和权限。不要把原始凭据放进命令参数、镜像元数据、URL、Git 或 issue。

## 恢复快照

每个会改变状态的生产窗口前，在仓库外创建一份完整、已验证、加密的恢复快照。它应覆盖
Control 数据库、所需 Redis 持久化和 ACL/配置、Control secrets、已准入部署记录、Nginx 配置
以及恢复所需的宿主集成信息。校验 checksum，并验证受保护的异地副本。

同一个未发生变化的窗口不要重复创建快照。只有受保护状态发生变化、上次快照不完整或策略
要求更新恢复点时才创建新快照。必须在隔离环境演练恢复；只生成但未解析和恢复验证的文件
不能算已验证恢复证据。

## 升级

新版本没有完整的签名镜像和 Connector 证据时，升级应保持阻断。对已准入版本：

1. 审查 schema、数据库迁移、Sub2API 与 Codex 兼容性；
2. 冻结变更窗口，并创建一次已验证恢复快照；
3. 在迁移前验证源码身份、签名、来源证明、SBOM、镜像 digest 和平台签名；
4. 仅通过该发布版本唯一准入的部署入口执行迁移和启动服务；
5. 验证回环监听、Nginx、UFW、真实登录 HTTP/WSS、Connector 策略、重连、撤销和注销；
6. 在新证据正式验收前保留上一已准入版本及其回滚说明。

不要替换镜像 digest、二进制、lock 文件或迁移版本后仍沿用同一个发布版本号。

## 卸载

卸载只应处理 Control 自己的组件：

1. 撤销已配对设备并停止用户 Connector；
2. 停止并移除 Control API、PWA 和仅供 Control 使用的迁移/备份容器；
3. 移除 Control Nginx include，测试完整 Nginx 配置后 reload；
4. 默认保留 Control PostgreSQL 数据库、Redis namespace、secrets、部署记录和恢复证据；
5. 只有另行做出明确的数据销毁决定后才删除保留数据；
6. 不要删除或修改外部 Sub2API 容器、数据库、Redis 服务、Docker network、TLS 资产或其他
   宿主机路由；
7. 不要自动删除 UFW 的 `80` 或 `443` 规则，同机其他服务可能仍需要它们。

详细发布与恢复约束见[运维手册](runbooks/README.md)。
