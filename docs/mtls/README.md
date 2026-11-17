# MPC 节点间 mTLS

节点配置统一放在 `configs/node-*.json`，默认启用 mTLS。从项目根目录运行以下命令，生成离线 CA 和三个节点的证书、私钥。

```powershell
.\scripts\gen-mpc-certs.ps1
```

```text
certs/mpc-dev/
  ca.crt
  ca.key
  node-1/node.crt
  node-1/node.key
  node-2/node.crt
  node-2/node.key
  node-3/node.crt
  node-3/node.key
```

脚本按输入配置的顺序生成节点证书。需要新的一套开发证书时，用 `-OutDir certs/mpc-dev-next`，然后更新现有三份配置中的 `mpcTLS` 路径。已有证书目录会保留。

用现有脚本启动三个节点。加上 `-Smoke` 会运行建钥冒烟测试。

```powershell
.\scripts\dev-up.ps1
```

节点配置中的 `mpcTLS` 包含 `caFile`、`certFile` 和 `keyFile`，相对路径以配置文件所在目录为基准。启用后，MPC 监听使用 TLS 1.3 并要求对端证书。节点验证证书链和对端 `partyId`，接收 MPC 消息时还检查证书身份与消息的 `From` 一致。证书的唯一 DNS SAN 使用 `mpc-node-` 加不带填充的小写 Base32 编码的 `partyId` 字节。例如节点 `1` 对应 `mpc-node-ge`。连接地址仍来自 `peers`，证书身份无需 DNS 解析。

客户端 REST 继续使用本机 HTTP。省略 `mpcTLS` 时，MPC 也只允许回环地址。配置证书后，MPC 监听和对端可以使用跨机器的 IP 地址。

## 证书保管和更换

本脚本生成的是开发证书，节点证书有效期为 90 天。目录 `certs/` 和 `*.key` 已加入 Git 忽略规则。Windows 上使用目录 ACL 限制私钥文件的读权限。

跨机器部署时，每台机器只安装自己的节点证书、自己的私钥和共享的 `ca.crt`。签发方离线保管 `ca.key`，生产节点在本机生成各自的私钥并提交证书签名请求。节点证书应同时具备客户端和服务端用途，延续该节点的证书身份。换证后重启节点，使新证书生效。

如果 CA 私钥疑似泄露，先停止节点并断开旧连接，再换上新的 CA 和各节点证书、私钥。三个节点都移除旧 CA 的信任后再启动，验证新证书互通及旧证书被拒绝。当前实现用配置中的 CA 文件决定信任范围。
