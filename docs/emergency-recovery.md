# 紧急恢复完整私钥

此功能用于离线恢复根私钥，支持 ECDSA/secp256k1 和 FROST/Ed25519。正常情况下保管加密恢复数据，发生故障时使用节点外保管的 RSA 私钥恢复，无需节点、数据库、MK 或 master password。

与 `exportkeyshare` 不同，此功能只备份用于恢复完整私钥的签名标量，以及继续派生所需的 chain code，不包含 CMP 辅助密钥、预签名或数据库运行状态。恢复结果用于单方签名，不能直接通过 `importkeyshare` 恢复节点。

## 配置

三个 `configs/node-*.json` 均默认关闭：

```json
"emergencyRecovery": {
  "enabled": false,
  "publicKeys": []
}
```

生成独立的测试恢复密钥，默认 4096 位，已有文件不会覆盖：

```powershell
go run ./cmd/mpc-wrapkeygen -out certs/ers-dev-4096
$publicKey = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$PWD/certs/ers-dev-4096/rsa-public.der"))
```

将 `$publicKey` 的值填写到每个参与节点的 `emergencyRecovery.publicKeys`，并设置 `enabled: true`，重启生效。公钥格式为 RSA SPKI DER 的 Base64，支持 2048–8192 位，指数必须为 65537。

开启时白名单为空或公钥无效会导致启动失败。接口收到非白名单公钥返回 403，未开启时返回 403。`keyTransfer.exportEnabled` 和 `wrappingPrivateKeyFile` 均不参与此功能的授权；普通导出开启也不会自动开启紧急恢复。

`rsa-private.pem` 由恢复操作方保管，不配置到节点，不上传到 REST。生产部署只将公钥分发给节点，RSA 私钥在节点外生成并离线保管。目录中的开发测试私钥不用于生产。

## REST

```text
POST /ecdsa/keys/{keyID}/recoverydata
POST /frost/keys/{keyID}/recoverydata
```

请求体：

```json
{
  "recoveryKey": "<Base64 RSA SPKI DER>",
  "label": "<Base64 UTF-8 标签字节>"
}
```

使用 API Key 和现有 MPC 会话头：

```text
Authorization: APIKEY <该节点 API Key>
MPC-SessionID: <本次恢复数据生成的唯一会话 ID>
MPC-RoutingID: <与现有签名接口相同的 routing ID>
MPC-Players: 1
MPC-Players: 2
MPC-Players: 3
```

URL 同样携带 `?mpc_routing_id=<routing ID>`。同时请求所有参与节点，同一个会话必须使用相同的 keyID、参与者、RSA 公钥和标签；节点还会比对根公钥、chain code、阈值及全部公开分片，避免混用不同分享代次。全部参与者必须持有当前分片，数量至少为原密钥的 `threshold + 1`。

响应是该节点的 `Partial` JSON，包含 `manifest`、`partyID`、`proof`。每份响应分别保存，例如 `node-1.json`、`node-2.json`、`node-3.json`。响应设置 `Cache-Control: no-store`，节点日志不打印响应、请求体、私钥或标签。API Key 只能访问所属应用的密钥，其他应用返回 404。

相同会话、相同参数的重试返回缓存中的原恢复数据；本节点同会话更改参数返回 409。会话缓存只在内存，重启后使用新的会话 ID 生成。接口不写入或修改数据库分片，不持久化恢复数据，也不备份预签名。

本版本只恢复根密钥，不接受 `chainPath`；恢复后使用根标量和 chain code 在离线环境派生，非硬化派生规则与节点一致。

## 离线工具

先在开发机编译，再将可执行文件复制到离线机器；离线运行不需要 Go 或联网：

```powershell
go build -o data/mpc-recovery.exe ./cmd/mpc-recovery
```

使用事先可信保存的 `/publickey` 响应，例如 `public.json`：

```json
{"curve":"ed25519","publicKey":"<Base64 公钥>"}
```

ECDSA 文件的 `curve` 为 `secp256k1`，`publicKey` 是接口返回的 65 字节未压缩公钥。不要把待验证备份里自带的公钥作为唯一信任来源。

合并时即验证证明，重复的节点或不足阈值的数据会被拒绝。以下命令中的 `-label` 是原始 UTF-8 文本；REST 请求中填写的是这些文本字节的 Base64。

```powershell
./data/mpc-recovery.exe combine `
  -in data/node-1.json -in data/node-2.json -in data/node-3.json `
  -public-key data/public.json -rsa-key certs/ers-dev-4096/rsa-public.pem `
  -label "wallet-a/emergency/v1" -out data/recovery.json
```

只使用公开信息验证，不需要 RSA 私钥：

```powershell
./data/mpc-recovery.exe validate -in data/recovery.json `
  -public-key data/public.json -rsa-key certs/ers-dev-4096/rsa-public.pem `
  -label "wallet-a/emergency/v1"
```

全部节点关闭后，可恢复完整私钥和 chain code：

```powershell
./data/mpc-recovery.exe recover -in data/recovery.json `
  -public-key data/public.json -rsa-key certs/ers-dev-4096/rsa-private.pem `
  -label "wallet-a/emergency/v1" -out data/recovered-private.json
```

恢复结果的 `privateKey`、`publicKey`、`chainCode` 均为 Base64。ECDSA 私钥为 32 字节大端标量；FROST 私钥为 32 字节规范小端 Ed25519 签名标量，**不是 RFC 8032 seed**，不能传给 `ed25519.NewKeyFromSeed`。FROST 离线派生使用基础库的 `eddsa.DeriveSigningScalar`，ECDSA 使用标准 BIP32 非硬化私钥派生。

恢复命令只将私钥写入明确指定的新文件，不在终端打印，拒绝覆盖现有文件。Unix 权限为 0600；Windows 由输出目录 ACL 控制访问。生成恢复数据不会撤销其恢复能力；更新节点分片、关闭功能、删除节点数据库，都不能让已经持有有效恢复备份和 RSA 私钥的人失去恢复能力。

## 证明和格式

采用公开的基本 additive cut-and-choose PVE 构造：每轮将本节点私钥分片随机拆成两个标量，各自使用独立随机种子的 RSA-OAEP-SHA256 加密。Fiat–Shamir 挑战选择公开其中一份随机拆分及其加密种子，另一份保留密文。验证者重建已公开一侧的密文和公开点，利用原公开分片补全另一侧的公开点，再重新计算挑战。128 轮挑战针对恢复失败的交互式基础构造给出 `2^-128` 的作弊概率；非交互版本在随机预言机模型下分析，不能把该数字理解为实现经过审计。

OAEP 标签为完整 manifest 和本节点 ID 的域分离 SHA-256 摘要；挑战另外绑定 RSA 公钥及公开分片。Manifest 绑定应用、keyID、会话 ID、阈值、原节点列表、公开分片、公钥、chain code、恢复 RSA 公钥和标签。元数据使用本项目 JSON 结构的固定字段顺序编码，版本为 1。验证还检查公开分片构成次数不超过 threshold 的同一个多项式，并与外部提供的根公钥一致。节点坐标沿用原库：CMP 使用原 party ID 的字节数值，FROST 使用原排序节点列表中从 1 开始的编号，不能按备份子集重新编号。

恢复时先验证全部证明，再解密每份备份中未公开的一侧，结合公开随机拆分得到本节点标量；检查其对应公开分片后，按原坐标做拉格朗日插值，最后再次比对根公钥。证明保证至少一轮可恢复，因此解密器会逐轮尝试，直到找到匹配公开点的一轮。

chain code 为公开派生参数，在本格式中以明文元数据保存并绑定到证明；它本身不能用于签名。该格式不对 chain code 提供保密性。RSA 公钥必须来自可信生成方并通过配置白名单分发：仅解析 RSA 公钥无法证明模数由两个合适的素数构成。

本实现参考公开协议理论，未复制 Blockdaemon SDK；没有新增密码学依赖。**这是新的、尚未经过独立密码学审计的 Go 实现，恢复数据不兼容 Blockdaemon ERS 格式。** 上生产前需要独立评审和固定备份测试向量。

参考：

- [Blockdaemon ERS 功能说明](https://builder-vault-tsm.docs.blockdaemon.com/docs/emergency-recovery-bv)
- [Coinbase 基本 PVE 规范，第 4 节](https://github.com/coinbase/cb-mpc/blob/master/docs/spec/publicly-verifiable-encryption-spec.pdf)
- [Coinbase PVE 理论和安全证明](https://github.com/coinbase/cb-mpc/blob/master/docs/theory/publicly-verifiable-encryption-as-ZK-theory.pdf)
