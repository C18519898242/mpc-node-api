# 助记词钱包

`POST /wallets` 一次生成 ECDSA（secp256k1）和 FROST（Ed25519）两把 3-of-3 根密钥。三个普通节点各自生成一组 24 词，本节点用同一组词派生两种算法的私有贡献。节点交换公开贡献，通过 mTLS 各自运行建钥协议。三组词一起可以离线恢复两把根私钥。

## 节点配置

功能默认关闭。启用要配置三节点 mTLS、REST API Key 和 `encryptorMasterPasswordEnv`。固定公钥模式在每个节点配置对应的 `walletBackup.publicKey`。需要允许按钱包提交三位保管人的公钥时，三个节点都设置 `walletBackup.allowRequestPublicKeys` 为 `true`。两种方式可以同时启用。所有公钥使用 Base64 编码的 PKIX DER 格式，建议使用 4096 位 RSA，各自的私钥由对应保管人在系统外保管。

```json
{
  "walletBackup": {
    "publicKey": "<Base64 PKIX DER>",
    "allowRequestPublicKeys": true
  }
}
```

`allowRequestPublicKeys` 默认关闭。可以只启用请求公钥模式，此时省略 `publicKey`，每次创建钱包都要提交完整的三份公钥。

### 本机测试 RSA

**测试私钥禁止用于生产。** 从项目根目录用 PowerShell 7 运行下列命令，前提是已经生成节点 mTLS 证书、准备好本地 MK 密码脚本，并空出默认的 REST 和 MPC 端口。

```powershell
.\scripts\gen-wallet-backup-test.ps1
. .\certs\mpc-master-passwords.ps1
$walletConfigs = @(1..3 | ForEach-Object { "certs/wallet-backup-test/configs/node-$_.json" })
.\scripts\dev-up.ps1 -Configs $walletConfigs
```

- RSA 测试私钥在 `certs/wallet-backup-test/node-1/rsa-private.pem` 到 `node-3/rsa-private.pem`。这个目录被 Git 忽略，另有 `TEST-ONLY.txt`。脚本重跑会保留已有的完整密钥对。
- 生成的节点配置在 `certs/wallet-backup-test/configs/`，其中 `walletBackup.publicKey` 各不相同。
- 独立测试数据库在 `data/wallet-backup-test/node-1/node.sqlite` 到 `node-3/node.sqlite`。

## 调用接口

向三个节点并发发 `POST /wallets?mpc_routing_id=<routingID>`，沿用现有建钥接口的 `Content-Type: application/json`、`Authorization: APIKEY ...`、`MPC-SessionID`、`MPC-RoutingID` 和每个节点一行的 `MPC-Players`。同一钱包使用相同的会话 ID、路由 ID、参与节点和应用 ID。

请求体为 `{}` 时，节点使用各自配置的公钥。按钱包指定公钥时，调用方收集并核对三位保管人的公钥，再向三个节点提交同一份 `partyId` 到公钥的映射。

```json
{
  "backupPublicKeys": {
    "1": "<保管人 1 的 Base64 PKIX DER RSA 公钥>",
    "2": "<保管人 2 的 Base64 PKIX DER RSA 公钥>",
    "3": "<保管人 3 的 Base64 PKIX DER RSA 公钥>"
  }
}
```

三个公钥必须分别来自不同的 RSA 密钥对，映射必须覆盖全部参与节点。每个节点使用自己对应的公钥封装备份。同一会话重试时，沿用原先的方式和映射。重新提交的有效请求如果使用另一种方式或另一组公钥，返回 `409`。响应格式如下。

```json
{
  "walletID": "<wallet ID>",
  "ecdsaKeyID": "<ECDSA key ID>",
  "frostKeyID": "<FROST key ID>"
}
```

每个节点将两份分片和助记词密文一次提交到本地库。客户端收到三个一致的成功响应后再使用钱包。若网络断开，可用同一会话 ID 重查已提交节点的原响应。已失败的会话在缓存过期或重启后返回 `409`。各节点的 SQLite 独立提交，如果某个节点最终写入失败，其他节点可能已完成。此时整组钱包不可用，请用新会话完整重建。两把密钥可用现有公钥、签名和预签名接口。

## 读取助记词加密备份

向目标节点发送以下请求，`walletID` 取自创建钱包的响应。三个节点各有一份备份，分别请求。

```http
GET /wallets/{walletID}/backup
Authorization: APIKEY <当前节点的 API Key>
```

接口按 API Key 对应的应用查找本节点已完成的备份。请求无需 MPC 会话。成功返回 `200` 和 `Cache-Control: no-store`。钱包不存在、属于其他应用或尚未完成时，均返回 `404`。凭据无效返回 `401`。节点关闭 REST 鉴权时返回 `403`。

| JSON 字段 | 含义 |
| --- | --- |
| `formatVersion` | 备份格式版本，目前为 `1` |
| `applicationID`、`partyID`、`walletID` | 所属应用、节点和钱包 |
| `backupKeyID` | 恢复 RSA 公钥 DER 的 SHA-256 指纹，上传的公钥使用规范化后的 PKIX DER |
| `wrappedKey` | Base64 编码的 RSA 包裹 AES 密钥 |
| `ciphertext` | Base64 编码的 `12 字节 nonce + 密文 + 16 字节 tag` |
| `aad` | Base64 编码的原始 AES-GCM 附加认证数据，解码后直接传给解密函数 |
| `manifest` | 用于离线恢复两把根密钥的公开数据 |

系统外先用 `backupKeyID` 找到对应的 RSA 私钥，再用 RSA-OAEP-SHA256（空 label）解开 `wrappedKey`。用得到的 AES 密钥、解码后的 `aad` 和 `ciphertext` 校验并解密，得到该节点的助记词。

## 数据库和离线恢复材料

`key_shares` 保存两个原有格式的加密分片。`wallet_backups` 保存本节点的加密备份和公共 `manifest`。清除普通签名分片后，离线备份和历史建钥回执仍保留。重查回执不会恢复已删除的签名分片。

备份格式 `format_version = 1` 使用 RSA-OAEP-SHA256（空 label）包裹独立随机 32 字节 AES 密钥，保存为 `wrapped_key`。`ciphertext` 是用 AES-256-GCM 加密后的助记词 UTF-8 文本，编码为 `12 字节 nonce || 密文 || 16 字节 tag`。`backup_key_id` 是公钥 DER 的 SHA-256 小写十六进制指纹。GCM 的 AAD 是以下五个字符串组成的 JSON 数组，使用 Go `json.Marshal` 的默认转义和紧凑格式。

```json
["mpc-node-api/wallet-backup/v1","<application_id>","<partyId>","<wallet_id>","<backup_key_id>"]
```

可离线用三个各自的私钥解封、读取三组词，再以 `manifest.ecdsa` 和 `manifest.frost` 中的公共数据调用 `mpc-wallet-recovery` 的两个恢复函数。根公钥和 chain code 应作为公开恢复材料单独保存并核验。FROST 恢复得到签名标量和 chain code。RSA 私钥和解封流程由系统外的恢复方管理。接入 KMS 或 enclave 时需要另行实现解封和受信运行环境。
