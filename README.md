# mpc-node-api

单个 MPC 节点的 Go HTTP 服务，支持 CMP（secp256k1 ECDSA）和 FROST-Ed25519 建钥及签名。仓库提供三节点联调配置。

手机节点的本地模拟（一个出站连接的嵌入式节点 + 两个服务端）：[运行、存储位置与 Android 接入边界](docs/mobile-nodes.md)。

## 代码结构

- `main.go` 解析启动参数并选择运行模式。
- `internal/config` 加载节点 JSON 配置，校验监听地址并解析数据目录。
- `internal/node` 运行单节点，处理 REST、节点通信和 CMP / FROST 建钥。
- `internal/keystore` 管理 SQLite 中的建钥记录和分片。
- `configs` 和 `scripts` 提供三节点配置、启动命令和 HTTP 冒烟测试。

## Windows 三节点联调

在仓库根目录首次运行证书生成命令，然后启动三个节点。启动脚本默认使用 `configs/node-*.json`。按 Ctrl+C 停止。

```powershell
.\scripts\gen-mpc-certs.ps1
.\scripts\dev-up.ps1
```

停止节点后，可以用仓库随附的测试凭据运行冒烟测试。

```powershell
$devKeys = Get-Content -Raw configs/dev-api-keys.json | ConvertFrom-Json
$env:MPC_NODE_API_KEY_1 = $devKeys.'1'.default
$env:MPC_NODE_API_KEY_2 = $devKeys.'2'.default
$env:MPC_NODE_API_KEY_3 = $devKeys.'3'.default
.\scripts\dev-up.ps1 -Smoke
```

`-Smoke` 启动三节点，使用同一个随机 `sessionId` 向每个 REST 端口发起 `POST /v1/keygen`，轮询 `GET /v1/sessions/{sessionId}`，检查三个节点成功、返回同一个压缩公钥并各自落盘，然后停止进程。

| 节点 | REST | MPC HTTP | 分片目录 |
|---|---:|---:|---|
| 1 | 8081 | 9081 | `data/node-1` |
| 2 | 8082 | 9082 | `data/node-2` |
| 3 | 8083 | 9083 | `data/node-3` |

单节点可用 `go run . -config configs/node-1.json` 启动。配置中的相对数据目录以配置文件所在目录为基准。

默认配置下，MPC 端口使用 TLS 1.3 双向认证，REST 端口使用回环 HTTP。`-Smoke` 调用旧的 `/v1/keygen`，分片以 CMP 二进制文件写入各节点的数据目录。只使用测试密钥。 [MPC mTLS 使用说明](docs/mtls/README.md)

## REST API Key 与应用隔离

默认三节点联调配置已开启认证。`configs/dev-api-keys.json` 包含 `default` 和 `wallet-a` 的测试凭据，仅供回环地址上的本地联调。

在节点 JSON 中加入 `restAuth` 开启认证。每把 API Key 配置一个 `applicationID` 和原始凭据字符串的 Base64 编码 SHA-256 摘要。

```json
{
  "restAuth": {
    "apiKeys": [
      {"applicationID":"wallet-a","sha256":"<Base64 SHA-256 digest>"}
    ]
  }
}
```

生成凭据时使用至少 32 字节的随机值，再编码为字符串；对该字符串的 UTF-8 字节计算摘要。客户端发送 `Authorization: APIKEY <原始凭据字符串>`。每个节点可以使用不同的凭据，同一组 MPC 请求在参与节点上必须映射到相同的 `applicationID`。轮换凭据时，可以把新旧两把凭据暂时绑定到同一个应用。

开启后，`GET /healthz` 可匿名访问，其余 REST 请求需要认证。凭据缺失或无效返回 `401`。访问另一个应用独有的 `keyID` 与访问当前应用不存在的 `keyID` 一样返回 `404`。不同应用可以使用相同的 `keyID` 或 `sessionId`。同一个应用里的凭据具有相同的操作权限。

每个节点的密钥、预签名和分片刷新记录都保存在该节点数据目录下的 `node.sqlite`，按表中的 `application_id` 隔离。升级时，已有记录自动归到 `default` 应用。如需继续访问，在每个参与节点配置一把映射到 `default` 的凭据。旧版 `/v1/keygen` 使用独立的分片文件，仍按应用区分文件目录。启用认证时同时更新参与节点的配置和客户端凭据。省略 `restAuth` 会使用本机联调模式。

启用认证后，`dev-up.ps1 -Smoke` 从 `MPC_NODE_API_KEY_1`、`MPC_NODE_API_KEY_2`、`MPC_NODE_API_KEY_3` 读取默认三节点的凭据。三个凭据需要映射到同一个应用。

## 节点主密钥

在节点的 JSON 配置中设置 `"encryptorMasterPasswordEnv": "MPC_NODE_1_MASTER_PASSWORD"`，再通过启动环境注入密码。三节点联调可以分别配置三个环境变量，让每个节点使用独立的密码。

若本机已将三个变量写入 Git 忽略的 `certs/mpc-master-passwords.ps1`，从仓库根目录运行以下命令启动。每次重启使用同一份密码。

```powershell
. .\certs\mpc-master-passwords.ps1
.\scripts\dev-up.ps1
```

首次启动时，节点生成随机的 32 字节 MK，用 PBKDF2-HMAC-SHA256（600,000 次、随机 16 字节盐）从密码派生 KEK，再用 AES-256-GCM 加密 MK。节点把格式版本、盐和含随机 nonce 的密文写入自己的 `node.sqlite` 的 `node_master_key` 表。后续启动用同一密码解密现有记录，再打开 REST 和 MPC 端口。密码缺失、密码错误或记录损坏时，节点会在 `master_key` 阶段退出。已有 MK 的节点仍需要该配置才能启动。

未配置密码且库中没有 MK 时，节点保留原来的存储模式。

### 私钥分片加密

启用 MK 后，节点用 HKDF-SHA256 按节点、用途、`application_id`、算法和 `key_id` 从 MK 派生 CEK，再用 AES-256-GCM 和随机 nonce 加密私钥分片。CEK 在读写时重新派生。数据库的 `key_shares.share` 和分片刷新候选使用 `share_format = 1` 标识加密格式，预留和删除状态继续以 `share IS NULL` 表示。旧版 `/v1/keygen` 的分片文件也会加密。

升级后首次启动会迁移节点当前数据库和旧版分片文件。重启时先读 MK，签名时再解密对应分片。预签名也使用独立 CEK 加密，详见下文“预签名加密存储”。升级前的数据库备份和废弃库仍可能含明文分片。

## 节点版本与协议

使用 `-config` 启动节点后，`GET /version` 返回服务主版本 `{"version":"1"}`。通过 `GET /info/protocols` 可查询该节点注册的 MPC 协议。

```json
{
  "ecdsa": { "name": "cmp", "curve": "secp256k1", "version": 1 },
  "frost": { "name": "frost", "curve": "ed25519", "version": 1 }
}
```

协议对象的 `version` 标识节点间 MPC 消息的兼容版本，由实现统一声明。节点配置文件继续管理本地端口、数据目录和对端节点。Blockdaemon Go SDK 的同名接口使用整数协议编号，直接调用本接口的客户端应按上面的对象结构解析。

## ECDSA 建钥接口

`POST /ecdsa/keys?mpc_routing_id=<routingID>`。对 `MPC-Players` 指定的节点并发发送同一份 JSON 和会话头。

- 请求体示例为 `{"threshold":1,"curve":"secp256k1","keyID":""}`。签名至少需要 `threshold + 1` 个节点，建钥要由本次选定的所有节点参与。
- `MPC-SessionID` 使用每次操作的新 ID。对其字节计算 64 位 FNV-1a，清除最高位后格式化为 16 位小写十六进制，作为 `MPC-RoutingID` 和查询参数的值。
- `MPC-Players` 每个玩家一条请求头，默认配置的玩家 ID 为 `1`、`2`、`3`，顺序不限。
- 各节点完成建钥后返回 HTTP 200 和 `{"keyID":"..."}`。传空 `keyID` 时，各节点从会话 ID 生成相同的 ID。调用方应等待全部响应并比对 ID。

此接口采用静态玩家和服务端固定会话超时。节点把分片写入 SQLite 后返回成功。

`POST /ecdsa/keys/{keyID}/publickey` 可以向任意持有该密钥分片的单个节点查询公钥，无需 MPC 会话头。请求体 `{"chainPath":null}` 查询根公钥，`{"chainPath":[0,1]}` 查询非硬化 BIP32 派生公钥。响应的 `curve` 为 `secp256k1`，`publicKey` 是标准 Base64 编码的 65 字节未压缩 SEC1 点。

`POST /ecdsa/keys/{keyID}/sign?mpc_routing_id=<routingID>` 使用与建钥相同的会话头和路由 ID 算法。每次签名使用新的 `MPC-SessionID`，只向 `MPC-Players` 指定的节点并发发送相同请求。参与方数量至少为建钥时的 `threshold + 1`。

```json
{"chainPath":null,"messageHash":"IRNprmnFIL3etbcSMvcRoCCABjD63A1AAJYHEsj8OoA="}
```

`messageHash` 是标准 Base64 编码的 32 字节摘要。可传非硬化 BIP32 路径使用派生密钥。每个参与节点返回 `{"signature":"..."}`，其中 `signature` 是完整的 DER ECDSA 签名，使用标准 Base64 编码，可直接验签。签名会话和结果保留在进程内存中。

`POST /ecdsa/keys/{keyID}/{count}/presiggen?mpc_routing_id=<routingID>` 为根密钥批量预计算。向指定的 `MPC-Players` 并发发送空请求体，使用同一个新会话 ID。单批支持 1 至 8 份。节点将整批本地材料写入各自的 `node.sqlite` 后返回 `{"ids":["..."]}`。调用方应等全部参与节点成功并比对有序 ID 列表。已完成的同参数会话在重启后也返回原批次 ID，已消费的 ID 不会因此重新可用。预签名材料用于本机联调，使用与密钥分片相同的存储保护。

`POST /ecdsa/keys/{keyID}/signwithpresig` 在单个节点消费预签名，无需 MPC 会话头。请求示例：

```json
{"chainPath":null,"messageHash":"IRNprmnFIL3etbcSMvcRoCCABjD63A1AAJYHEsj8OoA=","presignatureId":"<presiggen 返回的 ID>"}
```

向预计算组的每个节点发送相同的 ID、32 字节摘要和路径。支持根密钥和非硬化 BIP32 路径。空 ID 会在当前节点选择该密钥最早入库的可用记录，只应在首个节点使用，再把返回的 `presignatureId` 传给同组其余节点。响应使用 SDK 支持的结构化 `additive` 部分签名字段，包括 `presignatureId`、`curve`、`playerIndex`、`threshold`、`sharing`、`r`、`publicKey` 和 `sShare`。响应的 `threshold` 为预计算组人数减一，合成需要整组份额。客户端可通过 SDK 的 `SignWithPresignature` 解析响应，再调用 `ECDSAFinalizeSignature` 合成。

每个节点提交 SQLite 删除事务后才返回份额。未知或已消费的 ID 返回 HTTP 404。如果部分节点超时或失败，弃用该 ID，换一个 ID 重试。恢复旧数据库备份前须清空可用预签名，防止已消费的材料重新出现。

`POST /key/{keyID}/count/presigs` 查询当前节点上该密钥可用的预签名数量，无需 MPC 会话头。请求体为 `{}`，成功响应为单个 JSON 整数（例如 `2`），未知密钥返回 HTTP 404。

`DELETE /key/{keyID}/presigs` 清空当前节点上该密钥的所有可用预签名，无请求体、无需 MPC 会话头。成功返回 HTTP 204，未知密钥返回 HTTP 404。若需清理整组节点，需分别向各节点发起请求。

## FROST-Ed25519 建钥接口

`POST /frost/keys?mpc_routing_id=<routingID>` 沿用上面的会话头、路由 ID 算法和同步响应格式。向选定组并发发送同一份请求，例如 `{"threshold":1,"curve":"ed25519","keyID":""}`。

节点把本地分片和 FROST 公共信息写入 SQLite 后返回成功。

`POST /frost/keys/{keyID}/publickey` 可向任意持有分片的单个节点查询 Ed25519 公钥，无需 MPC 会话头。请求体传 `{"chainPath":null}` 或 `{"chainPath":[]}` 查询根公钥，传 `{"chainPath":[0,1]}` 查询子公钥。响应的 `curve` 为 `ed25519`，`publicKey` 是标准 Base64 编码的 32 字节 Ed25519 公钥。索引范围为 0 至 2147483647，硬化索引返回 HTTP 400。

`POST /frost/keys/{keyID}/sign?mpc_routing_id=<routingID>` 使用与 ECDSA 签名相同的会话头。向选定节点并发发送同一份请求，例如 `{"chainPath":[0,1],"message":"aGVsbG8="}`。`message` 是原始消息的标准 Base64 编码，示例签名的是 `hello`。每个参与节点返回 `{"signature":"..."}`，其中 `signature` 是 Base64 编码的完整 64 字节 Ed25519 签名，可用同一路径查询到的公钥和原始消息直接验签。

普通 FROST 建钥记录使用根公钥确定初始 chain code，现有数据库记录可直接派生。非硬化派生规则由 `go.mod` 锁定的 FROST fork 提供。

`POST /frost/keys/{keyID}/{count}/presiggen?mpc_routing_id=<routingID>` 使用和 ECDSA 批量预签名相同的会话头，向选定节点并发发送空请求体。单批支持 1 至 8 份。节点交换并核对公开承诺，将各自的一次性随机数和同组承诺写入 SQLite 的 `frost_presignatures`，再返回相同的有序 `{"ids":["..."]}`。批次记录保存在 `frost_presign_batches`。

`POST /frost/keys/{keyID}/signwithpresig` 在单个节点消费预签名，无需 MPC 会话头或节点间通信。

```json
{"chainPath":[0,1],"message":"aGVsbG8=","presignatureId":"<presiggen 返回的 ID>"}
```

`message` 是原始消息的标准 Base64 编码。`chainPath` 支持非硬化路径，传 `null` 或 `[]` 使用根密钥。向预计算组的每个节点发送相同的 ID、消息和路径。也可只在首个节点传空 ID，由该节点选择该密钥最早入库的可用记录，然后把响应中的 ID 传给同组其余节点。

响应返回 `sharing: "additive"` 的结构化份额，包含 `presignatureId`、`schnorr_variant`（`Ed25519`）、`curve`（`ed25519`）、`playerIndex`、`threshold`、`r`、`publicKey`、`challenge` 和 `sShare`。响应的 `threshold` 等于预计算组人数减一。合并时确认份额来自预计算组的每个节点，且 ID、`r`、`challenge` 和公钥一致。把整组 `sShare` 按大端标量解码并相加（模 Ed25519 群阶），将 32 字节小端的和拼接在 32 字节的 `r` 后面，得到标准 Ed25519 签名。使用同一路径的公钥和原始消息验签。响应字段兼容 Blockdaemon Go SDK v73.5.2 的 Schnorr 份额解析及 `SchnorrFinalizeSignature`。SDK 默认请求 `/schnorr/`，接入本服务时需要映射到 `/frost/`。

节点提交 SQLite 删除事务后才返回份额。未知或已消费的 ID 返回 HTTP 404。如果部分节点超时或失败，弃用该 ID，换一个 ID 重试。恢复旧数据库备份前须清空可用预签名，防止已消费的材料重新出现。

### 预签名加密存储

启用 MK 的节点会对 ECDSA、FROST 的预签名 `share` 使用 AES-256-GCM 加密。每条预签名通过现有 HKDF-SHA256 从 MK 派生独立 CEK，用途为 `presign:<presignatureID>`，同时绑定节点 ID、applicationID、算法及 keyID；不复用长期私钥分片的 CEK。随机 nonce 和认证标签包含在 `share` 中，CEK 不写入数据库。

`ecdsa_presignatures`、`frost_presignatures` 增加 `share_format`：`0` 为原始序列化材料，`1` 为加密材料。启用 MK 启动时，旧表自动补列，并在同一事务中将现存明文分片及预签名迁移为密文，保留 ID、创建时间和消费状态；已加密记录不会重复加密。解密与删除在同一 SQLite 事务中完成，只有认证成功且删除提交后才返回明文；密文篡改、跨记录替换或未加载对应 MK 会失败，不提交删除。

加密沿用现有 MK 配置，没有新增开关。未配置 MK 的开发实例仍保留明文模式；仓库中的正常节点和手机模拟配置均启用 MK。加密不防止旧数据库快照回滚造成预签名复用，恢复备份时仍需清空可用预签名。

## 刷新密钥分片

`POST /ecdsa/keys/{keyID}/reshare` 和 `POST /frost/keys/{keyID}/reshare` 刷新现有密钥在所有分片持有者上的分片。刷新保留原 `keyID`、阈值、根公钥和派生公钥。

首次刷新使用新的 MPC 会话 ID，向所有分片持有者并行发送相同参数。沿用建钥的 `MPC-SessionID`、`MPC-RoutingID`、每个玩家一条 `MPC-Players` 及 URL 查询参数 `mpc_routing_id`，请求体留空。每个节点成功后返回 HTTP 204。刷新期间，同一密钥上的签名和预签名操作可能返回 HTTP 409。

节点把候选分片暂存到各自的 SQLite，确认全组已持久化同一代次后再启用。本地启用和清理该密钥的旧预签名在同一事务中提交。协调端收到全部 204 后再恢复签名，并清理缓存的旧预签名 ID、重新生成所需的预签名和分片备份。

如果只收到部分 204，向全组重发原会话，已暂存的节点可从 SQLite 继续确认和启用。如果会话在候选分片写入前中断，且确认全组仍处于刷新前的同一代次，使用新的会话 ID 重试。

## 复制密钥到另一个分片组

ECDSA 使用 `POST /ecdsa/keys/{sourceKeyID}/keycopy`，Ed25519 使用 `POST /frost/keys/{sourceKeyID}/keycopy`。请求使用建钥的 MPC 会话头和 `mpc_routing_id`。向目标组所有节点并发发送，同一次复制使用同一个新会话 ID、目标 `MPC-Players`、目标 `keyID` 和目标 `threshold`。目标阈值从 1 到目标组人数减 1，目标组至少包含原安全阈值加 1 个原分片持有者。

以 `old-key` 的原持有者 1、3（安全阈值 1）为例，复制给 1、2、3 并将副本阈值设为 2。

| 算法 | 持有者 1、3 | 新节点 2 |
| --- | --- | --- |
| ECDSA | 路径 `/ecdsa/keys/old-key/keycopy`，请求 `{"keyID":"new-key","threshold":2,"curve":""}` | 路径 `/ecdsa/keys/_/keycopy`，请求 `{"keyID":"new-key","threshold":2,"curve":"secp256k1"}` |
| Ed25519 | 路径 `/frost/keys/old-key/keycopy`，请求 `{"keyID":"new-key","threshold":2,"curve":"","schnorr_variant":""}` | 路径 `/frost/keys/_/keycopy`，请求 `{"keyID":"new-key","threshold":2,"curve":"ED-25519","schnorr_variant":"Ed25519"}` |

所有节点的 `keyID` 都传空字符串时，由会话 ID 生成相同的副本 ID。各目标节点在内存中校验候选分片，确认同一组候选分片后把本节点的正式分片写入 `key_shares`，成功响应 `{"keyID":"new-key"}`。副本保留根公钥和派生公钥，拥有独立分片和预签名。原密钥继续通过原 ID 使用。

收到所有目标节点的成功响应后再使用副本。若复制失败或中断，用新会话和新副本 ID 重试。节点在内存中短暂保留已完成会话的参数和结果，用于返回相同请求的结果以及等待同组节点确认。节点重启后可按 `keyID` 使用已写入的正式分片。

每个目标节点的 `peers` 必须包含其他目标玩家。新建和复制的 FROST 密钥会保存自己的玩家列表。如果要在已有旧版 FROST 分片的节点上调整 `peers`，把这些旧密钥的原玩家列表填到 `legacyFrostPlayers`，例如 `["1","2","3"]`。

## 删除本地密钥分片

`DELETE /key/{keyID}` 删除接收请求节点上的 ECDSA 或 FROST 分片。请求体留空，无需 MPC 会话头。成功返回 HTTP 204，当前节点没有对应分片时返回 404，同一密钥正在执行操作时返回 409。若两种算法使用了相同的 `keyID`，该节点上的两份分片都会删除。

节点在同一 SQLite 事务中清空 `key_shares.share`、删除本地预签名并作废未启用的刷新分片。数据库保留已使用的 ID，防止旧会话重放后重新生成密钥。删除整组分片时，需要逐个调用持有分片的节点。

## 密钥导出和导入

ECDSA 和 FROST 都提供以下两个接口，使用 API Key 和与建钥相同的 MPC 会话头。

| 方法 | 路径 | 作用 |
|---|---|---|
| POST | `/{ecdsa 或 frost}/keys/{keyID}/exportkey` | 重新分享并返回 RSA 加密的节点分片 |
| POST | `/{ecdsa 或 frost}/keys/importkey` | 用节点 RSA 私钥解密分片，重新分享并保存新 keyID |

导出请求为 `{"chainPath":[],"wrappingKey":"<Base64 SPKI DER RSA 公钥>"}`。省略或清空 `chainPath` 导出根密钥，非空路径导出对应的非硬化派生密钥。每个参与节点返回自己的一份加密结果，包括 `version`、`wrappedKey` 和 `ciphertext`。包裹使用 RSA-OAEP-SHA256 加密随机 AES-256 内容密钥，AES-GCM 加密序列化的分片和 chain code。

导入请求为 `{"keyID":"imported-key","threshold":2,"wrappedKeyShare":{...}}`，其中 `wrappedKeyShare` 使用对应节点的完整导出响应。同时向参与节点发请求，使用同一个全新会话 ID、目标 `keyID` 和 `threshold`。分片必须来自同一次导出，各分片与原来的 `partyId` 对应。可以在新实例上导入，目标节点要保留这些 `partyId`。导入的密钥作为新根密钥使用，继续派生时从新根开始指定路径，导出的 chain code 会一起保留。

导出默认关闭。只有显式设置 `keyTransfer.exportEnabled = true`，才会开放 ECDSA 和 FROST 的 `exportkey`、`exportkeyshare`。省略配置或设为 `false` 时，这些接口返回 403。仓库中的三个节点配置均将其设为 `false`，启用后需要重启节点。导入接口沿用自己的 RSA 私钥配置。

以下示例开启导出。相对路径以节点配置文件为基准。`exportWrappingKeys` 可选，用于允许向额外的 RSA SPKI DER 公钥导出，JSON 中公钥使用 Base64。启用导出后，节点允许向自己的 wrapping 公钥导出。

```json
{
  "keyTransfer": {
    "exportEnabled": true,
    "wrappingPrivateKeyFile": "../certs/key-transfer-dev-4096/rsa-private.pem",
    "exportWrappingKeys": []
  }
}
```

本机三节点配置使用一套临时测试 RSA 密钥。新的开发环境先运行 `go run ./cmd/mpc-wrapkeygen` 生成 4096 位 RSA 密钥。私钥、PEM 公钥和 DER 公钥保存在 Git 忽略的 `certs/key-transfer-dev-4096` 下。该命令保留已有文件，避免替换已使用的解包私钥。RSA 私钥只在节点本机读取。导入保存到当前 API Key 所属应用，开启 MK 的节点会用 CEK 加密落库。

导出包采用本项目版本 1 的分片格式，可供本项目节点导入。Blockdaemon SDK 的包裹格式需要单独适配。密码保护外层由调用方本地处理。

### 单节点分片备份

ECDSA 和 FROST 还提供 `POST /{algorithm}/keys/{keyID}/exportkeyshare` 和 `POST /{algorithm}/keys/importkeyshare`，分别备份和恢复该节点的原始分片。这两个接口只需要 API Key，无需 MPC 会话头和对端节点在线。

导出请求为 `{"wrappingKey":"<Base64 SPKI DER RSA 公钥>"}`，响应仍包含 `version`、`wrappedKey`、`ciphertext`。导入请求为 `{"wrappedKeyShare":{...}}`，使用完整导出响应作为 `wrappedKeyShare`。RSA 包裹密钥和白名单配置与 `exportkey` 共用。

备份携带原节点 ID、应用 ID、`keyID`、建钥会话 ID、阈值、创建时间及原始分片。恢复后返回原 `keyID`，需要匹配原 `partyId` 和原 `applicationID`。原记录缺失或分片已删除时可以恢复，同一份现存分片的重复导入成功返回。现存记录的分片或会话参数不同、分片刷新处于待提交状态时返回 409。已启用 MK 的节点在恢复时用自己的 CEK 加密保存。

这两个接口只处理私钥分片，不携带预签名。分片刷新后请重新备份，恢复的分片需要与其他节点属于同一次分享。单节点备份包与 `exportkey` 的重新分享包分别通过各自的接口导入。

### 紧急恢复完整私钥（ERS）

ECDSA 和 FROST 新增 `POST /{algorithm}/keys/{keyID}/recoverydata`。参与节点用同一会话确认参数后，各自返回 RSA 加密、带公开可验证证明的恢复数据。节点不会拼出完整私钥，也不需要持有恢复 RSA 私钥。

`emergencyRecovery.enabled` 默认 `false`，与普通导出的 `keyTransfer.exportEnabled` 独立。启用时必须配置可信 RSA 公钥白名单。离线工具 `cmd/mpc-recovery` 提供 `combine`、`validate`、`recover`，收集 `threshold + 1` 份数据后可在全部节点关闭时恢复根私钥和 chain code。恢复数据使用本项目格式。配置、调用示例、证明方案和限制见 [紧急恢复说明](docs/emergency-recovery.md)。

## 节点数据库

`/ecdsa/keys` 和 `/frost/keys` 使用各节点 `dataDir` 下的 `node.sqlite`。默认路径为 `data/node-1/node.sqlite`、`data/node-2/node.sqlite` 和 `data/node-3/node.sqlite`。数据库会记录所属节点，拒绝用其他节点 ID 打开。

`key_shares.id` 是各节点库内的自增主键。`key_id` 仍用于 API 查询，在同一算法内唯一。`created_at` 是建钥记录写入时的 UTC 时间。旧库在启动时自动升级，原有记录的创建时间留为 `NULL`。

同一建钥请求在重启后重发时，已落库的节点返回原 `keyID`。节点重启前未写完的会话会拒绝重放。如需重新建钥，请用新的会话 ID 和新的密钥 ID（或留空生成）。

启用 MK 的节点会加密数据库中的私钥分片。数据库访问集中在 `internal/keystore`，后续可在该边界实现 MySQL 或 PostgreSQL。

## 本地运行

节点将 JSON 日志写入标准错误。建钥、签名和公钥查询记录节点 ID、操作、算法、状态、结果和耗时。MPC 后台任务还记录失败阶段和超时。日志不包含密钥 ID、会话 ID、请求体、认证头、消息、摘要、签名、分片或底层错误原文。

使用 Go 1.24 或更新版本。在仓库根目录执行 `go run .` 可单独运行健康检查，默认监听 `127.0.0.1:8080`，可通过 `MPC_NODE_HTTP_ADDR` 修改。

```sh
curl http://127.0.0.1:8080/healthz
```

预期返回 `{"status":"ok"}`。运行 `go test ./...` 检查 HTTP 接口和两套 MPC 库的入口。
