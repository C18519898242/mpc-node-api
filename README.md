# mpc-node-api

单个 MPC 节点的 Go HTTP 服务。当前支持 CMP（secp256k1 ECDSA）和 FROST-Ed25519 三节点建钥。

## 代码结构

- `main.go` 解析启动参数并选择运行模式。
- `internal/config` 加载节点 JSON 配置，校验监听地址并解析数据目录。
- `internal/node` 运行单节点，处理 REST、节点通信和 CMP / FROST 建钥。
- `internal/keystore` 管理 SQLite 中的建钥记录和分片。
- `configs` 和 `scripts` 提供三节点配置、启动命令和 HTTP 冒烟测试。

## Windows 三节点联调

在仓库根目录运行以下命令。脚本编译一次并启动三个独立进程，使用 `-Configs` 可以指定三份 JSON 配置。按 Ctrl+C 停止。

```powershell
.\scripts\dev-up.ps1
.\scripts\dev-up.ps1 -Smoke
```

`-Smoke` 启动三节点，使用同一个随机 `sessionId` 向每个 REST 端口发起 `POST /v1/keygen`，轮询 `GET /v1/sessions/{sessionId}`，检查三个节点成功、返回同一个压缩公钥并各自落盘，然后停止进程。

| 节点 | REST | MPC HTTP | 分片目录 |
|---|---:|---:|---|
| 1 | 8081 | 9081 | `data/node-1` |
| 2 | 8082 | 9082 | `data/node-2` |
| 3 | 8083 | 9083 | `data/node-3` |

单节点可用 `go run . -config configs/node-1.json` 启动。配置中的相对数据目录以配置文件所在目录为基准。

这套配置用于本机联调，监听地址限制在回环接口。MPC 消息使用本地 HTTP。脚本的 `-Smoke` 调用旧的 `/v1/keygen`，分片以 CMP 二进制文件写入各节点的数据目录。只使用测试密钥。

## ECDSA 建钥接口

`POST /ecdsa/keys?mpc_routing_id=<routingID>`。对三个节点并发发送同一份 JSON 和会话头。

- 请求体示例为 `{"threshold":1,"curve":"secp256k1","keyID":""}`。安全阈值 `1` 对应 2-of-3，`2` 对应 3-of-3，两种建钥都需要三个节点参与。
- `MPC-SessionID` 使用每次操作的新 ID。对其字节计算 64 位 FNV-1a，清除最高位后格式化为 16 位小写十六进制，作为 `MPC-RoutingID` 和查询参数的值。
- `MPC-Players` 每个玩家一条请求头，默认配置的玩家 ID 为 `1`、`2`、`3`，顺序不限。
- 三个节点各自完成建钥后返回 HTTP 200 和 `{"keyID":"..."}`。传空 `keyID` 时，各节点从会话 ID 生成相同的 ID。调用方应等待三个响应并比对 ID。

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

`POST /frost/keys?mpc_routing_id=<routingID>` 沿用上面的会话头、路由 ID 算法和同步响应格式。对三个节点并发发送同一份请求，例如 `{"threshold":1,"curve":"ed25519","keyID":""}`。支持安全阈值 `1`（2-of-3）和 `2`（3-of-3），建钥均由三个节点参与。

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

## 节点数据库

`/ecdsa/keys` 和 `/frost/keys` 使用各节点 `dataDir` 下的 `node.sqlite`。默认路径为 `data/node-1/node.sqlite`、`data/node-2/node.sqlite` 和 `data/node-3/node.sqlite`。数据库会记录所属节点，拒绝用其他节点 ID 打开。

`key_shares.id` 是各节点库内的自增主键。`key_id` 仍用于 API 查询，在同一算法内唯一。`created_at` 是建钥记录写入时的 UTC 时间。旧库在启动时自动升级，原有记录的创建时间留为 `NULL`。

同一建钥请求在重启后重发时，已落库的节点返回原 `keyID`。节点重启前未写完的会话会拒绝重放。如需重新建钥，请用新的会话 ID 和新的密钥 ID（或留空生成）。

数据库中的分片尚未加密，仅存放开发测试密钥。数据库访问集中在 `internal/keystore`，后续可在该边界实现 MySQL 或 PostgreSQL。

## 本地运行

节点将 JSON 日志写入标准错误。建钥、签名和公钥查询记录节点 ID、操作、算法、状态、结果和耗时。MPC 后台任务还记录失败阶段和超时。日志不包含密钥 ID、会话 ID、请求体、认证头、消息、摘要、签名、分片或底层错误原文。

使用 Go 1.24 或更新版本。在仓库根目录执行 `go run .` 可单独运行健康检查，默认监听 `127.0.0.1:8080`，可通过 `MPC_NODE_HTTP_ADDR` 修改。

```sh
curl http://127.0.0.1:8080/healthz
```

预期返回 `{"status":"ok"}`。运行 `go test ./...` 检查 HTTP 接口和两套 MPC 库的入口。
