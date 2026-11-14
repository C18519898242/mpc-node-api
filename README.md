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

## FROST-Ed25519 建钥接口

`POST /frost/keys?mpc_routing_id=<routingID>` 沿用上面的会话头、路由 ID 算法和同步响应格式。对三个节点并发发送同一份请求，例如 `{"threshold":1,"curve":"ed25519","keyID":""}`。支持安全阈值 `1`（2-of-3）和 `2`（3-of-3），建钥均由三个节点参与。

节点把本地分片和 FROST 公共信息写入 SQLite 后返回成功。

`POST /frost/keys/{keyID}/publickey` 可向任意持有分片的单个节点查询 Ed25519 根公钥，无需 MPC 会话头。请求体传 `{"chainPath":null}` 或 `{"chainPath":[]}`。响应的 `curve` 为 `ed25519`，`publicKey` 是标准 Base64 编码的 32 字节 Ed25519 公钥。非空派生路径返回 HTTP 400。

`POST /frost/keys/{keyID}/sign?mpc_routing_id=<routingID>` 使用与 ECDSA 签名相同的会话头。向选定节点并发发送同一份请求，例如 `{"chainPath":null,"message":"aGVsbG8="}`。`message` 是原始消息的标准 Base64 编码，示例签名的是 `hello`。FROST 使用根密钥，非空派生路径返回 HTTP 400。每个参与节点返回 `{"signature":"..."}`，其中 `signature` 是 Base64 编码的完整 64 字节 Ed25519 签名，可用查询到的公钥和原始消息直接验签。

## 节点数据库

`/ecdsa/keys` 和 `/frost/keys` 使用各节点 `dataDir` 下的 `node.sqlite`。默认路径为 `data/node-1/node.sqlite`、`data/node-2/node.sqlite` 和 `data/node-3/node.sqlite`。数据库会记录所属节点，拒绝用其他节点 ID 打开。

`key_shares.id` 是各节点库内的自增主键。`key_id` 仍用于 API 查询，在同一算法内唯一。`created_at` 是建钥记录写入时的 UTC 时间。旧库在启动时自动升级，原有记录的创建时间留为 `NULL`。

同一建钥请求在重启后重发时，已落库的节点返回原 `keyID`。节点重启前未写完的会话会拒绝重放。如需重新建钥，请用新的会话 ID 和新的密钥 ID（或留空生成）。

数据库中的分片尚未加密，仅存放开发测试密钥。数据库访问集中在 `internal/keystore`，后续可在该边界实现 MySQL 或 PostgreSQL。

## 本地运行

使用 Go 1.24 或更新版本。在仓库根目录执行 `go run .` 可单独运行健康检查，默认监听 `127.0.0.1:8080`，可通过 `MPC_NODE_HTTP_ADDR` 修改。

```sh
curl http://127.0.0.1:8080/healthz
```

预期返回 `{"status":"ok"}`。运行 `go test ./...` 检查 HTTP 接口和两套 MPC 库的入口。
