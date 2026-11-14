# mpc-node-api

单个 MPC 节点的 Go HTTP 服务。当前支持 CMP（secp256k1 ECDSA）3-of-3 建钥，并固定 CMP 和 FROST-Ed25519 的 Go 依赖版本。

## 代码结构

- `main.go` 解析启动参数并选择运行模式。
- `internal/config` 加载节点 JSON 配置，校验监听地址并解析数据目录。
- `internal/node` 运行单节点。 `server.go` 管理监听端口，`rest.go` 处理业务请求，`peer.go` 收发节点消息，`keygen.go` 管理会话和 CMP 轮次，`shares.go` 读写本地分片。
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

这套配置用于本机联调，监听地址限制在回环接口。MPC 消息使用本地 HTTP，分片以 CMP 二进制格式写入各节点的数据目录。只使用测试密钥。

## ECDSA 建钥接口

`POST /ecdsa/keys?mpc_routing_id=<routingID>`。对三个节点并发发送同一份 JSON 和会话头。

- 请求体示例为 `{"threshold":1,"curve":"secp256k1","keyID":""}`。安全阈值 `1` 对应 2-of-3，`2` 对应 3-of-3，两种建钥都需要三个节点参与。
- `MPC-SessionID` 使用每次操作的新 ID。对其字节计算 64 位 FNV-1a，清除最高位后格式化为 16 位小写十六进制，作为 `MPC-RoutingID` 和查询参数的值。
- `MPC-Players` 每个玩家一条请求头，默认配置的玩家 ID 为 `1`、`2`、`3`，顺序不限。
- 三个节点各自完成建钥后返回 HTTP 200 和 `{"keyID":"..."}`。传空 `keyID` 时，各节点从会话 ID 生成相同的 ID。调用方应等待三个响应并比对 ID。

此接口用于本机联调，采用静态玩家和服务端固定会话超时。每个节点的分片只保留在内存，重启后失效。

## 本地运行

使用 Go 1.24 或更新版本。在仓库根目录执行 `go run .` 可单独运行健康检查，默认监听 `127.0.0.1:8080`，可通过 `MPC_NODE_HTTP_ADDR` 修改。

```sh
curl http://127.0.0.1:8080/healthz
```

预期返回 `{"status":"ok"}`。运行 `go test ./...` 检查 HTTP 接口和两套 MPC 库的入口。
