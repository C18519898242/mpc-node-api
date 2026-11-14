# mpc-node-api

单个 MPC 节点的 Go HTTP 服务。当前提供 `GET /healthz`，并固定 CMP（secp256k1 ECDSA）和 FROST-Ed25519 的 Go 依赖版本。

## 本地运行

使用 Go 1.24 或更新版本，在仓库根目录执行 `go run .`。默认监听 `127.0.0.1:8080`，可以通过 `MPC_NODE_HTTP_ADDR` 为每个实例配置监听地址。

```sh
curl http://127.0.0.1:8080/healthz
```

预期返回 `{"status":"ok"}`。运行 `go test ./...` 检查 HTTP 接口和两套 MPC 库的入口。
