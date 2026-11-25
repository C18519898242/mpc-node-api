# Docker 多节点部署

同一份镜像可以启动多个 MPC 节点，**每个容器只运行一个节点**。节点编号由 `partyId` 决定。配置、证书和数据目录分别从宿主机挂载。单台机器启动三个开发节点可以沿用仓库的 [Docker Desktop 配置](../README.md#docker-desktop-三节点联调)。

## 构建镜像

从仓库根目录运行。跨主机部署时，将同一版本的镜像分发到各台主机。

```sh
docker build -t mpc-node-api:1.0.0 .
```

## 持久化哪些文件

每个节点使用自己的宿主机目录。例如节点 1 用 `/srv/mpc-node/node-1`，其他节点用各自的目录。

| 宿主机目录或文件 | 容器内路径 | 用途 |
| --- | --- | --- |
| `config/node.json` | `/etc/mpc-node/node.json` | 保存节点编号、对端地址、API Key 摘要和主密码环境变量名。只读挂载。 |
| `tls/ca.crt`、`tls/node.crt`、`tls/node.key` | `/run/mpc-tls/` | 共享 CA 证书和该节点自己的 mTLS 身份。只读挂载。 |
| `data/` | `/data/` | 写入 `node.sqlite`，其中存有分片、预签名和加密后的 MK。整个目录读写挂载。 |

镜像以 UID/GID `10001:10001` 运行。配置和证书文件需允许该用户读取，数据目录需允许该用户写入。使用独立硬盘时，先挂载硬盘，再启动容器。备份时同时保留配置、证书和数据目录，并单独保管每个节点的 `MPC_MASTER_PASSWORD`。重建容器时用相同的 `partyId`、原数据目录和原主密码启动。

## 配置三个或更多节点

下面是节点 1 的 `node.json` 示例。假设节点所在主机能通过私网域名 `mpc-node-1.internal`、`mpc-node-2.internal`、`mpc-node-3.internal` 相互访问。

```json
{
  "partyId": "1",
  "restAddr": "0.0.0.0:8080",
  "allowNonLoopbackREST": true,
  "mpcAddr": "0.0.0.0:9000",
  "dataDir": "/data",
  "peers": {
    "2": "mpc-node-2.internal:9000",
    "3": "mpc-node-3.internal:9000"
  },
  "mpcTLS": {
    "caFile": "/run/mpc-tls/ca.crt",
    "certFile": "/run/mpc-tls/node.crt",
    "keyFile": "/run/mpc-tls/node.key"
  },
  "restAuth": {
    "apiKeys": [
      {"applicationID": "wallet", "sha256": "<Base64 SHA-256 of the node's API Key>"}
    ]
  },
  "encryptorMasterPasswordEnv": "MPC_MASTER_PASSWORD"
}
```

- 为节点 2、3 分别设置 `partyId` 为 `"2"`、`"3"`，各自的 `peers` 填另外两个节点的可达 MPC 地址。增加节点时为新节点分配独立 ID、目录和证书，并更新需要和它通信的节点的 `peers`。`peers` 中省略本节点。
- 每个节点挂载自己的证书和私钥。三个节点的证书由同一 CA 签发，唯一 DNS SAN 分别是 `mpc-node-ge`、`mpc-node-gi`、`mpc-node-gm`，同时具备客户端和服务端用途。其他编号的 SAN 生成规则见 [mTLS 说明](mtls/README.md)。
- 每个节点可使用不同的 API Key。同一组 MPC 请求在参与节点上必须映射到同一个 `applicationID`。三签三建钥时，向 1、2、3 使用同一会话发送请求，`threshold` 传 `2`。

## 启动每个节点

以下为 Linux 主机上的节点 1。先准备表中的目录和文件，把私网 IP 换成当台主机的实际地址，再注入该节点的 `MPC_MASTER_PASSWORD`。其余节点按同样方式各启动一个容器。

```sh
NODE_ID=1
NODE_DIR="/srv/mpc-node/node-$NODE_ID"
MPC_BIND_IP=10.10.0.11
: "${MPC_MASTER_PASSWORD:?Set the master password for this node}"
export MPC_MASTER_PASSWORD

docker run -d --init --name "mpc-node-$NODE_ID" \
  --env MPC_MASTER_PASSWORD \
  --publish 127.0.0.1:8080:8080 \
  --publish "$MPC_BIND_IP:9000:9000" \
  --mount "type=bind,src=$NODE_DIR/config,dst=/etc/mpc-node,readonly" \
  --mount "type=bind,src=$NODE_DIR/tls,dst=/run/mpc-tls,readonly" \
  --mount "type=bind,src=$NODE_DIR/data,dst=/data" \
  mpc-node-api:1.0.0

curl --fail --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:8080/healthz
```

`9000` 是节点之间的 mTLS 端口，`8080` 是宿主机上的回环 REST 端口。SDK 从其他机器接入时，使用 HTTPS 入口转发到对应节点的 REST。多个节点在同一台主机上运行时，用 Compose，或给每个容器映射不同的宿主机端口，并在 `peers` 里填写其实际可达的地址和端口。

部署验证可以先创建一把测试密钥，再逐个重启节点，使用原 `keyID` 查询公钥。三个节点都恢复后，用同一把密钥签名并验签。

Kubernetes 或 EKS 使用同一镜像，为每个节点分别挂载配置、证书和独立的持久卷，保持相同的容器内路径。
