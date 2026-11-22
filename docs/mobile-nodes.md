# 手机节点本地模拟

当前实现是一台桌面电脑上的三个独立进程：两个服务端节点和一个通过 CLI 启动的嵌入式“手机”节点。三方使用现有 CMP / FROST 协议建钥、生成预签名和签名，手机分片实际保存在运行 CLI 的这台电脑上。这里没有 Android APK，也不需要下载 Android SDK、NDK 或 gomobile。

手机不监听 REST / MPC 端口，只向两个服务端 MPC HTTPS 地址发起连接，使用节点证书进行双向 TLS 认证，并使用应用 API Key 发起控制请求和轮询消息。两个服务端复用各自的 MPC 监听器和内存消息队列；服务端重启、会话超时或网络中断可能使进行中的操作失败，失败后不会自动重试签名。此版本不含离线消息持久化。

## 启动与冒烟测试

在 `mpc-node-api` 仓库根目录运行，需要 Go 及现有的 `certs/mpc-dev` 证书、`certs/mpc-master-passwords.ps1` 服务端密码文件。脚本复用这些文件，不修改证书。首次运行会随机生成手机主密码，写入 Git 忽略的 `certs/mobile-dev-passwords.ps1`；后续启动复用同一密码。密码和原始 API Key 不会打印。

```powershell
.\scripts\dev-mobile.ps1 -Smoke
```

脚本只启动节点 2、3，分别为 ECDSA 和 FROST 建钥，再用另一个 CLI 进程重新打开手机数据库并签名。随后各生成两份预签名，用独立 CLI 进程消费其中一份，检查公钥一致、重复消费失败及服务端剩余数量。嵌入式客户端在返回完整签名之前完成合并和验签。每种算法保留一份未消费的预签名供查看数据库。结束时脚本仅停止自己启动的两个服务端进程，保留数据供再次使用。二进制和日志位于 Git 忽略的 `data/mobile-demo/bin`、`data/mobile-demo/logs`。

只启动服务端并保持运行：

```powershell
.\scripts\dev-mobile.ps1
```

在第二个 PowerShell 终端进入同一仓库根目录，加载手机密码和测试 API Key，再执行：

```powershell
. .\certs\mobile-dev-passwords.ps1
$keys = Get-Content -Raw configs/dev-api-keys.json | ConvertFrom-Json
$env:MPC_NODE_API_KEY_2 = $keys.'2'.'wallet-a'
$env:MPC_NODE_API_KEY_3 = $keys.'3'.'wallet-a'

go run ./cmd/mobile-sim keygen -config configs/mobile/mobile.json -algorithm frost -threshold 2 -key-id phone-frost-1
go run ./cmd/mobile-sim sign -config configs/mobile/mobile.json -algorithm frost -key-id phone-frost-1 -message hello

go run ./cmd/mobile-sim keygen -config configs/mobile/mobile.json -algorithm ecdsa -threshold 2 -key-id phone-ecdsa-1
go run ./cmd/mobile-sim sign -config configs/mobile/mobile.json -algorithm ecdsa -key-id phone-ecdsa-1 -message hello
```

`keygen` 省略 `-key-id` 会生成新 ID。请保留返回的 `keyID` 供签名使用。同一应用下已有的 ID 不应重复建钥。协议阈值为 `t`，至少需要 `t+1` 个签名参与者；本演示默认 `-threshold 2`，使用全部三方。当前 CLI 每次操作使用配置中的所有参与方。

成功时 stdout 仅输出公开 JSON：`keyID`、`curve`、Base64 `publicKey`，签名结果另含 Base64 `signature`。错误写入 stderr，返回非零退出码。`-message` 为 UTF-8 原文；ECDSA 在客户端对原文做一次 SHA-256 后签名，FROST-Ed25519 直接签原文字节。请勿先自行对 ECDSA 消息散列后再传入本接口。

## 生成和消费预签名

服务端启动、环境变量加载后，可使用前面创建的密钥：

```powershell
$batch = go run ./cmd/mobile-sim presiggen -config configs/mobile/mobile.json -algorithm frost -key-id phone-frost-1 -count 2 | ConvertFrom-Json
go run ./cmd/mobile-sim signwithpresig -config configs/mobile/mobile.json -algorithm frost -key-id phone-frost-1 -presignature-id $batch.ids[0] -message hello

$batch = go run ./cmd/mobile-sim presiggen -config configs/mobile/mobile.json -algorithm ecdsa -key-id phone-ecdsa-1 -count 2 | ConvertFrom-Json
go run ./cmd/mobile-sim signwithpresig -config configs/mobile/mobile.json -algorithm ecdsa -key-id phone-ecdsa-1 -presignature-id $batch.ids[0] -message hello
```

`presiggen` 的 `-count` 为 1–8，默认 1。手机协调当前配置中的全部参与方执行预计算，逐项轮询批次消息，确认各节点返回相同的有序 `{"ids":["..."]}`。每个节点仅保存自己的预签名分片，手机数据库中的 `ecdsa_presignatures`、`frost_presignatures` 同样使用 MK 派生独立 CEK 加密，`share_format=1`。

`signwithpresig` 必须明确指定一个未消费的 ID，不会自动选取或重试。手机先消费本地记录，再通过 HTTPS 并行向服务端请求同一个 ID 的部分签名；此阶段不启动 MPC 会话或轮询，服务端之间也无需为这次签名交换消息。手机校验参与方、ID、公钥和承诺，合并后验签，成功返回与 `sign` 相同的完整签名 JSON，另含 `presignatureId`。ECDSA 返回 DER 签名，FROST 返回标准 64 字节 Ed25519 签名。

预签名生成和消费应使用相同的参与方集合；门限允许时可为缩减后的集合重新生成一批，合并仍按密钥原始参与方编号校验。当前手机接口与原有 `Sign` 一样只签根密钥，不接收派生路径。

手机可在预计算后关闭，下次使用原密码重新打开数据库再消费。每个 ID 只能使用一次；一部分节点已消费后发生断网、超时或合并失败，应弃用该 ID，换新的 ID，不恢复已消费记录，也不自动重试。恢复旧数据库备份仍需清空预签名，防止重复使用。

## 配置和实际存储位置

相对路径均按 JSON 配置所在目录解析。手机配置 `configs/mobile/mobile.json` 的 `dataDir` 为 `../../data/mobile-sim`，因此默认实际数据库为 `<仓库根目录>\data\mobile-sim\node.sqlite`；脚本启动时会打印绝对路径。

| 参与方 | REST | MPC HTTPS | 实际数据库（相对仓库根目录） |
|---|---|---|---|
| 手机 / party 1 | 无 | 无监听器 | `data/mobile-sim/node.sqlite` |
| 服务端 / party 2 | `127.0.0.1:8182` | `127.0.0.1:9182` | `data/mobile-demo/node-2/node.sqlite` |
| 服务端 / party 3 | `127.0.0.1:8183` | `127.0.0.1:9183` | `data/mobile-demo/node-3/node.sqlite` |

手机配置不含 `restAddr`、`mpcAddr`、`restAuth` 或 `mobilePeers`。`serverAPIKeyEnvs` 只保存凭据的环境变量名。CLI 解析路径后，把实际 API Key 在内存中交给 `mobile.New`，不写回配置文件。服务端的 `mobilePeers` 将 party 1 授权给 `mobile-demo` 应用；静态 `peers` 仅包含另一个服务端。此演示复用 `configs/dev-api-keys.json` 中 `wallet-a` 的测试凭据摘要，但绑定到独立的 `mobile-demo` 应用。

数据库为 SQLite，敏感 MPC 分片沿用现有 CEK / MK 加密机制；并非整份 SQLite 文件加密，公开元数据仍可见。主密码用于解锁数据库中的加密 MK，重启必须使用原密码。手机密码文件只是本地演示的秘密保存方式，应保护该文件及操作系统账户权限。它不是 Android Keystore 集成。不要删除数据库、替换密码或复用原三节点的数据目录来“重置”一个已有手机节点；这些行为可能让分片无法再解密。

原三节点联调的 8081–8083 / 9081–9083 和 `data/node-*` 与此演示隔离。本流程不启用密钥导出、恢复或 wrapping key。

## 嵌入接口与未来 Android 接入

公开 Go 包 `github.com/C18519898242/mpc-node-api/mobile` 提供：

```go
client, err := mobile.New(configJSON, absoluteDataDir, masterPassword)
// 检查 err；配置中的 TLS 文件路径也应先由调用方解析。
defer client.Close()
createdJSON, err := client.CreateKey("frost", 2, "phone-key-1")
signedJSON, err := client.Sign("frost", "phone-key-1", []byte("hello"))
batchJSON, err := client.GeneratePresignatures("frost", "phone-key-1", 2)
// 从 batchJSON 的 ids 中选取一个未消费的 ID。
presignedJSON, err := client.SignWithPresignature("frost", "phone-key-1", presignatureID, []byte("hello"))
```

Android 应用未来可传入 `getFilesDir()/mpc`，使数据库位于应用私有目录下的 `mpc/node.sqlite`，并使用 Android Keystore 保护用于解锁 MK 的主密码。这些 Android 文件路径、证书置备、Keystore 调用、UI 和绑定构建均未实现。应用私有存储会随卸载而删除；没有其他恢复安排时，卸载可能丢失手机分片。参见 Android 官方的[应用专属存储说明](https://developer.android.com/training/data-storage/app-specific)及 [Android Keystore 说明](https://developer.android.com/privacy-and-security/keystore)。
