# Builder Vault TSM 安全设计解读

> 目标读者：正在自研类似 MPC 密钥托管系统的人
> 依据：Blockdaemon Builder Vault 官方文档（v73.x）+ 官方 local-deployment 示例配置
> 本文中的每个结论都带标记：
>
> - **[文档]** —— 官方文档明确写了
> - **[推导]** —— 从架构和配置必然推出，文档没直说
> - **[待验证]** —— 需要反编译/实测才能确认，见第 9 节

---

## 0. 5 分钟速读

三句话抓住这套设计：

1. **密钥分片，任何单点都拿不到完整私钥**：私钥被拆成 share 分散在 n 个节点，签名时通过 MPC 协议直接算出签名，全程不重组私钥。
2. **数据库里没有一个明文机密**：连"主密钥"本身在库里都是加密的，解开它需要 config 文件里的密码 —— 密码和密文物理分离在两个系统里。
3. **每条密钥有自己的内容加密密钥**：由主密钥 + KeyID 派生，不落盘。所以删一条密钥就是删一段密文，不需要管理成千上万个 DEK。

---

## 1. 威胁模型：它到底在防谁

官方文档没有正式列出威胁模型，以下是从架构反推的。[推导]

**要保护的资产**

| 资产 | 位置 | 泄露后果 |
|---|---|---|
| 用户私钥的 share | 数据库（加密） | 累积到 t+1 个 share = 私钥泄露 |
| Master Key (MK) | 数据库（被 KEK 加密） | 泄露 = 该节点所有 share 全部解密 |
| KEK 的来源（master password） | config 文件 / 外部文件 / KMS | 泄露 = MK 泄露 |
| API Key | config 文件（**SHA-256 哈希**，非明文） | 哈希泄露无法直接用来认证；但弱 key 可被爆破 |
| 节点身份私钥 | config 文件（明文 P-256） | 泄露 = 可冒充节点加入 MPC 会话 |

**假设的攻击者能力**

| 攻击者 | 能拿到 | 设计上如何应对 |
|---|---|---|
| 拿到数据库备份 / 云盘快照 / DBA 权限 | 全部密文 + 表结构 | 没有 config 里的密码，MK 解不开 |
| 拿到单个节点的容器或主机 | 一份 config + 一个库 | 只有 1 个 share，低于阈值 |
| 中间人 / 抓包 | 节点间、SDK 间的流量 | TLS 1.3 + 公钥固定 |
| 拿到某个应用的 API Key | 一个节点的入口 | 单节点无法完成 MPC，多节点需要多方同意 |
| 拿到 config 但没拿到库 | 密码、API Key | 没有密文可解 |

**明确不在防护范围内的**（自研时也要写清楚，否则会被误认为"全能"）

- t+1 个节点 + 它们的 config + 它们的数据库同时失守
- 侧信道攻击、供应链后门
- 运维把 master password 和数据库备份放在同一个网盘里 —— 这是最常见的人为失效点

---

## 2. 密钥层级（核心）

### 2.1 四层结构

| 层 | 名称 | 如何产生 | 存在哪 | 生命周期 |
|---|---|---|---|---|
| L0 | **Master Password** | 人工设置 | **config 文件**（或外部文件/USB/命令行） | 长期，需离线备份 |
| L1 | **KEK**（Key Encryption Key） | PBKDF2(password) | **不落盘**，仅进程内存 | 每次启动重新派生 |
| L2 | **MK**（Master Key） | 节点首次启动时随机生成 | **数据库**，被 KEK 加密 | 跟随数据库 |
| L3 | **CEK**（Content Encryption Key） | HKDF(MK, info=KeyID) | **不落盘**，用完即弃 | 单条记录 |
| L4 | **Key Share 密文** | MPC 协议产出 share 后用 CEK 加密 | **数据库** | 跟随密钥 |

注意 L1/L3 都是**派生出来的**，从不持久化 —— 这是整个设计里最省事也最关键的一点：需要保管的只有"一个密码"和"一个数据库"。

### 2.2 数据流图

```mermaid
flowchart TD
    P["① config.toml<br/>EncryptorMasterPassword<br/>（或外部密钥文件）"]
    P -->|"PBKDF2<br/>迭代次数/盐 = 待验证"| KEK["② KEK（仅内存）"]

    KEK --> DEC{{"AES-GCM-256 解密"}}
    DBMK[("数据库<br/>MK 密文")] --> DEC
    DEC --> MK["③ MK 明文（仅内存）"]

    MK -->|"HKDF<br/>info = KeyID + 非机密元数据"| CEK["④ CEK（仅内存）"]

    CEK -->|"AES-GCM-256"| DBK[("数据库<br/>Key Share 密文<br/>按 KeyID 一行")]
```

**读这张图的顺序**：config 提供密码 → 派生 KEK → 用 KEK 解开库里的 MK → 用 MK 和 KeyID 派生出这条记录的 CEK → CEK 解密 share。

### 2.3 为什么这么分层（设计意图）

**① 信任根与密文物理分离** [文档]
数据库被拖走时，攻击者拿到的是"用 KEK 加密的 MK"加上"用 CEK 加密的 share"。KEK 只存在于内存和那个密码里。**这是整个方案防"拖库"的全部依据。**

**② 密码不进数据库** [推导]
没有 `users` 表、没有 password hash、没有 salt 列。好处：没有离线爆破的入口点；坏处：**密码错误和数据库损坏在现象上是同一种失败**（都表现为 MK 解不开、节点起不来），运维上必须能区分。自研时建议在 config 或启动日志里明确区分这两种错误。

**③ 每 KeyID 派生 CEK，不存 DEK** [文档]
否则你有 100 万条密钥就要管理 100 万个 DEK。派生方案让"加密一条新记录"变成纯计算，不产生新的存储对象。

**④ HKDF 的 info 里绑 KeyID** [文档]
这不是为了保密，是为了**绑定身份**：把 A 密钥的 share 密文复制到 B 的记录上，用 B 的 KeyID 派生出的 CEK 解不开（GCM tag 校验失败）。这挡住了"有数据库写权限但没密钥"的攻击者最直接的一种破坏方式 —— 密文搬家。

**⑤ 全部用 AEAD（AES-GCM-256）** [文档]
不需要单独的 HMAC 列做完整性校验，密文自带 tag。代价是：GCM 的 nonce 管理必须严格，重复 nonce 会直接摧毁机密性。**官方没公开 nonce 的构造方式，这是自研时最容易翻车的地方，也值得用 REA 看一眼。** [待验证]

### 2.4 派生式 CEK 与"信封加密"的区别

主流做法（AWS KMS、Vault 那一类）是**信封加密**：每条记录随机生成一个 DEK，用 master key 把它包裹后**存起来**。
这里换了思路：**不生成、不存，直接用 HKDF 从 MK 现场算出来**。

| | 派生式（本产品） | 信封式（KMS 主流） |
|---|---|---|
| 每条记录的密钥 | 确定性派生 | 随机生成 |
| 是否需要存储 | 不存 | 存（被包裹后） |
| 100 万条记录 | 0 个额外存储对象 | 100 万个包裹后的 DEK |
| 删除一条密钥 | 删密文即可 | 删密文 + 清理 DEK 行 |
| 逐条轮换 | 取决于 info 里是否含版本号 [待验证] | 天然支持 |
| 单点故障 | MK 泄露 = 全部失守 | master key 泄露 = 全部失守 |

**隐藏的坑**：CEK 对同一个 KeyID 是确定性的，意味着"同一条记录被反复重加密"时用的是**同一把 CEK**。所以 **nonce 必须每次加密都不同**，否则 GCM 直接失去机密性。派生式设计必须配套这条纪律，且要有对应测试。

---

## 3. 生命周期时序

### 3.1 节点启动

```mermaid
sequenceDiagram
    autonumber
    participant O as 运维
    participant N as MPC Node
    participant C as config.toml
    participant D as 数据库

    O->>N: 启动（CONFIG_FILE 指向配置）
    N->>C: 读取 EncryptorMasterPassword
    N->>N: PBKDF2 → KEK（仅内存）
    N->>D: 查询 MK 记录
    alt 首次启动（MK 不存在）
        N->>N: 生成随机 MK
        N->>D: 用 KEK 加密后写入 MK
    end
    N->>N: 用 KEK 解密得到 MK（仅内存）
    N->>N: 打开 8000（SDK 服务）和 9000（节点间 MPC）
    Note over N: 此后每条记录的加解密都用 MK 现场派生 CEK
```

要点：

- demo 里每个节点连自己的库，所以 **3 个节点 = 3 个 MK = 3 个密码**。生产里允许多个节点共享同一个库（负载均衡/容灾），此时它们共享同一个 MK 和同一个密码。[推导]
- 首次启动自动建表 + 生成 MK，所以**反编译拿不到 schema 时，跑一次就能看到**。
- config 文件本身可以被同一个加密器加密，**唯一例外是 `[Database]` 段** —— 因为需要用这段信息去实例化解密器。这是个鸡生蛋问题的标准解法，自研时可以直接抄。 [文档]

### 3.2 密钥生成 / 签名（MPC 会话）

```mermaid
sequenceDiagram
    autonumber
    participant A as SDK 操作方 A
    participant B as SDK 操作方 B
    participant N0 as Node 0
    participant N1 as Node 1
    participant N2 as Node 2

    A->>N0: KeyGen / Sign(sessionID, 消息哈希)
    B->>N1: KeyGen / Sign(sessionID, 相同消息哈希)
    Note over N0,N2: 三方建立两两 TLS 1.3（公钥固定，不依赖 CA）

    N0->>N1: 交换会话元数据
    N1->>N2: 交换会话元数据
    Note over N0,N2: 校验 sessionID 和消息哈希一致<br/>不一致 → 立即中止（防止某方被诱导签别的东西）

    N0->>N0: 用本地 share 参与 MPC 计算
    N1->>N1: 用本地 share 参与 MPC 计算
    N2->>N2: 用本地 share 参与 MPC 计算

    N0-->>A: 部分签名结果
    N1-->>B: 部分签名结果
    Note over A,B: 私钥从未被拼出来；每个节点只知道自己的 share
```

关键安全属性 [文档]：

- **每方必须各自发起**：一个节点被攻破，攻击者也不能单方面伪造签名，因为需要 t+1 个节点各自同意。
- **元数据一致性校验**：参与方对"这次要签什么"进行哈希比对，防的是"某节点以为在签交易 X，实际在签 Y"。
- 阈值 (n, t) **不是节点配置项，由 SDK 在生成密钥时指定**。典型是 (2,1)；三节点场景常用 (3,1)，即容忍任意 1 个节点被攻破。要更安全就 t=2，代价是签名必须全部 3 个节点在线。
- 本地 demo 里一个程序同时驱动 3 个节点（`client-0/1/2`）；生产里这三方往往分属不同组织，各拿各的 API Key。

---

## 4. 威胁矩阵：拿到什么能干什么

这是最值得抄进自己设计文档的一张表。

| 攻击者拿到 | 缺什么 | 实际后果 |
|---|---|---|
| 数据库备份 | config 里的密码 | MK 解不开 → 所有 share 是 AES-GCM 密文，**完全无用** |
| 一个节点的 config | 数据库 | 只有密码和 API Key，**没有密文可解** |
| 一个节点的 config + 数据库 | 其他节点的 share | 得到该节点的 share 明文；**低于阈值，无法签名** |
| t+1 个节点的 config + 数据库 | 无 | 密钥泄露（这是设计上承认的边界） |
| 一个应用的 API Key | 其他节点的 API Key | 只能驱动 1 个节点，MPC 会话建立不起来 |
| 网络流量 | 无 | TLS 1.3 + 公钥固定，**抓包无用** |
| 数据库写权限 | 密码 | 只能破坏（删数据/改密文导致校验失败），**不能读取** |

注意最后一行 —— 这解释了两件事：
1. 为什么 DB 账号权限可以给到 DDL（节点要自己建表/迁移），因为"能写"本来就等于"能破坏"，给不给权限不改变机密性。
2. 为什么"密文搬家"防护是必要的。

---

## 5. 认证与通道

### 5.1 SDK → 节点

三种方式，config 里选一种 [文档]：

| 方式 | 凭据放哪 | 特点 |
|---|---|---|
| **API Key** | config 存 **base64(SHA-256(实际 key))** + ApplicationID | 用 key 换 JWT（`TokenLifetime` 可配，例子里 5m）。demo 用的就是这种 |
| **双向 TLS** | 客户端证书 | ApplicationID 取 DN 的哈希，支持 OCSP 吊销 |
| **OIDC** | 第三方 IdP（Google/Auth0） | ApplicationID 取 OIDC 标识 |

关于 **API Key 的存储方式**（官方文档这段很容易读错）：

config 里那一行**不是明文 key，而是 `base64(SHA-256(实际 key))`**。我用 demo 配置验证过：

```text
"apikey0"  --SHA-256-->  IntV2sEZRwwd2F+UkDLC7zmFhwvpxAwb0eQKwdEnSZU=
```

- 好处：config 泄露 **不等于** 节点入口泄露 —— 拿到哈希没法直接拿去认证。
- 还支持更慢的哈希：MD5 / SHA256 / SHA512 / bcrypt / Argon2i / Argon2id（crypt 格式）。
- 注意：**SHA-256 是无盐的**，所以 key 本身的熵决定一切。demo 里的 `apikey0` 秒破；生产必须用长随机值，或者换成 bcrypt/argon2id。

### 5.2 应用隔离（多租户）

每个节点可以配置多个 **application**，application 就是 key 的命名空间。官方原话：**"登录到同一个 application 的 SDK 可以访问同一批 key。"**

三种认证方式最终都会解析出**唯一一个 ApplicationID**：

| 认证方式 | application 怎么定 |
|---|---|
| API Key | `[[Authentication.APIKeys]]` 里的 `ApplicationID` 字段 |
| mTLS | 证书属性匹配 `[[TLSUserAuthentication.Applications.Filters]]`（CN / O / OU / serialNumber…） |
| OIDC | 固定值，或从 token 的某个 claim 取：`ApplicationID = "$CLAIM:claim"` |

application 不存在时**首次登录自动创建**，不需要预先 provisioning。

**"看不到"是怎么做到的** [推导]：

```text
API Key ──┐
证书属性 ──┼──► 认证 ──► ApplicationID（唯一确定）
OIDC claim ┘                    │
                                ├─► 签发 JWT（含 appID，TokenLifetime 可配）
                                └─► 每条 key 记录带 application_id
                                          │
                                   所有查询 WHERE application_id = ?
                                          │
                                   不匹配 → 403
```

**403 是刻意模糊的**：官方排障文档写的是 "The key does not exist or belong to a different user" —— "不存在"和"不属于你"返回同一个错误，防止攻击者用 KeyID 枚举别人的密钥。

**关键认知：这是授权隔离，不是密码学隔离。**

同一个数据库、同一个 MK、同一套加密。拖库 + 拿到密码 = 所有 application 的 share 都暴露。application 边界只由节点进程的代码逻辑保证，数据库里没有第二道门。

想要真正的密码学隔离，就得把 ApplicationID 放进 CEK 派生的 info 里 —— 代价是 application 改名/迁移会变得极其麻烦。官方是否这么做属于待验证项。 [待验证]

### 5.3 节点 ↔ 节点

- **两两 TLS 1.3**，用 config 里的私钥做服务端身份，用其他节点的公钥做**固定（pinning）**，不依赖任何 CA [文档]。
- demo 配置里 `?symmetricConnection=true` 的含义（双向用同一套连接参数）**官方没解释**，需实测 [待验证]。
- 如果用消息代理（broker）模式：broker 只终结 TLS，节点在其上再叠一层端到端加密，broker 不是可信方 [文档]。这个设计对"多组织部署"很关键。

### 5.4 节点身份密钥

我从 demo config 里解出了实际结构：

```
-----BEGIN EC PRIVATE KEY-----   (SEC1, 32 字节标量)
曲线 OID: 1.2.840.10045.3.1.7  → prime256v1 (P-256)
公钥:     SubjectPublicKeyInfo, id-ecPublicKey + prime256v1, 非压缩点 0x04||X||Y
```

API Key 解码后是 **32 字节**（256 bit）随机值，base64 编码后 44 字符。

---

## 6. 密码学原语清单

| 用途 | 算法 / 参数 | 证据等级 |
|---|---|---|
| 密码 → KEK | PBKDF2（RFC 8018）。**迭代次数、盐来源、盐长度均未公开** | [文档] / [待验证] |
| MK 封装 | AES-GCM-256 | [文档]（"all encryptions"） |
| CEK 派生 | HKDF，input=MK，info=KeyID + 非机密数据 | [文档] |
| 记录加密 | AES-GCM-256 | [文档] |
| 节点身份 | ECDSA P-256 | [实测解码] |
| 节点间传输 | TLS 1.3，双向，公钥固定 | [文档] |
| 随机源 | Go `crypto/rand` → Linux `getrandom(2)` | [文档] |
| 阈值 ECDSA | DKLS23 协议（配置节 `[DKLS23.Features]`） | [文档] |
| 阈值 ECDSA（另一套） | SEPD19S（feature flags 与 DKLS23 完全一致） | [推导] |
| 阈值 RSA | ADN06（SignPKCS1v15 / SignPSS / Decrypt） | [推导自 feature flags] |
| 对称密钥 / HMAC | MRZ15（AES-CTR/CBC/GCM/CMAC，HMAC-SHA256/512） | [推导自 feature flags] |

**从配置能读出的产品取向**：节点把"支持哪些密码学协议"做成了配置开关（`[DKLS23.Features]` 一大串 true/false），而不是编译期决定。好处是可以按租户/环境裁剪攻击面；代价是配置错误会静默地让某些功能不可用（表现为 404，见官方 Troubleshooting 的 `404 page not found`）。

---

## 7. 运维安全边界（这部分决定了系统会不会真的可用）

### 7.1 备份：缺一不可

```
可用备份 = 数据库备份  +  config 里的 EncryptorMasterPassword
```

**只有数据库备份 = 永久数据丢失。** 因为 MK 是被密码派生的 KEK 加密的，没有密码，连厂商也解不开。这是本设计里最容易被低估的运维风险。 [推导]

自研建议：把"密码托管流程"当成一等公民设计（哪些人持有、存哪里、如何轮换、轮换时如何批量重加密），而不是写一句"请妥善保管"。

### 7.2 数据库迁移 = 全量重加密

升级节点版本时，migration 会把**所有密钥重新加密一遍**，密钥越多耗时越长；迁移期间**所有共享该库的节点必须停机**。 [文档]

这暴露了一个设计事实：加密密钥的轮换粒度是"全库"，不是"逐条"。如果自研，可以考虑加版本号字段做惰性重加密（读到时才升级），避免每次升级都停服。

### 7.3 导出控制

`ExportWhiteList` 限定允许导出时使用的 wrapping key。demo 里是 `["*"]`（全放开，仅测试用）。生产应该按调用方证书/密钥白名单收敛。 [文档]

### 7.4 审计

有独立的 audit 服务，日志带签名，可离线验签。 [文档] 这属于合规能力，与密钥机密性正交，但说明厂商把"事后追责"当成独立组件而不是塞进主库。

### 7.5 数据库账号权限

要求：`SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES` [文档]

看起来很大，但结合第 4 节：**能写库的攻击者本来就只能破坏、不能读取**，所以给 DDL 不额外降低机密性。真正该收敛的是"谁能拿到这个库"。如果要更严格，可以拆成两个账号：迁移用 DDL 账号（平时禁用）、运行时用 DML 账号。

---

## 8. 给自研实现的 10 条检查表

按重要性排序：

1. **信任根必须和密文分离**。密码在文件/KMS，密文在数据库。两者同时在一个人手里，方案就退化成"普通加密数据库"。
2. **不要发明密钥层级**。KEK → MK → CEK 这三层各自解决一个问题：密码可以换、MK 可以随库走、CEK 可以按记录派生。少一层就多一个运维难题。
3. **AEAD 的 AAD 要绑定资源 ID**。否则有库写权限的人可以搬密文。GCM 的 tag 校验也能挡住，但 AAD 是显式意图，更清晰。
4. **nonce 管理写进设计文档**。确定性派生（如 HKDF(MK, KeyID||version) 作为 nonce）比随机 nonce 更容易审计。**不要用计数器落库**。
5. **密码派生优先 Argon2id**，PBKDF2 只有在需要 FIPS 兼容时才用。文档没说迭代次数，自研时把它做成可配置并写进版本元数据，否则将来无法升级。
6. **明确区分"密码错误"与"数据损坏"**。两者的表现都是解密失败，但处置方式完全不同。
7. **密钥删除 = 删密文 + 考虑安全擦除**。不要用"逻辑删除"标志位，因为密文还在。
8. **备份方案必须包含密码**，并且"没有密码无法恢复"要在 UI/文档里显式说明至少两次。
9. **阈值和可用性一起设计**。(3,1) 容忍挂 1 个节点；(3,2) 容忍挂 0 个。签名可用性 = n - t 个节点在线。这个公式要写进 SLA。
10. **会话元数据一致性校验**（sessionID + 消息哈希）不要省。它防的是最阴险的一类攻击：让不同参与方对"签什么"产生分歧。

---

## 9. 未证实项（留着用 REA 验证）

按价值排序，这些是文档没写、但直接影响实现理解的点：

| # | 待验证 | 为什么重要 | 怎么验 |
|---|---|---|---|
| 1 | PBKDF2 的迭代次数、盐来源/长度 | 决定离线爆破成本，也决定能不能做参数升级 | 二进制里搜 `pbkdf2.Key` 调用点，看常量 |
| 2 | GCM nonce 的构造方式 | 重复 nonce = 机密性崩溃 | 搜 `NewGCM` 附近的 seal 逻辑 |
| 3 | 表结构（表名、列、索引） | 直接对标自研 schema | 启动一次后 `\dt` / `pg_dump --schema-only` |
| 4 | MK 是否带 AAD、AAD 内容 | 决定密文迁移的可行性 | 同上 |
| 5 | JWT 的签名算法、有效期、刷新机制 | SDK 接入体验与安全性 | 读 SDK 源码（公开 repo）或抓包 |
| 6 | `symmetricConnection=true` 的确切语义 | 节点间信道模型 | 抓包 + 配置对照 |
| 7 | share 的序列化格式（是否含版本号） | 决定能否做惰性重加密 | 看二进制里的结构体/strings |
| 8 | config 加密的实现细节（算法、KDF 复用） | 自研时的直接参考 | 搜 "encrypt config" 相关字符串 |

**最省力的一招**：Go 二进制默认保留符号和字符串常量，`strings | grep -i "create table"` 大概率直接给出完整 schema，比反编译快一个数量级。

---

## 10. 术语表

| 术语 | 含义 |
|---|---|
| **MPC** | 安全多方计算。多方各持一份数据片段，共同算出结果，但都不窥见他人片段 |
| **Threshold (n, t)** | n 份分片、容忍 t 份泄露。签名需要 t+1 份参与 |
| **Share** | 私钥的分片。单独一份不含完整密钥的信息 |
| **KEK** | Key Encryption Key，用来加密"密钥的密钥" |
| **MK** | Master Key，节点级主密钥，加密所有 CEK 的源头 |
| **CEK** | Content Encryption Key，单条记录的内容密钥，派生而非存储 |
| **Wrapping Key** | 导出的分片在离开系统时用于包裹（加密）的公钥 |
| **TSM** | Trusted Security Module，本产品的定位（软件实现的、分布式的"HSM"） |

---

## 附：证据来源

- Security Overview: https://builder-vault-tsm.docs.blockdaemon.com/docs/security-overview
- Database 配置: https://builder-vault-tsm.docs.blockdaemon.com/docs/database-configuration
- Database Migration: https://builder-vault-tsm.docs.blockdaemon.com/docs/database-migration
- Troubleshooting: https://builder-vault-tsm.docs.blockdaemon.com/docs/troubleshooting
- Local Deployment: https://builder-vault-tsm.docs.blockdaemon.com/docs/getting-started-local-deployment
- 节点身份密钥与 API Key 的字节结构：本文作者对 demo config 直接解码验证
