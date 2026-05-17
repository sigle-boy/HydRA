## 项目结构

- `attester`：生成设备信息 `dev_infor`，发送给 `verifier`；收到 `dev_res` 后生成 `reply` 和 `sig`，发送给 `relying-party`。
- `verifier`：持续监听 attester 的连接，接收 `dev_infor`，生成 `dev_res`、`root` 和 verifier 公钥；把 `dev_res + public_context` 返回给 attester，同时把公开的 `root + verifier_pk` 发布给 relying-party。
- `relying-party`：持续监听，接收 verifier 发布的公开上下文，也接收 attester 发来的证据并执行最终验证。

默认地址：

- verifier：`127.0.0.1:7001`
- relying-party：`127.0.0.1:7002`

## 推荐启动方式：打开 3 个 cmd

### cmd 1：启动 relying-party

```bash
cargo run -p relying-party
```

### cmd 2：启动 verifier

```bash
cargo run -p verifier
```

### cmd 3：启动 attester，触发一次完整流程

```bash
cargo run -p attester
```

运行后流程是：

```text
attester -> verifier: dev_infor
verifier -> attester: dev_res + public_context
verifier -> relying-party: public_context(root + verifier_pk)
attester -> relying-party: reply + sig
relying-party: rely_party_verification(&root, &reply, sig, &verifier_pk)
```

`verifier` 和 `relying-party` 都是持续监听的。你可以多次执行 `cargo run -p attester`，每次都会重新发起一轮认证流程。

## 自定义端口

### relying-party

```bash
cargo run -p relying-party -- 127.0.0.1:8002
```

### verifier

第一个参数是 verifier 自己监听的地址，第二个参数是 relying-party 地址：

```bash
cargo run -p verifier -- 127.0.0.1:8001 127.0.0.1:8002
```

### attester

第一个参数是 verifier 地址，第二个参数是 relying-party 地址：

```bash
cargo run -p attester -- 127.0.0.1:8001 127.0.0.1:8002
```

## 通信格式

TCP 采用简单长度前缀帧：

```text
8 字节 big-endian u64 消息长度 + 消息体
```

其中发给 relying-party 的消息体前 4 字节用于区分消息类型：

- `PUBC`：verifier 发布的公开上下文 `PublicContext`
- `EVID`：attester 发送的证据消息 `EvidenceReply + Signature`

