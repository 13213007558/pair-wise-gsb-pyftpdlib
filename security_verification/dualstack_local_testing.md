# 双栈本机测试与 PASV/EPSV 对端校验配置说明

适用版本：本仓库 `pyftpdlib`（异步 `IOLoop` 架构，`PassiveDTP` 位于
`pyftpdlib/handlers/ftp/dispatchers.py`）。

## 1. 数据通道对端校验是如何工作的

- 客户端发送 `PASV`/`EPSV` 后，服务器新建一个 `PassiveDTP` 监听器
  （随机端口或 `passive_ports` 范围内端口），并在 `IOLoop` 中注册读事件。
- TCP 连接到达时由 `Acceptor.handle_accept` 取出 `(sock, addr)`，交给
  `PassiveDTP.handle_accepted`。
- `handle_accepted` 的第一道判断就是来源校验
  （`dispatchers.py:140`）：
  - `cmd_channel.remote_ip != addr[0]` 且 `permit_foreign_addresses=False`
    （默认）时，立即 `sock.close()`，通过控制连接回复
    `425 Rejected data connection from foreign address ...`，
    **监听器本身不关闭**，合法客户端仍可继续连入；不会创建 `DTPHandler`，
    因此传输不可能开始。
  - 地址匹配时，先 `self.close()` 关闭监听 socket（一个被动监听器只接受
    一条连接），再用接入 socket 构造真实 `DTPHandler` 并赋给
    `cmd_channel.data_channel`，随后 `_on_dtp_connection()` 接管传输。
- 控制连接已断开（`not cmd_channel.connected`）时，任何到达的连接都被
  直接关闭并拆除监听器，不会产生 DTP。

## 2. IPv4 与 IPv4-mapped IPv6 的地址语义

双栈监听器（绑定 `::` 且内核未开启 `IPV6_V6ONLY`）上，IPv4 客户端在
`accept()`/`getpeername()` 中会以 IPv4-mapped IPv6 形式出现，例如
`::ffff:203.0.113.7`。其语义由 RFC 3493 §3.7 定义：该地址与
`203.0.113.7` 表示同一个 IPv4 节点。

- 正确做法是按地址身份比较，而不是按字符串比较。测试套件中的
  `addresses_same_identity()` 用标准库 `ipaddress` 归一化：
  `getattr(addr, "ipv4_mapped", None) or addr`，把 mapped 地址折叠回
  IPv4 身份后再比较。
- 依据：`ipaddress.IPv6Address.ipv4_mapped` 对 `::ffff:a.b.c.d` 返回
  对应的 `IPv4Address`；`::1` 等原生 IPv6 地址返回 `None`，不会被错误
  折叠。字符串不等绝不等于攻击——`::ffff:127.0.0.1` 与 `127.0.0.1`
  字符串不同但身份相同。
- 当前实现差异（已在测试中如实记录）：
  - 主动模式 `FTPHandler._make_eport`（`control.py:1197`）在比较前会
    剥掉 `::ffff:` 前缀，因此主动模式对 mapped 对判定正确。
  - 被动模式 `PassiveDTP.handle_accepted` 使用裸字符串比较，mapped 对
    会被**误拒**。这是 fail-closed（宁可不传也不越权），属于可用性/
    一致性缺陷，不是数据泄露漏洞；建议后续让被动模式复用同一归一化逻辑。

## 3. 本机双栈测试配置

### 3.1 无需绑定端口的可重复测试（默认、沙箱友好）

```
.venv/bin/python -m pytest security_verification/test_pasv_peer_validation.py -v
```

该套件不 `bind()` 任何 TCP 端口、不依赖 NAT 或公网地址：用
`socket.socketpair()` 造环回 fd 模拟监听器与接入连接，peer 地址通过
参数注入，可确定性地复现任意 IPv4/IPv6/mapped 来源。因此在禁止本地
端口绑定的环境（如本沙箱，`bind` 返回 EPERM）也能完整运行。

### 3.2 需要真实端口的端到端验证

`security_verification/e2e_dualstack_demo.py` 会启动真实
`FTPServer` 并走 `ftplib` 完整 PASV 流程。当环境不允许绑定时它会打印
`SKIP` 并退出。需要在下列环境运行：

- 普通开发机/CI：直接 `.venv/bin/python security_verification/e2e_dualstack_demo.py`
- 受限沙箱：需在设置中开启 `sandbox.network.allowLocalBinding: true`
  （即时生效，无需重启）；是否开启由环境管理者决定。

### 3.3 双栈监听器的推荐配置

```python
from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler

# 绑定 :: 得到单 socket 双栈监听器（依赖平台默认 IPV6_V6ONLY=0）。
# Linux/macOS 默认支持；Windows 行为不同，应分别绑定 :: 与 0.0.0.0。
server = FTPServer(("::", 0), FTPHandler)          # 或 ("0.0.0.0", 0) 纯 IPv4

FTPHandler.permit_foreign_addresses = False        # 默认值，务必保持
FTPHandler.passive_ports = range(60000, 60100)     # 固定范围，便于防火墙放通
# 位于 NAT 后时，向客户端通告公网地址（不改变对端校验逻辑）：
# FTPHandler.masquerade_address = "203.0.113.10"
```

校验平台双栈能力用 `socket.has_dualstack_ipv6()`；仓库现有
`TestIPv6MixedEnvironment` 也是在该条件满足时才运行。

## 4. 哪些部署需要额外网络隔离

应用层对端校验只能约束“谁能把数据连接接到这条 FTP 会话”，无法替代
网络层隔离。以下部署应在 pyftpdlib 之外再加隔离：

- 多租户或同机存在不可信本地进程：任何能访问被动端口的本地进程都可能
  抢先连接。应使用独立网络命名空间/容器、受限 `bind` 地址（只绑业务
  网卡而非 `0.0.0.0`/`::`），或主机防火墙限制源地址。
- 云端/共享 VPC：结合安全组与 `passive_ports` 固定范围，仅放通受信
  CIDR 到控制端口与被动端口范围。
- NAT/负载均衡后的部署：注意 `remote_ip` 是 TCP 直连对端。若前置代理
  终止了 TCP，则所有连接对端都会变成代理地址，应用层校验形同虚设；
  此场景必须由代理做源认证并在网络层限制谁能访问代理。
- 显式开启 `permit_foreign_addresses=True`（FXP/site-to-site）：见下节。

## 5. 为什么 `permit_foreign_addresses` 会改变信任边界

默认 `False` 时，信任边界是“数据通道对端必须等于控制通道对端”，即只有
发起该 FTP 会话的同一 IP 能拿到该会话的数据。监听器虽短暂开放在一个
端口上，但任何第三方抢先连入都会在 `handle_accepted` 被 `425` 拒绝，
且监听器保留给合法对端。

设为 `True` 后，这道相等性检查被整体跳过：任意地址都能建立数据通道，
该连接会被构造成 `DTPHandler` 并归属到当前控制会话，从而可读取
`RETR`/目录列表数据或参与 `STOR`。这正是 FXP（RFC 2577 明确不建议）
所需的语义——信任边界从“同一客户端 IP”扩大到“任何能路由到被动端口的
主机”。因此：

- 只有在确需 site-to-site 传输、且已用防火墙把被动端口限制到对端
  服务器地址时才开启；
- 开启后必须依赖网络隔离来弥补被移除的应用层校验；
- 测试套件 `test_permit_foreign_addresses_accepts_and_attributes_foreign`
  明确断言：开启后外来连接被接受并归属当前会话，直观呈现边界变化。
