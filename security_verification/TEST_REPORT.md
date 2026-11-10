# PASV/EPSV 数据通道对端校验测试报告

- 日期：2026-11-10
- 对象：本仓库 `pyftpdlib`，核心代码
  `pyftpdlib/handlers/ftp/dispatchers.py`（`PassiveDTP`）、
  `pyftpdlib/handlers/ftp/data.py`（`DTPHandler`）、
  `pyftpdlib/handlers/ftp/control.py`（`FTPHandler`）
- 测试方式：环回 `socket.socketpair` + 可注入 peer 地址，驱动真实
  `PassiveDTP.handle_accepted` 与真实 `DTPHandler`；不绑定 TCP 端口、
  不依赖公网/NAT，可在禁止本地绑定的沙箱内重复运行。
- 复现命令：
  `.venv/bin/python -m pytest security_verification/test_pasv_peer_validation.py -v`
- 结果：**17 passed**。

## 1. 被测机制

`PASV`/`EPSV` → `FTPHandler._make_epasv` 新建 `PassiveDTP` 监听器并注册到
`IOLoop`；连接到达 → `Acceptor.handle_accept` →
`PassiveDTP.handle_accepted(sock, addr)`：

1. 控制连接已断开则直接关闭，不产生 DTP；
2. `remote_ip != addr[0]` 且 `permit_foreign_addresses=False` 时，关闭
   接入 socket、回 `425 ... foreign address`，保留监听器，不创建 DTP；
3. 校验通过则关闭监听器（只接一条），用接入 socket 构造 `DTPHandler`
   赋给 `data_channel`，`_on_dtp_connection` 接管传输。

## 2. 每个被接受连接的控制会话归属

下表逐条记录每次接入最终是否形成 DTP 以及归属哪条控制会话。

| 用例 | 控制会话 remote_ip | 数据连接 peer | 是否形成 DTP | 最终归属 | 结论 |
|---|---|---|---|---|---|
| C1 外来 IPv4 | `203.0.113.7` | `198.51.100.66` | 否 | 无 | `425` 拒绝，未开始传输 |
| C2 外来 IPv6 | `2001:db8::1` | `2001:db8::beef` | 否 | 无 | `425` 拒绝 |
| C3 合法同对端 IPv4 | `203.0.113.7` | `203.0.113.7` | 是 `DTPHandler` | `alice` | 接受，归属本会话 |
| C4 mapped 同身份 | `::ffff:203.0.113.7` | `203.0.113.7` | 否 | 无 | 当前字符串比较误拒（见 §4） |
| C5 mapped 不同身份 | `::ffff:203.0.113.7` | `198.51.100.66` | 否 | 无 | 正确拒绝 |
| C6 开启 foreign 许可 | `203.0.113.7` | `198.51.100.66` | 是 `DTPHandler` | `bob` | 外来连接被接受并归属本会话（信任边界外扩） |
| C7a 控制连接正常 | `203.0.113.7` | `203.0.113.7` | 是 `DTPHandler` | `carol` | 接受，归属本会话 |
| C7b 控制连接已关闭 | `203.0.113.7` | `203.0.113.7` | 否 | 无 | 关闭且不接管 |

关键安全结论：除 C6（显式关闭校验）外，**唯一形成 DTP 的外来连接 C3/C7a
都精确归属发起该控制会话的同一身份**；所有被拒连接均无 `DTPHandler`、
无任何归属，证明抢连被动端口拿不到其他用户的文件。

## 3. 需求项与测试映射

- 来源不匹配不能开始传输：`test_foreign_ipv4_peer_is_rejected_and_never_attached`、
  `test_foreign_ipv6_peer_is_rejected`（断言无 DTP、无归属、回 425、对端收 EOF）。
- 被拒绝后合法对端仍能连接：`test_legitimate_peer_still_accepted_after_rejection`
  （先拒外来，再接受同对端，并实际收到 `ownership-proof` 数据，归属 `user-1`）。
- 重新发起被动模式后旧监听器不能接管：`test_new_pasv_replaces_old_listener`
  （旧监听器 `close()` 后 socket 关闭、fd 移出 `socket_map`，新连接只归新监听器）。
- 切换用户/会话隔离：`test_two_sessions_keep_separate_listeners_and_ownership`
  （Bob 连 Alice 监听器被拒；各自合法连接分别归属 `alice`/`bob`）。
- 关闭控制连接后不接管：`test_closed_control_connection_refuses_takeover`。
- mapped 地址按地址语义而非字符串判定：
  `test_address_identity_semantics`（8 组参数化）+
  `test_mapped_ipv6_peer_*`，使用 `ipaddress` 的 `ipv4_mapped` 归一化，
  依据 RFC 3493 §3.7。
- `permit_foreign_addresses` 的边界变化：
  `test_permit_foreign_addresses_accepts_and_attributes_foreign`。

## 4. 发现的问题与风险评级

1. 被动模式 mapped 地址误拒（一致性/可用性缺陷，**非越权**）。
   - 现象：双栈监听器上控制连接对端为 `::ffff:203.0.113.7`，同一 IPv4
     客户端的数据连接 `addr[0]` 为 `203.0.113.7`，`dispatchers.py:140`
     的裸字符串不等导致 `425` 拒绝（C4）。
   - 对照：主动模式 `control.py:1197` 比较前已剥 `::ffff:` 前缀，判定正确。
   - 评级：fail-closed——错误方向是拒绝服务而非放行，不会泄露文件；但会
     让双栈+IPv4 客户端的合法被动传输失败。建议让被动路径复用
     `ipaddress` 归一化（测试中 `addresses_same_identity` 已给出可直接
     采用的实现），并保持“不同身份仍拒绝”（C5）。
2. 未发现任何可让外来对端在默认配置下取得他人会话 DTP 的路径。
3. `permit_foreign_addresses=True` 会移除上述相等性校验，属预期但高危，
   部署要求见 `dualstack_local_testing.md` §4–§5。

## 5. 环境限制说明

本沙箱禁止本地 TCP 绑定（`bind` 返回 `EPERM`，仓库
`tests/__init__.py` 的能力探测因此把网络功能测试标记为 skip）。
真实端到端脚本 `security_verification/e2e_dualstack_demo.py` 在该环境
打印 `SKIP`；需在允许绑定的 CI/开发机，或开启
`sandbox.network.allowLocalBinding: true` 后运行。核心安全逻辑已由
不依赖绑定的 socketpair 套件完整覆盖。
