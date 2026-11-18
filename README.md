# pairwise-session-guard

后台会话改成多标签页共用后，会话固定和 Cookie 问题就藏不住了：登录前后 session id 不轮换，攻击者预置的 id 登录后继续有效；Cookie 没设 HttpOnly/Secure，XSS 能直接读；SameSite 设成 None 还带凭证；Domain 写成父域，子域应用都能拿到；Path 设成 `/`，所有接口共享；空闲超时和绝对超时都没有；并发登录不限制，旧设备一直不掉线；退出只清前端，服务端 session 还在；session id 用自增或时间戳，能枚举；Cookie 前缀没有用 `__Host-`。security/session_guard.py 是核心，tests/test_session_guard.py 15个红。要修的是：登录轮换；Cookie 安全属性；SameSite 策略；Domain/Path 收紧；双超时；并发上限；退出吊销；高熵 id；`__Host-` 前缀；旧会话失效。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
