# NodiGuard Zero-IP Origin Cloaking: Cloudflare Zero Trust Tunnel Guide

> **核心目标**：彻底从公网消除服务器的物理 IP 地址，关闭路由器所有入站端口（0 Open Ports），使服务器在全网扫描器（Shodan, Censys, Nmap）面前实现 100% 物理隐形，彻底免疫 Direct-to-Origin 绕过攻击与 DDoS。

---

## 1. 为什么传统 A 记录暴露 IP 是高危漏洞？

* **传统做法**：在 Cloudflare DNS 中添加一条 A 记录指向服务器公网 IP（如 `203.0.113.50`）。
* **黑客攻击路径**：黑客通过查询 DNS 历史解析记录（SecurityTrails, ViewDNS）或扫描公网端口，获取真实 Origin IP。获取 IP 后，黑客直接攻击 `http://203.0.113.50:8090`，**完全绕过了 Cloudflare WAF、DDoS 防护和蜜罐哨兵**！
* **Zero-IP 解决方案**：使用 **Cloudflare Tunnel (`cloudflared`)**。服务器与 Cloudflare 之间只建立**出站加密隧道**（基于 gRPC/QUIC），路由器不需要映射任何端口，DNS 记录中完全没有 IP，只有一个指向虚拟隧道的 CNAME。

---

## 2. 三步落地 Cloudflare Tunnel 物理隐身

### 第一步：在 AI 服务器上安装 `cloudflared`

* **Windows (PowerShell)**:
  ```powershell
  winget install Cloudflare.cloudflared
  # 或下载独立 exe: https://github.com/cloudflare/cloudflared/releases/latest
  ```
* **Linux (Ubuntu/Debian)**:
  ```bash
  curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  sudo dpkg -i cloudflared.deb
  ```

---

### 第二步：登录并创建加密隧道

1. **授权登录**：
   ```bash
   cloudflared tunnel login
   ```
   *浏览器会自动打开 Cloudflare 授权页面，选择您的域名 `iotservices.my` 即可完成绑定。*

2. **创建隧道**：
   ```bash
   cloudflared tunnel create paintrace-tunnel
   ```
   *该命令会生成一个专属的 `<TUNNEL_UUID>` 并保存在 `~/.cloudflared/` 目录中。*

3. **编写本地配置文件 (`~/.cloudflared/config.yml`)**：
   ```yaml
   tunnel: <TUNNEL_UUID>
   credentials-file: /root/.cloudflared/<TUNNEL_UUID>.json

   ingress:
     # 将公网域名无缝路由至本地安全网关 (8090 端口)
     - hostname: ai.iotservices.my
       service: http://localhost:8090
     # 默认阻断其他一切未授权请求
     - service: http_status:404
   ```

4. **绑定公网域名**：
   ```bash
   cloudflared tunnel route dns paintrace-tunnel ai.iotservices.my
   ```
   *Cloudflare 会自动在 DNS 中创建 CNAME：`ai.iotservices.my -> <TUNNEL_UUID>.cfargotunnel.com`，DNS 记录里 100% 不含任何物理 IP！*

---

### 第三步：启动隧道并关闭所有路由器端口

1. **将隧道注册为开机自启系统服务**：
   * Windows:
     ```powershell
     cloudflared service install
     Start-Service cloudflared
     ```
   * Linux:
     ```bash
     sudo cloudflared service install
     sudo systemctl start cloudflared
     sudo systemctl enable cloudflared
     ```

2. **【关键安全动作】彻底关闭路由器端口映射**：
   - 进入家庭/公司路由器管理后台，**删除所有针对 80、443、8090、11434 的 Port Forwarding（端口转发）规则**！
   - 防火墙入站规则设为全丢弃（Drop All Inbound Connections）。
   - **此时，全世界任何人通过公网 IP 都无法连入您的电脑，只有通过 Cloudflare 加密隧道由内向外出站握手才能访问！**

---

## 3. 验证 Zero-IP 物理隐身效果

在任何外部电脑上执行以下测试：
```bash
# 1. 验证域名解析不再有您的真实 IP，全部由 Cloudflare Anycast CDN 代理
nslookup ai.iotservices.my

# 2. 尝试全网端口扫描您的公网真实 IP
nmap -Pn -p 80,443,8090,11434 <您的真实公网IP>
# 输出应显示：All 4 scanned ports on ... are filtered (零端口响应)

# 3. 访问生产服务
curl -I https://ai.iotservices.my/health
# 返回 HTTP 200 OK，流量经过 Tunnel 直达本地 8090 网关，实现完全隐身！
```
