# 域名监控系统

监控学校域名可访问性 + SSL 证书到期，异常时自动发送钉钉告警。

## 监控列表

| 学校名称 | 域名 |
|---------|------|
| 青岛健康科技职业学院 | https://www.qdjk.edu.cn/ |
| 白银矿冶职业技术学院 | https://www.bymu.cn/ |
| 陕西国际商贸学院 | https://www.csiic.edu.cn/ |
| 西安航空职业技术学院 | https://www.xihang.com.cn/ |
| 四川轻化工大学 | https://www.suse.edu.cn/ |
| 安徽广播影视职业技术学院 | https://www.amtc.edu.cn/ |
| 马鞍山学院 | https://www.masu.edu.cn/ |
| 克孜勒苏职业技术学院 | https://www.kzvtc.edu.cn/ |
| 枣庄经济学校 | https://www.zzjjxx.com/ |
| 青岛理工大学 | https://www.qut.edu.cn/ |
| 兰州石化职业技术大学 | https://www.lzpuvt.edu.cn/ |

## 云端部署（电脑关机也能监控）

### 方式一：GitHub Actions（推荐，免费）

1. 注册 GitHub 账号：https://github.com/signup
2. 创建新仓库（Private 私有仓库即可）
3. 上传以下文件到仓库：
   - `domain_monitor.py`
   - `domain_monitor_state.json`
   - `.github/workflows/domain-monitor.yml`
   - `.gitignore`
4. GitHub Actions 会自动每 5 分钟运行一次监控
5. 在仓库的 Actions 页面可以查看运行日志

### 方式二：Gitee（国内访问更快）

1. 注册 Gitee 账号：https://gitee.com/signup
2. 创建新仓库
3. 上传同样的文件
4. 注意：Gitee 的 CI/CD（Gitee Go）需要付费，建议搭配 GitHub Actions 使用

## 本地运行（电脑开机时）

### 安装开机自启

双击运行 `install_startup.bat`，监控会在开机后自动启动。

### 卸载自启

双击运行 `uninstall_startup.bat`。

### 手动运行

```bash
python domain_monitor.py
```

## 配置说明

编辑 `domain_monitor.py` 顶部的配置区域：

- `DOMAINS` - 监控域名列表（学校名称, 域名地址）
- `DINGTALK_WEBHOOK` - 钉钉机器人 Webhook 地址
- `TIMEOUT` - 请求超时时间（默认 30 秒）
- `ALERT_COOLDOWN` - 域名异常告警冷却（默认 600 秒 = 10 分钟）
- `SSL_ALERT_COOLDOWN` - SSL 告警冷却（默认 600 秒 = 10 分钟）
- `SSL_WARNING_DAYS` - SSL 预警天数（默认 30 天）
- `SSL_CRITICAL_DAYS` - SSL 紧急告警天数（默认 7 天）

## 告警规则

- 域名正常 → 不发消息
- 域名打不开 → 立即发钉钉告警，之后每 10 分钟重复一次
- SSL 证书剩余 ≤ 30 天 → 预警
- SSL 证书剩余 ≤ 7 天 → 紧急告警
- SSL 证书已过期 → 过期告警
