#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
域名监控脚本 - 检查域名可访问性 + SSL证书到期检测，异常时推送钉钉告警消息
支持：多域名监控、告警冷却（防轰炸）、状态持久化
仅使用 Python 标准库，无需安装第三方依赖
规则：域名打不开或SSL证书异常时发钉钉告警，正常时不发任何消息
"""

import json
import time
import hmac
import hashlib
import base64
import socket
import ssl
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.parse import quote_plus, urlparse
from urllib.error import HTTPError, URLError

# ==================== 配置区域 ====================

# 要监控的域名列表（学校名称, 域名地址）
DOMAINS = [
    ("青岛健康科技职业学院", "https://www.qdjk.edu.cn/"),
    ("白银矿冶职业技术学院", "https://www.bymu.cn/"),
    ("陕西国际商贸学院", "https://www.csiic.edu.cn/"),
    ("西安航空职业技术学院", "https://www.xihang.com.cn/"),
    ("四川轻化工大学", "https://www.suse.edu.cn/"),
    ("安徽广播影视职业技术学院", "https://www.amtc.edu.cn/"),
    ("马鞍山学院", "https://www.masu.edu.cn/"),
    ("克孜勒苏职业技术学院", "https://www.kzvtc.edu.cn/"),
    ("枣庄经济学校", "https://www.zzjjxx.com/"),
    ("青岛理工大学", "https://www.qut.edu.cn/"),
    ("兰州石化职业技术大学", "https://www.lzpuvt.edu.cn/"),
]

# 钉钉自定义机器人 Webhook URL
# 优先级：环境变量 DINGTALK_WEBHOOK > local_webhook.py > 空
# GitHub Actions 通过 Secrets 设置环境变量；本地通过 local_webhook.py 配置
DINGTALK_WEBHOOK = os.environ.get("DINGTALK_WEBHOOK", "")
if not DINGTALK_WEBHOOK:
    try:
        from local_webhook import DINGTALK_WEBHOOK
    except ImportError:
        pass

# 钉钉加签密钥（安全设置选"加签"时填写，选"关键词"则留空）
DINGTALK_SECRET = ""

# 请求超时时间（秒）—— 海外服务器访问国内站点较慢，设90秒避免误报
TIMEOUT = 90

# 域名不可访问 - 告警冷却时间（秒）
ALERT_COOLDOWN = 600  # 10 分钟

# SSL 证书告警配置
SSL_WARNING_DAYS = 30    # 剩余天数 <= 30 时预警
SSL_CRITICAL_DAYS = 7    # 剩余天数 <= 7 时紧急告警
SSL_ALERT_COOLDOWN = 600  # SSL 告警冷却 10 分钟

# ==================== 配置区域结束 ====================

# 状态文件路径（与脚本同目录）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, "domain_monitor_state.json")


def check_domain(url, retries=2):
    """
    检查域名是否可访问（含重试机制）
    返回: (is_ok: bool, status_code: int, error_msg: str)
    """
    last_error = ""
    last_status = 0
    for attempt in range(retries):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = Request(url, method='GET', headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 DomainMonitor/1.0'
            })
            resp = urlopen(req, timeout=TIMEOUT, context=ctx)
            return True, resp.getcode(), ""
        except HTTPError as e:
            status = e.getcode()
            last_status = status
            if status >= 500:
                last_error = "服务器内部错误 (HTTP %d)" % status
                # 5xx 错误重试
                if attempt < retries - 1:
                    time.sleep(3)
                    continue
                return False, status, last_error
            elif status >= 400:
                return True, status, "HTTP %d" % status
            return False, status, str(e)
        except URLError as e:
            reason = str(e.reason) if hasattr(e, 'reason') else str(e)
            last_error = "连接失败: %s" % reason
            last_status = 0
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return False, 0, last_error
        except socket.timeout:
            last_error = "请求超时 (%d秒无响应)" % TIMEOUT
            last_status = 0
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return False, 0, last_error
        except socket.gaierror as e:
            return False, 0, "DNS解析失败: %s" % str(e)
        except ssl.SSLError as e:
            return False, 0, "SSL证书错误: %s" % str(e)
        except ConnectionResetError:
            last_error = "连接被重置"
            last_status = 0
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return False, 0, last_error
        except Exception as e:
            last_error = "未知错误: %s" % str(e)
            last_status = 0
            if attempt < retries - 1:
                time.sleep(3)
                continue
            return False, 0, last_error

    return False, last_status, last_error


def check_ssl_cert(url):
    """
    检查 SSL 证书到期情况
    返回: (cert_info: dict or None, error_msg: str or None)
    cert_info 包含: expire_date, days_left, status
    status: "ok" / "warning" / "critical" / "expired"
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme != 'https':
        return None, "非HTTPS域名，跳过SSL检查"

    # 方法1: 用 CERT_REQUIRED 获取证书信息（证书有效时）
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert and 'notAfter' in cert:
                    return _parse_cert_info(cert['notAfter']), None
    except ssl.SSLCertVerificationError:
        # 证书验证失败（可能已过期）→ 方法2: 用 CERT_NONE 获取原始证书
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        pem = ssl.DER_cert_to_PEM_cert(der_cert)
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                            f.write(pem)
                            tmp_path = f.name
                        try:
                            cert_dict = ssl._ssl._test_decode_cert(tmp_path)
                            if cert_dict and 'notAfter' in cert_dict:
                                return _parse_cert_info(cert_dict['notAfter']), None
                        finally:
                            os.unlink(tmp_path)
        except Exception as e2:
            return None, "SSL证书解析失败: %s" % str(e2)
    except socket.timeout:
        return None, None  # 连接超时，跳过SSL检查（域名检查会报超时）
    except Exception as e:
        return None, "SSL检查失败: %s" % str(e)

    return None, "无法获取SSL证书信息"


def _parse_cert_info(not_after_str):
    """解析证书过期时间，返回证书状态信息"""
    expire_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
    expire_date = expire_date.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_left = (expire_date - now).days

    if days_left < 0:
        status = "expired"
    elif days_left <= SSL_CRITICAL_DAYS:
        status = "critical"
    elif days_left <= SSL_WARNING_DAYS:
        status = "warning"
    else:
        status = "ok"

    return {
        'expire_date': expire_date.strftime('%Y-%m-%d'),
        'days_left': days_left,
        'status': status,
    }


def dingtalk_sign(secret):
    """计算钉钉加签签名"""
    timestamp = str(round(time.time() * 1000))
    string_to_sign = "%s\n%s" % (timestamp, secret)
    hmac_code = hmac.new(
        secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256
    ).digest()
    sign = quote_plus(base64.b64encode(hmac_code))
    return timestamp, sign


def send_dingtalk(title, text):
    """发送钉钉 markdown 消息"""
    webhook = DINGTALK_WEBHOOK

    if DINGTALK_SECRET:
        timestamp, sign = dingtalk_sign(DINGTALK_SECRET)
        webhook += "&timestamp=%s&sign=%s" % (timestamp, sign)

    payload = {
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": text
        }
    }

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(webhook, data=data, headers={
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 DomainMonitor/1.0"
    })

    try:
        resp = urlopen(req, timeout=10)
        result = json.loads(resp.read().decode("utf-8"))
        if result.get("errcode") == 0:
            print("[钉钉] 消息发送成功")
            return True
        else:
            print("[钉钉] 发送失败: %s" % json.dumps(result, ensure_ascii=False))
            return False
    except Exception as e:
        print("[钉钉] 发送异常: %s" % str(e))
        return False


def load_state():
    """加载上次监控状态"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state(state):
    """保存监控状态"""
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("[状态] 保存失败: %s" % str(e))


def main():
    now = datetime.now(timezone(timedelta(hours=8)))  # 北京时间
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    now_ts = time.time()

    print("")
    print("=" * 55)
    print("  域名监控 - %s" % now_str)
    print("=" * 55)

    state = load_state()
    domain_alerts = []
    ssl_alerts = []

    for school_name, domain in DOMAINS:
        print("")
        print("[检查] %s (%s)" % (school_name, domain))

        # === 1. 域名可访问性检查 ===
        is_ok, status_code, error = check_domain(domain)
        if is_ok:
            print("  -> 访问正常 (HTTP %d)" % status_code)
        else:
            print("  -> 访问异常: %s" % error)

        prev = state.get(domain, {})
        was_ok = prev.get("is_ok", True)
        last_alert = prev.get("last_alert", 0)

        # 保留上次的 SSL 状态
        ssl_last_alert = prev.get("ssl_last_alert", 0)
        ssl_prev_status = prev.get("ssl_status", "ok")

        if not is_ok:
            if was_ok:
                domain_alerts.append({
                    "school_name": school_name,
                    "domain": domain,
                    "error": error,
                    "status_code": status_code,
                })
                last_alert = now_ts
            else:
                if now_ts - last_alert >= ALERT_COOLDOWN:
                    domain_alerts.append({
                        "school_name": school_name,
                        "domain": domain,
                        "error": error,
                        "status_code": status_code,
                    })
                    last_alert = now_ts
                else:
                    remaining = int(ALERT_COOLDOWN - (now_ts - last_alert))
                    print("  -> 告警冷却中，%d秒后可再次告警" % remaining)

        # === 2. SSL 证书到期检查 ===
        cert_info, ssl_error = check_ssl_cert(domain)
        if cert_info:
            ssl_status = cert_info['status']
            days_left = cert_info['days_left']
            expire_date = cert_info['expire_date']
            print("  -> SSL证书: 到期日 %s，剩余 %d 天" % (expire_date, days_left))

            if ssl_status != "ok":
                # 证书有问题 → 检查是否需要告警
                should_alert = False
                if ssl_status != ssl_prev_status:
                    # 状态升级了（如 ok→warning, warning→critical）→ 立即告警
                    should_alert = True
                elif now_ts - ssl_last_alert >= SSL_ALERT_COOLDOWN:
                    # 同状态但过了冷却期 → 重复告警
                    should_alert = True

                if should_alert:
                    ssl_alerts.append({
                        "school_name": school_name,
                        "domain": domain,
                        "expire_date": expire_date,
                        "days_left": days_left,
                        "status": ssl_status,
                    })
                    ssl_last_alert = now_ts
                else:
                    remaining = int(SSL_ALERT_COOLDOWN - (now_ts - ssl_last_alert))
                    print("  -> SSL告警冷却中，%d秒后可再次告警" % remaining)
        elif ssl_error:
            print("  -> SSL检查: %s" % ssl_error)
            ssl_status = ssl_prev_status
        else:
            ssl_status = ssl_prev_status

        # 保存状态
        state[domain] = {
            "is_ok": is_ok,
            "last_alert": last_alert,
            "error": error if not is_ok else "",
            "ssl_status": ssl_status,
            "ssl_last_alert": ssl_last_alert,
        }

    # === 发送域名访问异常告警 ===
    if domain_alerts:
        lines = ["### 域名监控告警\n"]
        lines.append("**检测时间**: %s\n" % now_str)
        for a in domain_alerts:
            lines.append("---")
            lines.append("**学校**: %s" % a["school_name"])
            lines.append("**域名**: %s" % a["domain"])
            if a["status_code"]:
                lines.append("**状态码**: HTTP %d" % a["status_code"])
            lines.append("**错误信息**: %s\n" % a["error"])
        lines.append("> 域名监控 - 自动检测")
        send_dingtalk("域名监控告警", "\n".join(lines))

    # === 发送SSL证书告警 ===
    if ssl_alerts:
        lines = ["### SSL证书到期告警\n"]
        lines.append("**检测时间**: %s\n" % now_str)
        for a in ssl_alerts:
            lines.append("---")
            lines.append("**学校**: %s" % a["school_name"])
            lines.append("**域名**: %s" % a["domain"])
            lines.append("**到期时间**: %s" % a["expire_date"])
            if a["status"] == "expired":
                lines.append("**状态**: 已过期 (已过期 %d 天)\n" % abs(a["days_left"]))
            elif a["status"] == "critical":
                lines.append("**状态**: 即将过期 (仅剩 %d 天)\n" % a["days_left"])
            else:
                lines.append("**状态**: 即将到期 (剩余 %d 天)\n" % a["days_left"])
        lines.append("> 域名监控 - 自动检测")
        send_dingtalk("SSL证书到期告警", "\n".join(lines))

    if not domain_alerts and not ssl_alerts:
        print("\n[结果] 所有域名及SSL证书状态正常，无需告警")

    save_state(state)
    print("")
    print("=" * 55)
    print("  监控完成")
    print("=" * 55)
    print("")


if __name__ == "__main__":
    main()
