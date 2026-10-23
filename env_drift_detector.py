#!/usr/bin/env python3
"""
Env Drift Detector — .env 漂移/泄漏检测器 (v1.0)

三个子命令：
  drift   — 对比 .env 与 .env.example：缺失键/多出键/空值键/占位符未填键
  leak    — 扫描 .env（或任意env文件）里的真实secret泄漏风险（弱熵/默认值/示例值没换）
  report  — 全项目扫描：找出所有 env 文件 + 汇总漂移与泄漏（--json 机器可读）

退出码契约（挂CI/cron）：
  0 = 干净（无漂移无泄漏）
  1 = 发现问题（漂移或泄漏）
  2 = 参数/文件错误

纯stdlib零依赖。文件不出本机。
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys

# ---------- 解析 ----------

LINE_RE = re.compile(r'^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')

# 常见占位符值 = 没填真实值
PLACEHOLDER_PATTERNS = [
    r'^$', r'^changeme$', r'^change[-_]me$', r'^xxx+$', r'^<.*>$', r'^\$\{.*\}$',
    r'^your[-_].*$', r'^REPLACE.*$', r'^example.*$', r'^test$', r'^placeholder$',
    r'^TODO.*$', r'^insert.*$', r'^SK-XXX', r'^xxx-xxx', r'^abc123$', r'^password$',
]

# 已知公共示例值（出现=泄漏嫌疑）
KNOWN_DEFAULTS = {
    'SECRET_KEY': ['django-insecure-', 'devsecret'],
    'DATABASE_URL': ['postgres://user:pass@localhost', 'sqlite:///db.sqlite3', 'mysql://root:root@localhost'],
    'AWS_ACCESS_KEY_ID': ['AKIAIOSFODNN7EXAMPLE'],
    'AWS_SECRET_ACCESS_KEY': ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
    'STRIPE_SECRET_KEY': ['sk_test_'],
    'SMTP_PASSWORD': ['password', '123456'],
}

# 值形状识别：真实凭证形状但出现在 example 文件里没关系，出现在生产 .env 且值=默认形状要告警
HIGH_ENTROPY_MIN = 3.5  # bits/char 阈值


def parse_env_file(path):
    """解析env文件 → dict key→value（保留原文顺序与行号）。返回 (envdict, problems)"""
    env = {}
    problems = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for ln, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                m = LINE_RE.match(raw)
                if not m:
                    if raw.strip():
                        problems.append(f'{path}:{ln}: 无法解析的行: {line[:60]}')
                    continue
                _exp, key, val = m.group(1), m.group(2), m.group(3).strip()
                # 去引号
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                    val = val[1:-1]
                env[key] = val
    except FileNotFoundError:
        return None, [f'{path}: 文件不存在']
    return env, problems


def is_placeholder(val):
    v = val.strip().lower()
    for pat in PLACEHOLDER_PATTERNS:
        if re.match(pat, v, re.IGNORECASE):
            return True
    return False


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def looks_like_secret(key):
    k = key.upper()
    return any(t in k for t in ('SECRET', 'TOKEN', 'PASSWORD', 'PASSWD', 'API_KEY', 'APIKEY', 'PRIVATE', 'ACCESS_KEY', 'SIGNING', 'CREDENTIAL'))


# ---------- drift 子命令 ----------

def cmd_drift(args):
    actual, p1 = parse_env_file(args.env)
    example, p2 = parse_env_file(args.example)
    if actual is None or example is None:
        for p in (p1 + p2):
            print(p, file=sys.stderr)
        return 2
    findings = []
    missing = [k for k in example if k not in actual]
    extra = [k for k in actual if k not in example]
    empty_vals = [k for k, v in actual.items() if v == '']
    placeholders = [k for k, v in actual.items() if is_placeholder(v) and looks_like_secret(k)]
    if missing:
        findings.append(('MISSING_IN_ENV', f'.env 缺 {len(missing)} 个 .env.example 里的键: {", ".join(sorted(missing)[:10])}{"..." if len(missing) > 10 else ""}'))
    if extra and not args.allow_extra:
        findings.append(('EXTRA_IN_ENV', f'.env 多出 {len(extra)} 个 example 没有的键: {", ".join(sorted(extra)[:10])}{"..." if len(extra) > 10 else ""}'))
    if empty_vals:
        findings.append(('EMPTY_VALUE', f'.env 有 {len(empty_vals)} 个空值键: {", ".join(sorted(empty_vals)[:10])}'))
    if placeholders:
        findings.append(('PLACEHOLDER_SECRET', f'.env 疑似占位符未填的 secret 键: {", ".join(sorted(placeholders)[:10])}'))
    # 输出
    if args.json:
        print(json.dumps({
            'mode': 'drift', 'env': args.env, 'example': args.example,
            'clean': not findings,
            'missing': sorted(missing), 'extra': sorted(extra),
            'empty': sorted(empty_vals), 'placeholder_secrets': sorted(placeholders),
        }, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print(f'DRIFT_CLEAN: {args.env} 与 {args.example} 一致')
        for tag, msg in findings:
            print(f'[{tag}] {msg}')
    return 1 if findings else 0


# ---------- leak 子命令 ----------

def cmd_leak(args):
    env, problems = parse_env_file(args.env)
    if env is None:
        for p in problems:
            print(p, file=sys.stderr)
        return 2
    findings = []
    for key, val in env.items():
        if not val:
            continue
        low = val.lower()
        # 1) 已知默认值
        for kw in KNOWN_DEFAULTS.get(key, []):
            if kw.lower() in low:
                findings.append(('KNOWN_DEFAULT', key, f'值包含已知示例/默认值 "{kw}"'))
                break
        # 2) secret键 + 占位符
        if looks_like_secret(key) and is_placeholder(val):
            findings.append(('PLACEHOLDER', key, 'secret 键的值是占位符/示例'))
        # 3) secret键 + 低熵短值
        elif looks_like_secret(key) and len(val) >= 8 and shannon_entropy(val) < HIGH_ENTROPY_MIN:
            findings.append(('LOW_ENTROPY', key, f'secret 键熵值 {shannon_entropy(val):.2f} < {HIGH_ENTROPY_MIN}（像人肉敲的弱值）'))
        # 4) 真实凭证形状出现在非example文件（sk_live_ / AKIA / ghp_ / xoxb-）
        for prefix, label in (('sk_live_', 'Stripe live key'), ('AKIA', 'AWS key'), ('ghp_', 'GitHub PAT'), ('xoxb-', 'Slack bot token'), ('-----BEGIN', '私钥块')):
            if val.startswith(prefix):
                findings.append(('LIVE_CREDENTIAL_SHAPE', key, f'检测到 {label} 形状的真实凭证'))
                break
    if args.json:
        print(json.dumps({
            'mode': 'leak', 'env': args.env, 'clean': not findings,
            'findings': [{'type': t, 'key': k, 'detail': d} for t, k, d in findings],
        }, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print(f'LEAK_CLEAN: {args.env} 未发现泄漏风险')
        for t, k, d in findings:
            print(f'[{t}] {k}: {d}')
    return 1 if findings else 0


# ---------- report 子命令 ----------

ENV_FILE_NAMES = ('.env', '.env.local', '.env.production', '.env.development', '.env.staging')


def find_env_files(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', '__pycache__', 'venv', '.venv')]
        for fn in filenames:
            if fn in ENV_FILE_NAMES or fn.endswith('.env'):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)


def cmd_report(args):
    root = args.root
    if not os.path.isdir(root):
        print(f'{root}: 不是目录', file=sys.stderr)
        return 2
    env_files = find_env_files(root)
    summary = {'root': root, 'env_files': env_files, 'results': [], 'clean': True}
    for ef in env_files:
        ex = os.path.join(os.path.dirname(ef), '.env.example')
        entry = {'file': ef}
        if os.path.exists(ex):
            rc = _run_silent(['--mode', 'drift', '--env', ef, '--example', ex, '--json'])
            entry['drift'] = rc
            if rc:
                summary['clean'] = False
        rc2 = _run_silent(['--mode', 'leak', '--env', ef, '--json'])
        entry['leak'] = rc2
        if rc2:
            summary['clean'] = False
        summary['results'].append(entry)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(f'ENV REPORT: {len(env_files)} 个env文件 @ {root}')
        for e in summary['results']:
            status = 'CLEAN' if (e.get('drift', 0) == 0 and e.get('leak', 0) == 0) else 'ISSUES'
            print(f'  {e["file"]}: drift={e.get("drift", "-")} leak={e.get("leak", "-")} → {status}')
        if summary['clean']:
            print('ALL_CLEAN')
    return 0 if summary['clean'] else 1


def _run_silent(argv):
    """内部子调用（进程内直接调cmd函数避免重复解析）"""
    ns = argparse.Namespace(**{k: v for k, v in zip(('mode', 'env', 'example', 'json', 'allow_extra', 'root'),
                                                    (argv[1], argv[3], None, True, False, '.'))})
    if argv[1] == 'drift':
        ns.example = argv[5]
        return _quiet_drift(ns)
    return _quiet_leak(ns)


def _quiet_drift(ns):
    actual, p1 = parse_env_file(ns.env)
    example, p2 = parse_env_file(ns.example)
    if actual is None or example is None:
        return 2
    findings = bool([k for k in example if k not in actual] or
                    [k for k, v in actual.items() if v == ''] or
                    [k for k, v in actual.items() if is_placeholder(v) and looks_like_secret(k)])
    return 1 if findings else 0


def _quiet_leak(ns):
    env, problems = parse_env_file(ns.env)
    if env is None:
        return 2
    for key, val in env.items():
        if not val:
            continue
        low = val.lower()
        for kw in KNOWN_DEFAULTS.get(key, []):
            if kw.lower() in low:
                return 1
        if looks_like_secret(key) and (is_placeholder(val) or (len(val) >= 8 and shannon_entropy(val) < HIGH_ENTROPY_MIN)):
            return 1
        for prefix in ('sk_live_', 'AKIA', 'ghp_', 'xoxb-', '-----BEGIN'):
            if val.startswith(prefix):
                return 1
    return 0


def main():
    ap = argparse.ArgumentParser(prog='env_drift_detector', description='Env Drift Detector — .env 漂移与泄漏检测')
    sub = ap.add_subparsers(dest='cmd')

    d1 = sub.add_parser('drift', help='对比 .env 与 .env.example')
    d1.add_argument('--env', default='.env')
    d1.add_argument('--example', default='.env.example')
    d1.add_argument('--allow-extra', action='store_true', help='容忍 .env 里的额外键')
    d1.add_argument('--json', action='store_true')
    d1.set_defaults(func=cmd_drift)

    d2 = sub.add_parser('leak', help='扫描 env 文件的 secret 泄漏风险')
    d2.add_argument('--env', default='.env')
    d2.add_argument('--json', action='store_true')
    d2.set_defaults(func=cmd_leak)

    d3 = sub.add_parser('report', help='扫描整个项目的 env 文件')
    d3.add_argument('--root', default='.')
    d3.add_argument('--json', action='store_true')
    d3.set_defaults(func=cmd_report)

    args = ap.parse_args()
    if not getattr(args, 'func', None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
