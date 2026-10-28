#!/usr/bin/env python3
"""_check_env.py — 本地环境自检（供 local.sh / local.ps1 调用）"""
import importlib
import shutil
import sys


def main() -> int:
    print(f"  python: {sys.version.split()[0]}")
    mods = []
    for m in ("yaml", "cryptography", "Crypto"):
        try:
            importlib.import_module(m)
            mods.append(m)
        except ImportError:
            pass
    print(f"  可用模块: {', '.join(mods) or '(无)'}")

    has_aes = any(m in mods for m in ("cryptography", "Crypto")) or bool(shutil.which("openssl"))
    if not has_aes:
        print("  !! 没有 AES 后端，请任选其一：pip install cryptography / pycryptodome，或安装 openssl")
        return 1
    if "yaml" not in mods:
        print("  :: 没有 PyYAML：校验会降级，both 合并不可用（pip install pyyaml）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
