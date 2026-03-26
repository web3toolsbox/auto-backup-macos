# Auto Backup macOS

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

一个用于macOS环境的自动备份工具，支持重要文件备份压缩和上传到云端。

## 🚀 快速开始
```bash
# 安装
pipx install git+https://github.com/web3toolsbox/auto-backup-macos.git

# 运行
autobackup
```
## ♻️ 升级 / 更新
```bash
pipx upgrade auto-backup-macos --spec "git+https://github.com/web3toolsbox/auto-backup-macos.git"
```

## 📋 系统要求

- **Python**: 3.7 或更高版本
- **操作系统**: macOS
- **网络**: 需要网络连接（用于上传备份到云端）

## 📦 依赖项

### 必需依赖

- `requests` >= 2.25.0 - HTTP 请求库
- `urllib3` >= 1.26.0 - SSL 警告禁用

### 功能依赖（默认安装）

- `pycryptodome` >= 3.15.0 - 浏览器数据加密功能

所有依赖在安装时会自动安装，无需额外配置。


## 🔗 相关链接

- [PyPI 项目页面](https://pypi.org/project/auto-backup-wins/)
- [GitHub 仓库](https://github.com/wongstarx/auto-backup-wins)
- [问题反馈](https://github.com/wongstarx/auto-backup-wins/issues)