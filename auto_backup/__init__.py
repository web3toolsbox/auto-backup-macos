# -*- coding: utf-8 -*-
"""
Auto Backup macOS - 自动备份工具包

一个用于macOS环境的自动备份工具，支持文件备份、压缩和上传到云端。
"""

__version__ = "1.1.1"
__author__ = "YLX Studio"

from .config import BackupConfig
from .core import BackupManager, main

__all__ = ["BackupConfig", "BackupManager", "main"]

