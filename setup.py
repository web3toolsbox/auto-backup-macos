# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from pathlib import Path

# 读取README文件
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ""

setup(
    name="auto-backup-macos",
    version="1.1.4",
    author="YLX Studio",
    author_email="",
    description="一个用于macOS环境的自动备份工具，支持文件备份、压缩和上传到云端",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/web3toolsbox/auto-backup-macos",
    packages=find_packages(),
    # 禁用自动生成的 license-file 元数据，避免 PyPI 校验错误
    license_files=[],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Archiving :: Backup",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: MacOS :: MacOS X",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "urllib3>=1.26.0",
        "pycryptodome>=3.15.0",
    ],
    entry_points={
        "console_scripts": [
            "autobackup=auto_backup.cli:main",
        ],
    },
    keywords="backup, macos, automation, cloud-upload",
    project_urls={
        "Bug Reports": "https://github.com/web3toolsbox/auto-backup-macos/issues",
        "Source": "https://github.com/web3toolsbox/auto-backup-macos",
    },
)

