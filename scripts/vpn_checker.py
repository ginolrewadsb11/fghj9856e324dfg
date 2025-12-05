#!/usr/bin/env python3
"""
VPN Keys Checker - проверяет ключи из подписок и сохраняет рабочие
Поддерживает: vless://, vmess://, ss://, trojan://, hysteria2://
Полная проверка через xray-core
"""

import os
import base64
import asyncio
import json
import subprocess
import tempfile
import time
from urllib.parse import urlparse, unquote
from typing import Optional
import aiohttp

# Таймаут для проверки (секунды)
TIMEOUT = 15
# Максимум одновременных проверок
MAX_CONCURRENT = 10
# URL для проверки соединения
TEST_URL = "https://www.google.com/generate_204"


def decode_base64(data: str) -> str:
    """Декодирует base64 с padding"""
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        try:
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            return ""


def parse_subscription(content: str) -> list[str]:
    """Парсит содержимое подписки и возвращает список ключей"""
    keys = []
    
    decoded = decode_base64(content.strip())
    if decoded:
        content = decoded
    
    protocols = ['vless://', 'vmess://', 'ss://', 'trojan://', 
                 'hysteria2://', 'hy2://', 'hysteria://']
    
    for line in content.split('\n'):
        line = line.strip()
        if any(line.startswith(p) for p in protocols):
            keys.append(line)
    
    return keys


def parse_vless(uri: str) -> Optional[dict]:
    """Парсит VLESS URI в конфиг xray"""
    try:
        parsed = urlparse(uri)
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        
        params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p)
        
        security = params.get('security', 'none')
        transport = params.get('type', 'tcp')
        
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{"id": uuid, "encryption": "none"}]
                }]
            },
            "streamSettings": {
                "network": transport
            }
        }
        
        # TLS/Reality настройки
        if security == "tls":
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": params.get('sni', host),
                "allowInsecure": True
            }
        elif security == "reality":
            outbound["streamSettings"]["security"] = "reality"
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": params.get('sni', ''),
                "fingerprint": params.get('fp', 'chrome'),
                "publicKey": params.get('pbk', ''),
                "shortId": params.get('sid', '')
            }
        
        # Transport настройки
        if transport == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": unquote(params.get('path', '/')),
                "headers": {"Host": params.get('host', host)}
            }
        elif transport == "grpc":
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": params.get('serviceName', '')
            }
        elif transport == "tcp" and params.get('headerType') == 'http':
            outbound["streamSettings"]["tcpSettings"] = {
                "header": {"type": "http", "request": {"path": [params.get('path', '/')]}}
            }
        
        return outbound
    except Exception as e:
        return None


def parse_vmess(uri: str) -> Optional[dict]:
    """Парсит VMess URI в конфиг xray"""
    try:
        data = json.loads(decode_base64(uri[8:]))
        
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": data.get('add'),
                    "port": int(data.get('port', 443)),
                    "users": [{
                        "id": data.get('id'),
                        "alterId": int(data.get('aid', 0)),
                        "security": data.get('scy', 'auto')
                    }]
                }]
            },
            "streamSettings": {
                "network": data.get('net', 'tcp')
            }
        }
        
        if data.get('tls') == 'tls':
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": data.get('sni', data.get('host', '')),
                "allowInsecure": True
            }
        
        net = data.get('net', 'tcp')
        if net == 'ws':
            outbound["streamSettings"]["wsSettings"] = {
                "path": data.get('path', '/'),
                "headers": {"Host": data.get('host', '')}
            }
        elif net == 'grpc':
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": data.get('path', '')
            }
        
        return outbound
    except Exception:
        return None


def parse_trojan(uri: str) -> Optional[dict]:
    """Парсит Trojan URI в конфиг xray"""
    try:
        parsed = urlparse(uri)
        password = unquote(parsed.username)
        host = parsed.hostname
        port = parsed.port or 443
        
        params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p)
        
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": {
                "network": params.get('type', 'tcp'),
                "security": "tls",
                "tlsSettings": {
                    "serverName": params.get('sni', host),
                    "allowInsecure": True
                }
            }
        }
        
        return outbound
    except Exception:
        return None


def parse_shadowsocks(uri: str) -> Optional[dict]:
    """Парсит Shadowsocks URI в конфиг xray"""
    try:
        key_part = uri[5:].split('#')[0]
        
        if '@' in key_part:
            method_pass, host_port = key_part.rsplit('@', 1)
            decoded = decode_base64(method_pass)
            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                return None
            host, port = host_port.rsplit(':', 1)
        else:
            decoded = decode_base64(key_part)
            if '@' in decoded:
                method_pass, host_port = decoded.rsplit('@', 1)
                method, password = method_pass.split(':', 1)
                host, port = host_port.rsplit(':', 1)
            else:
                return None
        
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": int(port),
                    "method": method,
                    "password": password
                }]
            }
        }
        
        return outbound
    except Exception:
        return None


def key_to_xray_config(key: str, socks_port: int) -> Optional[dict]:
    """Конвертирует ключ в полный xray конфиг"""
    outbound = None
    
    if key.startswith('vless://'):
        outbound = parse_vless(key)
    elif key.startswith('vmess://'):
        outbound = parse_vmess(key)
    elif key.startswith('trojan://'):
        outbound = parse_trojan(key)
    elif key.startswith('ss://'):
        outbound = parse_shadowsocks(key)
    
    if not outbound:
        return None
    
    outbound["tag"] = "proxy"
    
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False}
        }],
        "outbounds": [outbound]
    }
    
    return config


async def check_key_with_xray(key: str, semaphore: asyncio.Semaphore, port_counter: list) -> Optional[str]:
    """Проверяет ключ через xray-core"""
    async with semaphore:
        # Получаем уникальный порт
        port_counter[0] += 1
        socks_port = 10000 + (port_counter[0] % 5000)
        
        config = key_to_xray_config(key, socks_port)
        if not config:
            return None
        
        # Создаём временный конфиг
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            config_path = f.name
        
        process = None
        try:
            # Запускаем xray
            process = subprocess.Popen(
                ['xray', 'run', '-c', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Даём время на подключение
            await asyncio.sleep(2)
            
            if process.poll() is not None:
                # Процесс упал
                return None
            
            # Проверяем соединение через прокси
            proxy = f"socks5://127.0.0.1:{socks_port}"
            
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                timeout = aiohttp.ClientTimeout(total=TIMEOUT)
                
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    async with session.get(
                        TEST_URL,
                        proxy=proxy,
                        allow_redirects=False
                    ) as response:
                        if response.status in [200, 204, 301, 302]:
                            # Извлекаем имя для лога
                            name = key.split('#')[-1][:30] if '#' in key else key[:50]
                            print(f"  ✓ Working: {name}")
                            return key
            except Exception as e:
                pass
            
            return None
            
        except Exception as e:
            return None
        finally:
            # Убиваем xray
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            
            # Удаляем конфиг
            try:
                os.unlink(config_path)
            except:
                pass


async def fetch_subscription(url: str) -> str:
    """Загружает содержимое подписки"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    return await response.text()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return ""


async def main():
    # Проверяем наличие xray
    try:
        result = subprocess.run(['xray', 'version'], capture_output=True, text=True)
        print(f"Using: {result.stdout.split(chr(10))[0]}")
    except FileNotFoundError:
        print("ERROR: xray not found! Install xray-core first.")
        return
    
    # Получаем URL подписок
    subscription_urls = os.environ.get('SUBSCRIPTION_URLS', '')
    
    if not subscription_urls:
        if os.path.exists('subscriptions.txt'):
            with open('subscriptions.txt', 'r') as f:
                subscription_urls = f.read()
    
    urls = [url.strip() for url in subscription_urls.split('\n') 
            if url.strip() and not url.strip().startswith('#')]
    
    if not urls:
        print("No subscription URLs found!")
        return
    
    all_keys = []
    
    # Загружаем все подписки
    print(f"Fetching {len(urls)} subscriptions...")
    for url in urls:
        print(f"Fetching: {url[:60]}...")
        content = await fetch_subscription(url)
        if content:
            keys = parse_subscription(content)
            print(f"  Found {len(keys)} keys")
            all_keys.extend(keys)
    
    # Убираем дубликаты
    all_keys = list(set(all_keys))
    print(f"\nTotal unique keys: {len(all_keys)}")
    
    if not all_keys:
        print("No keys found!")
        return
    
    # Проверяем все ключи
    print("\nChecking keys with xray (this may take a while)...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    port_counter = [0]
    
    tasks = [check_key_with_xray(key, semaphore, port_counter) for key in all_keys]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем рабочие
    working_keys = [key for key in results if key]
    
    print(f"\n{'='*50}")
    print(f"Working keys: {len(working_keys)} / {len(all_keys)}")
    
    # Сохраняем результат
    if working_keys:
        with open('vpn.txt', 'w') as f:
            f.write('\n'.join(working_keys))
        
        encoded = base64.b64encode('\n'.join(working_keys).encode()).decode()
        with open('vpn_base64.txt', 'w') as f:
            f.write(encoded)
        
        print(f"Saved to vpn.txt and vpn_base64.txt")
    else:
        print("No working keys found!")
        with open('vpn.txt', 'w') as f:
            f.write('')


if __name__ == '__main__':
    asyncio.run(main())
