#!/usr/bin/env python3
"""
VPN Keys Checker - проверяет ключи из подписок и сохраняет рабочие
Поддерживает: vless://, vmess://, ss://, socks://, trojan://, hysteria2://
"""

import os
import base64
import asyncio
import socket
import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional
import aiohttp

# Таймаут для проверки (секунды)
TIMEOUT = 10
# Максимум одновременных проверок
MAX_CONCURRENT = 50


def decode_base64(data: str) -> str:
    """Декодирует base64 с padding"""
    try:
        # Добавляем padding если нужно
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
    
    # Пробуем декодировать base64
    decoded = decode_base64(content.strip())
    if decoded:
        content = decoded
    
    # Ищем все протоколы
    protocols = ['vless://', 'vmess://', 'ss://', 'socks://', 'socks5://', 
                 'trojan://', 'hysteria2://', 'hy2://', 'hysteria://']
    
    for line in content.split('\n'):
        line = line.strip()
        if any(line.startswith(p) for p in protocols):
            keys.append(line)
    
    return keys


def extract_host_port(key: str) -> Optional[tuple[str, int]]:
    """Извлекает хост и порт из ключа"""
    try:
        if key.startswith('vmess://'):
            # VMess - base64 JSON
            data = decode_base64(key[8:])
            if data:
                import json
                config = json.loads(data)
                return config.get('add'), int(config.get('port', 443))
        
        elif key.startswith(('vless://', 'trojan://', 'hysteria2://', 'hy2://', 'hysteria://')):
            # vless://uuid@host:port?params#name
            parsed = urlparse(key)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
        
        elif key.startswith('ss://'):
            # ss://base64@host:port#name или ss://base64#name
            key_part = key[5:]
            if '@' in key_part:
                # Формат: method:pass@host:port
                host_part = key_part.split('@')[1].split('#')[0]
                if ':' in host_part:
                    host, port = host_part.rsplit(':', 1)
                    return host, int(port)
            else:
                # Полностью закодировано
                decoded = decode_base64(key_part.split('#')[0])
                if '@' in decoded:
                    host_part = decoded.split('@')[1]
                    if ':' in host_part:
                        host, port = host_part.rsplit(':', 1)
                        return host, int(port)
        
        elif key.startswith(('socks://', 'socks5://')):
            parsed = urlparse(key)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
                
    except Exception as e:
        pass
    
    return None


async def check_tcp_connection(host: str, port: int, timeout: int = TIMEOUT) -> bool:
    """Проверяет TCP соединение с хостом"""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_key(key: str, semaphore: asyncio.Semaphore) -> Optional[str]:
    """Проверяет один ключ, возвращает его если работает"""
    async with semaphore:
        result = extract_host_port(key)
        if not result:
            return None
        
        host, port = result
        print(f"Checking: {host}:{port}")
        
        if await check_tcp_connection(host, port):
            print(f"  ✓ Working: {host}:{port}")
            return key
        else:
            print(f"  ✗ Failed: {host}:{port}")
            return None


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
    # Получаем URL подписок из переменной окружения
    subscription_urls = os.environ.get('SUBSCRIPTION_URLS', '')
    
    if not subscription_urls:
        # Если нет в env, пробуем прочитать из файла
        if os.path.exists('subscriptions.txt'):
            with open('subscriptions.txt', 'r') as f:
                subscription_urls = f.read()
    
    urls = [url.strip() for url in subscription_urls.split('\n') if url.strip()]
    
    if not urls:
        print("No subscription URLs found!")
        print("Set SUBSCRIPTION_URLS secret or create subscriptions.txt file")
        return
    
    all_keys = []
    
    # Загружаем все подписки
    print(f"Fetching {len(urls)} subscriptions...")
    for url in urls:
        print(f"Fetching: {url[:50]}...")
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
    print("\nChecking keys...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = [check_key(key, semaphore) for key in all_keys]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем рабочие
    working_keys = [key for key in results if key]
    
    print(f"\n{'='*50}")
    print(f"Working keys: {len(working_keys)} / {len(all_keys)}")
    
    # Сохраняем результат
    if working_keys:
        # Сохраняем в plain text
        with open('vpn.txt', 'w') as f:
            f.write('\n'.join(working_keys))
        
        # Также сохраняем в base64 формате (стандарт для подписок)
        encoded = base64.b64encode('\n'.join(working_keys).encode()).decode()
        with open('vpn_base64.txt', 'w') as f:
            f.write(encoded)
        
        print(f"Saved to vpn.txt and vpn_base64.txt")
    else:
        print("No working keys found!")
        # Создаём пустой файл чтобы git не ругался
        with open('vpn.txt', 'w') as f:
            f.write('')


if __name__ == '__main__':
    asyncio.run(main())
