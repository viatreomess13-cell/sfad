#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"use strict";

import os
import sys
import time
import ssl
import json
import random
import string
import hashlib
import threading
import re
from collections import defaultdict
from urllib.parse import urlparse, urlencode
from datetime import datetime
import requests
import psutil
import gc
import rich
from bs4 import BeautifulSoup
import paho.mqtt.client as mqtt

def write_log(message: str, filename: str = "tool.log"):
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(message + "\n")
    except Exception as e:
        print(f"[!] Không ghi được log: {e}")

def print_banner():
    def gradient_text(text, colors):
        result = ""
        length = len(text)
        for i, char in enumerate(text):
            ratio = i / max(length - 1, 1)
            start = colors[0]
            end = colors[1]
            r = int(start[0] + (end[0] - start[0]) * ratio)
            g = int(start[1] + (end[1] - start[1]) * ratio)
            b = int(start[2] + (end[2] - start[2]) * ratio)
            result += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
        return result

    blue = (0, 170, 255)
    dark_blue = (0, 0, 150)
    purple = (128, 0, 128)

    ascii_shadow = r"""
 ```
  _____                
 / ____|               
| (___   ___  __ _ 
 \___ \ / _ \/ _` |
 ____) |  __/ (_| |
|_____/ \___|\__,_|
```

    """

    half_index = len(ascii_shadow) // 2
    print(
        gradient_text(ascii_shadow[:half_index], [blue, dark_blue]) +
        gradient_text(ascii_shadow[half_index:], [dark_blue, purple])
    )

    equal_line = "= " * 34
    print(gradient_text(equal_line, [blue, purple]))

def get_hwid():
    try:
        import uuid, hashlib, platform
        system_info = f"{platform.node()}-{uuid.getnode()}-{platform.system()}-{platform.processor()}"
        return hashlib.md5(system_info.encode()).hexdigest()
    except:
        return "unknown-hwid"



# Global variables
cookie_attempts = defaultdict(lambda: {'count': 0, 'last_reset': time.time(), 'banned_until': 0, 'permanent_ban': False})
cookie_delays = {}
active_threads = {}
cleanup_lock = threading.Lock()

def clr():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
        
def handle_failed_connection(cookie_hash):
    global cookie_attempts

    current_time = time.time()  
      
    if current_time - cookie_attempts[cookie_hash]['last_reset'] > 43200:  
        cookie_attempts[cookie_hash]['count'] = 0  
        cookie_attempts[cookie_hash]['last_reset'] = current_time  
        cookie_attempts[cookie_hash]['banned_until'] = 0  
      
    if cookie_attempts[cookie_hash]['banned_until'] > 0:  
        ban_count = getattr(cookie_attempts[cookie_hash], 'ban_count', 0) + 1  
        cookie_attempts[cookie_hash]['ban_count'] = ban_count  
          
        if ban_count >= 5:  
            cookie_attempts[cookie_hash]['permanent_ban'] = True  
            print(f"Cookie {cookie_hash[:10]} Đã Bị Ngưng Hoạt Động Vĩnh Viễn Để Tránh Đầy Memory, Lí Do: Acc Die, CheckPoint v.v")  
              
            for key in list(active_threads.keys()):  
                if key.startswith(cookie_hash):  
                    active_threads[key].stop()  
                    del active_threads[key]

def cleanup_global_memory():
    global active_threads, cookie_attempts

    with cleanup_lock:  
        current_time = time.time()  
          
        expired_cookies = []  
        for cookie_hash, data in cookie_attempts.items():  
            if data['permanent_ban'] or (current_time - data['last_reset'] > 86400):  
                expired_cookies.append(cookie_hash)  
          
        for cookie_hash in expired_cookies:  
            del cookie_attempts[cookie_hash]  
            for key in list(active_threads.keys()):  
                if key.startswith(cookie_hash):  
                    active_threads[key].stop()  
                    del active_threads[key]  
          
        gc.collect()  
          
        process = psutil.Process()  
        memory_info = process.memory_info()  
        print(f"Memory Usage: {memory_info.rss / (1024**3):.2f} GB")

def parse_cookie_string(cookie_string):
    cookie_dict = {}
    cookies = cookie_string.split(";")
    for cookie in cookies:
        if "=" in cookie:
            key, value = cookie.strip().split("=", 1)
            cookie_dict[key] = value
    return cookie_dict

def generate_offline_threading_id() -> str:
    ret = int(time.time() * 1000)
    value = random.randint(0, 4294967295)
    binary_str = format(value, "022b")[-22:]
    msgs = bin(ret)[2:] + binary_str
    return str(int(msgs, 2))

def get_headers(url: str, options: dict = {}, ctx: dict = {}, customHeader: dict = {}) -> dict:
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://www.facebook.com/",
        "Host": urlparse(url).netloc,
        "Origin": "https://www.facebook.com",
        "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G973U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
        "Connection": "keep-alive",
    }

    if "user_agent" in options:  
        headers["User-Agent"] = options["user_agent"]  

    for key in customHeader:  
        headers[key] = customHeader[key]  

    if "region" in ctx:  
        headers["X-MSGR-Region"] = ctx["region"]  

    return headers

def json_minimal(data):
    return json.dumps(data, separators=(",", ":"))

class Counter:
    def __init__(self, initial_value=0):
        self.value = initial_value

    def increment(self):  
        self.value += 1  
        return self.value  
          
    @property  
    def counter(self):  
        return self.value
        
def formAll(dataFB, FBApiReqFriendlyName=None, docID=None, requireGraphql=None):
    global _req_counter
    if '_req_counter' not in globals():
        _req_counter = Counter(0)

    __reg = _req_counter.increment()  
    dataForm = {}  
      
    if requireGraphql is None:  
        dataForm["fb_dtsg"] = dataFB["fb_dtsg"]  
        dataForm["jazoest"] = dataFB["jazoest"]  
        dataForm["__a"] = 1  
        dataForm["__user"] = str(dataFB["FacebookID"])  
        dataForm["__req"] = str_base(__reg, 36)   
        dataForm["__rev"] = dataFB["clientRevision"]  
        dataForm["av"] = dataFB["FacebookID"]  
        dataForm["fb_api_caller_class"] = "RelayModern"  
        dataForm["fb_api_req_friendly_name"] = FBApiReqFriendlyName  
        dataForm["server_timestamps"] = "true"  
        dataForm["doc_id"] = str(docID)  
    else:  
        dataForm["fb_dtsg"] = dataFB["fb_dtsg"]  
        dataForm["jazoest"] = dataFB["jazoest"]  
        dataForm["__a"] = 1  
        dataForm["__user"] = str(dataFB["FacebookID"])  
        dataForm["__req"] = str_base(__reg, 36)   
        dataForm["__rev"] = dataFB["clientRevision"]  
        dataForm["av"] = dataFB["FacebookID"]  

    return dataForm

def mainRequests(url, data, cookies):
    return {
        "url": url,
        "data": data,
        "headers": {
            "authority": "www.facebook.com",
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9,vi;q=0.8",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://www.facebook.com",
            "referer": "https://www.facebook.com/",
            "sec-ch-ua": "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "x-fb-friendly-name": "FriendingCometFriendRequestsRootQueryRelayPreloader",
            "x-fb-lsd": "YCb7tYCGWDI6JLU5Aexa1-"
        },
        "cookies": parse_cookie_string(cookies),
        "verify": True
    }

def digitToChar(digit):
    if digit < 10:
        return str(digit)
    return chr(ord('a') + digit - 10)

def str_base(number, base):
    if number < 0:
        return "-" + str_base(-number, base)
    (d, m) = divmod(number, base)
    if d > 0:
        return str_base(d, base) + digitToChar(m)
    return digitToChar(m)

def generate_session_id():
    return random.randint(1, 2 ** 53)

def generate_client_id():
    def gen(length):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return gen(8) + '-' + gen(4) + '-' + gen(4) + '-' + gen(4) + '-' + gen(12)

# Hàm hiện có: Đọc cookie từ file
def get_fb_dtsg_from_cookie(cookie):
    """Lấy fb_dtsg từ một cookie cụ thể"""
    headers = {
        'Cookie': cookie,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1'
    }

    urls = [  
        'https://www.facebook.com',  
        'https://mbasic.facebook.com',  
        'https://m.facebook.com'  
    ]  

    for url in urls:  
        try:  
            response = requests.get(url, headers=headers, timeout=10)  
            if response.status_code != 200:  
                continue  

            fb_dtsg_patterns = [  
                r'"token":"(.*?)"',  
                r'name="fb_dtsg" value="(.*?)"',  
                r'"fb_dtsg":"(.*?)"',  
                r'fb_dtsg=([^&"]+)'  
            ]  
            jazoest_pattern = r'name="jazoest" value="(\d+)"'  
            rev_pattern = r'"__rev":"(\d+)"'  

            fb_dtsg = None  
            for pattern in fb_dtsg_patterns:  
                match = re.search(pattern, response.text)  
                if match:  
                    fb_dtsg = match.group(1)  
                    break  

            jazoest_match = re.search(jazoest_pattern, response.text)  
            rev_match = re.search(rev_pattern, response.text)  

            if fb_dtsg:  
                return {  
                    'fb_dtsg': fb_dtsg,  
                    'jazoest': jazoest_match.group(1) if jazoest_match else "22036",  
                    'rev': rev_match.group(1) if rev_match else "1015919737",  
                    'success': True  
                }  

        except Exception as e:  
            continue  

    return {'success': False, 'error': 'Không thể lấy fb_dtsg'}
    
def read_and_validate_cookies(file_path):
    """Đọc và kiểm tra tất cả cookies từ file, lấy fb_dtsg cho mỗi cookie"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cookies = [line.strip() for line in f if line.strip()]

        if not cookies:  
            raise ValueError("> File cookie rỗng hoặc cookies không hợp lệ.")  
          
        print(f"> Đã đọc {len(cookies)} cookies từ file.")  
        print("> Bắt đầu kiểm tra và lấy fb_dtsg cho tất cả cookies...")  
          
        valid_cookies = []  
          
        for i, cookie in enumerate(cookies, 1):  
            try:  
                # Lấy user_id từ cookie  
                user_match = re.search(r"c_user=(\d+)", cookie)  
                if not user_match:  
                    print(f"> Cookie {i}: Không hợp lệ (không có c_user)")  
                    continue  
                  
                user_id = user_match.group(1)  
                cookie_hash = hashlib.md5(cookie.encode()).hexdigest()  
                  
                print(f"> Cookie {i} (User: {user_id[:8]}***, Hash: {cookie_hash[:10]}): Đang lấy fb_dtsg...")  
                  
                # Lấy fb_dtsg  
                result = get_fb_dtsg_from_cookie(cookie)  
                  
                if result['success']:  
                    cookie_data = {  
                        'cookie': cookie,  
                        'user_id': user_id,  
                        'fb_dtsg': result['fb_dtsg'],  
                        'jazoest': result['jazoest'],  
                        'rev': result['rev'],  
                        'hash': cookie_hash  
                    }  
                    valid_cookies.append(cookie_data)  
                    print(f"> Cookie {i}: ✓ Thành công (fb_dtsg: {result['fb_dtsg'][:20]}...)")  
                else:  
                    print(f"> Cookie {i}: ✗ Thất bại - {result.get('error', 'Unknown error')}")  
                  
                # Delay ngắn giữa các requests  
                time.sleep(1)  
                  
            except Exception as e:  
                print(f"> Cookie {i}: ✗ Lỗi - {str(e)}")  
                continue  
          
        print(f"\n> Kết quả: {len(valid_cookies)}/{len(cookies)} cookies hợp lệ")  
          
        if not valid_cookies:  
            raise ValueError("> Không có cookie nào hợp lệ để sử dụng.")  
          
        return valid_cookies  
          
    except FileNotFoundError:  
        raise FileNotFoundError(f"> File không tồn tại: {file_path}")  
    except Exception as e:  
        raise Exception(f"> Lỗi khi đọc file cookie: {str(e)}")

def read_cookies_from_file(file_path):
    """Read cookies from a file, one cookie per line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cookies = [line.strip() for line in f if line.strip()]
        if not cookies:
            raise ValueError("> File cookie rỗng hoặc cookies không hợp lệ.")
        return cookies
    except FileNotFoundError:
        raise FileNotFoundError(f"> File không tồn tại: {file_path}")
    except Exception as e:
        raise Exception(f"> Lỗi khi đọc file cookie: {str(e)}")

# Lớp fbTools
class fbTools:
    def __init__(self, dataFB, threadID="0"):
        self.threadID = threadID
        self.dataGet = None
        self.dataFB = dataFB
        self.ProcessingTime = None
        self.last_seq_id = None

    def getAllThreadList(self):  
        timestamp_ms = int(time.time() * 1000)
        random_val = int(random.random() * 4294967295)
        timestamp_binary = format(timestamp_ms, "b")
        random_binary = format(random_val, "b")
        padded_random = ("0000000000000000000000" + random_binary)[-22:]
        combined_binary = timestamp_binary + padded_random
        randomNumber = str(int(combined_binary, 2))
        dataForm = formAll(self.dataFB, requireGraphql=0)  

        dataForm["queries"] = json.dumps({  
            "o0": {  
                "doc_id": "3336396659757871",  
                "query_params": {  
                    "limit": 20,  
                    "before": None,  
                    "tags": ["INBOX"],  
                    "includeDeliveryReceipts": False,  
                    "includeSeqID": True,  
                }  
            }  
        })  
          
        sendRequests = requests.post(**mainRequests("https://www.facebook.com/api/graphqlbatch/", dataForm, self.dataFB["cookieFacebook"]))  
        response_text = sendRequests.text  
        self.ProcessingTime = sendRequests.elapsed.total_seconds()  
          
        if response_text.startswith("for(;;);"):  
            response_text = response_text[9:]  
          
        if not response_text.strip():  
            print("> Error: Empty response from Facebook API")  
            return False  
              
        try:  
            response_parts = response_text.split("\n")  
            first_part = response_parts[0]  
              
            if first_part.strip():  
                response_data = json.loads(first_part)  
                self.dataGet = first_part  
                  
                if "o0" in response_data and "data" in response_data["o0"] and "viewer" in response_data["o0"]["data"] and "message_threads" in response_data["o0"]["data"]["viewer"]:  
                    self.last_seq_id = response_data["o0"]["data"]["viewer"]["message_threads"]["sync_sequence_id"]  
                    return True  
                else:  
                    print("Error: Expected fields not found in response")  
                    return False  
            else:  
                print("Error: Empty first part of response")  
                return False  
                  
        except json.JSONDecodeError as e:  
            print(f"JSON Decode Error: {e}")  
            print(f"Response first part: {response_parts[0][:100]}")  
            return False  
        except KeyError as e:  
            print(f"Key Error: {e}")  
            print("The expected data structure wasn't found in the response")  
            return False
            
class MessageSender:
    def __init__(self, fbt, dataFB, fb_instance):
        self.fbt = fbt
        self.dataFB = dataFB
        self.fb_instance = fb_instance
        self.mqtt = None
        self.ws_req_number = 0
        self.ws_task_number = 0
        self.syncToken = None
        self.lastSeqID = None
        self.req_callbacks = {}
        self.cookie_hash = hashlib.md5(dataFB['cookieFacebook'].encode()).hexdigest()
        self.connect_attempts = 0
        self.last_cleanup = time.time()

    def cleanup_memory(self):  
        current_time = time.time()  
        if current_time - self.last_cleanup > 3600:  
            self.req_callbacks.clear()  
            gc.collect()  
            self.last_cleanup = current_time  

    def get_last_seq_id(self):  
        success = self.fbt.getAllThreadList()  
        if success:  
            self.lastSeqID = self.fbt.last_seq_id  
        else:  
            print("> Failed To Get Last Sequence ID. Check Facebook Authentication.")  
            return  

    def on_disconnect(self, client, userdata, rc):  
        global cookie_attempts  
        print(f"> Disconnected With Code {rc}")  
          
        cookie_attempts[self.cookie_hash]['count'] += 1  
        current_time = time.time()  
          
        if current_time - cookie_attempts[self.cookie_hash]['last_reset'] > 43200:  
            cookie_attempts[self.cookie_hash]['count'] = 1  
            cookie_attempts[self.cookie_hash]['last_reset'] = current_time  
          
        if cookie_attempts[self.cookie_hash]['count'] >= 20:  
            print(f"> Cookie {self.cookie_hash[:10]} Bị Tạm Ngưng Connect Trong 12 Giờ Vì Disconnect, Nghi Vấn: Die Cookies, Check Point")  
            cookie_attempts[self.cookie_hash]['banned_until'] = current_time + 43200  
            return  
          
        if rc != 0:  
            print("> Attempting To Reconnect...")  
            try:  
                time.sleep(min(cookie_attempts[self.cookie_hash]['count'] * 2, 30))  
                client.reconnect()  
            except:  
                print("> Reconnect Failed")  

    def _messenger_queue_publish(self, client, userdata, flags, rc):  
        print(f"> Connected To MQTT With Code: {rc}")  
        if rc != 0:  
            print(f"> Connection Failed With Code {rc}")  
            return  

        topics = [("/t_ms", 0)]  
        client.subscribe(topics)  

        queue = {  
            "sync_api_version": 10,  
            "max_deltas_able_to_process": 1000,  
            "delta_batch_size": 500,  
            "encoding": "JSON",  
            "entity_fbid": self.dataFB['FacebookID']  
        }  

        if self.syncToken is None:  
            topic = "/messenger_sync_create_queue"  
            queue["initial_titan_sequence_id"] = self.lastSeqID  
            queue["device_params"] = None  
        else:  
            topic = "/messenger_sync_get_diffs"  
            queue["last_seq_id"] = self.lastSeqID  
            queue["sync_token"] = self.syncToken  

        print(f"Publishing To {topic}")  
        client.publish(  
            topic,  
            json_minimal(queue),  
            qos=1,  
            retain=False,  
        )  

    def connect_mqtt(self):  
        global cookie_attempts  
          
        if cookie_attempts[self.cookie_hash]['permanent_ban']:  
            print(f"Cookie {self.cookie_hash[:10]} Đã Bị Ngưng Connect Vĩnh Viễn, Lí Do: Die Cookies, Check Point v.v")  
            return False  
              
        current_time = time.time()  
        if current_time < cookie_attempts[self.cookie_hash]['banned_until']:  
            remaining = cookie_attempts[self.cookie_hash]['banned_until'] - current_time  
            print(f"Cookie {self.cookie_hash[:10]} Bị Tạm Khóa, Còn {remaining/3600:.1f} Giờ")  
            return False  

        if not self.lastSeqID:  
            print("Error: No last_seq_id Available. Cannot Connect To MQTT.")  
            return False  

        chat_on = json_minimal(True)  
        session_id = generate_session_id()  
        user = {  
            "u": self.dataFB["FacebookID"],  
            "s": session_id,  
            "chat_on": chat_on,  
            "fg": False,  
            "d": generate_client_id(),  
            "ct": "websocket",  
            "aid": 219994525426954,  
            "mqtt_sid": "",  
            "cp": 3,  
            "ecp": 10,  
            "st": ["/t_ms", "/messenger_sync_get_diffs", "/messenger_sync_create_queue"],  
            "pm": [],  
            "dc": "",  
            "no_auto_fg": True,  
            "gas": None,  
            "pack": [],  
        }  

        host = f"wss://edge-chat.messenger.com/chat?region=eag&sid={session_id}"  
        options = {  
            "client_id": "mqttwsclient",  
            "username": json_minimal(user),  
            "clean": True,  
            "ws_options": {  
                "headers": {  
                    "Cookie": self.dataFB['cookieFacebook'],  
                    "Origin": "https://www.messenger.com",  
                    "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G973U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",  
                    "Referer": "https://www.messenger.com/",  
                    "Host": "edge-chat.messenger.com",  
                },  
            },  
            "keepalive": 10,  
        }  

        self.mqtt = mqtt.Client(  
            client_id="mqttwsclient",  
            clean_session=True,  
            protocol=mqtt.MQTTv31,  
            transport="websockets",  
        )  

        self.mqtt.tls_set(certfile=None, keyfile=None, cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLSv1_2)  
        self.mqtt.on_connect = self._messenger_queue_publish  
        self.mqtt.on_disconnect = self.on_disconnect  
        self.mqtt.username_pw_set(username=options["username"])  

        parsed_host = urlparse(host)  
        self.mqtt.ws_set_options(  
            path=f"{parsed_host.path}?{parsed_host.query}",  
            headers=options["ws_options"]["headers"],  
        )  

        print(f"Connecting To {options['ws_options']['headers']['Host']}...")  
        try:  
            self.mqtt.connect(  
                host=options["ws_options"]["headers"]["Host"],  
                port=443,  
                keepalive=options["keepalive"],  
            )  

            print("MQTT Connection Established")  
            self.mqtt.loop_start()  
            return True  
        except Exception as e:  
            print(f"MQTT Connection Error: {e}")  
            cookie_attempts[self.cookie_hash]['count'] += 1  
            return False  

        self.cleanup_memory()  

    def stop(self):  
        if self.mqtt:  
            print("Stopping MQTT Client...")  
            try:  
                self.mqtt.disconnect()  
                self.mqtt.loop_stop()  
            except:  
                pass  

    def send_message(self, text=None, thread_id=None, attachment=None, mention=None, message_id=None, callback=None):  
        if self.mqtt is None:  
            print("Error: Not Connected To MQTT")  
            return False  

        if thread_id is None:  
            print("Error: Thread ID Is Required")  
            return False  

        if text is None and attachment is None:  
            print("Error: Text Or Attachment Is Required")  
            return False  

        self.cleanup_memory()  

        self.ws_req_number += 1  
        content = {  
            "app_id": "2220391788200892",  
            "payload": {  
                "data_trace_id": None,  
                "epoch_id": int(generate_offline_threading_id()),  
                "tasks": [],  
                "version_id": "7545284305482586",  
            },  
            "request_id": self.ws_req_number,  
            "type": 3,  
        }  

        text = str(text) if text is not None else ""  
        if len(text) > 0:  
            self.ws_task_number += 1  
            task_payload = {  
                "initiating_source": 0,  
                "multitab_env": 0,  
                "otid": generate_offline_threading_id(),  
                "send_type": 1,  
                "skip_url_preview_gen": 0,  
                "source": 0,  
                "sync_group": 1,  
                "text": text,  
                "text_has_links": 0,  
                "thread_id": int(thread_id),  
            }  

            if message_id is not None:  
                if not isinstance(message_id, str):  
                    raise ValueError("message_id must be a string")  
                task_payload["reply_metadata"] = {  
                    "reply_source_id": message_id,  
                    "reply_source_type": 1,  
                    "reply_type": 0,  
                }  

            task = {  
                "failure_count": None,  
                "label": "46",  
                "payload": json.dumps(task_payload, separators=(",", ":")),  
                "queue_name": str(thread_id),  
                "task_id": self.ws_task_number,  
            }  

            content["payload"]["tasks"].append(task)  

        self.ws_task_number += 1  
        task_mark_payload = {  
            "last_read_watermark_ts": int(time.time() * 1000),  
            "sync_group": 1,  
            "thread_id": int(thread_id),  
        }  

        task_mark = {  
            "failure_count": None,  
            "label": "21",  
            "payload": json.dumps(task_mark_payload, separators=(",", ":")),  
            "queue_name": str(thread_id),  
            "task_id": self.ws_task_number,  
        }  

        content["payload"]["tasks"].append(task_mark)  

        content["payload"] = json.dumps(content["payload"], separators=(",", ":"))  

        if callback is not None and callable(callback):  
            self.req_callbacks[self.ws_req_number] = callback  

        try:  
            self.mqtt.publish(  
                topic="/ls_req",  
                payload=json.dumps(content, separators=(",", ":")),  
                qos=1,  
                retain=False,  
            )  
            return True  
        except Exception as e:  
            print(f"Error Publishing Message: {e}")  
            return False

    def send_message(self, text=None, thread_id=None, attachment=None, mention=None, message_id=None, callback=None):  
        if self.mqtt is None:  
            print("Error: Not Connected To MQTT")  
            return False  

        if thread_id is None:  
            print("Error: Thread ID Is Required")  
            return False  

        if text is None and attachment is None:  
            print("Error: Text Or Attachment Is Required")  
            return False  

        self.cleanup_memory()  

        self.ws_req_number += 1  
        content = {  
            "app_id": "2220391788200892",  
            "payload": {  
                "data_trace_id": None,  
                "epoch_id": int(generate_offline_threading_id()),  
                "tasks": [],  
                "version_id": "7545284305482586",  
            },  
            "request_id": self.ws_req_number,  
            "type": 3,  
        }  

        text = str(text) if text is not None else ""  
        if len(text) > 0:  
            self.ws_task_number += 1  
            task_payload = {  
                "initiating_source": 0,  
                "multitab_env": 0,  
                "otid": generate_offline_threading_id(),  
                "send_type": 1,  
                "skip_url_preview_gen": 0,  
                "source": 0,  
                "sync_group": 1,  
                "text": text,  
                "text_has_links": 0,  
                "thread_id": int(thread_id),  
            }  

            if message_id is not None:  
                if not isinstance(message_id, str):  
                    raise ValueError("message_id must be a string")  
                task_payload["reply_metadata"] = {  
                    "reply_source_id": message_id,  
                    "reply_source_type": 1,  
                    "reply_type": 0,  
                }  

            task = {  
                "failure_count": None,  
                "label": "46",  
                "payload": json.dumps(task_payload, separators=(",", ":")),  
                "queue_name": str(thread_id),  
                "task_id": self.ws_task_number,  
            }  

            content["payload"]["tasks"].append(task)  

            
        self.ws_task_number += 1  
        task_mark_payload = {  
            "last_read_watermark_ts": int(time.time() * 1000),  
            "sync_group": 1,  
            "thread_id": int(thread_id),  
        }  

        task_mark = {  
            "failure_count": None,  
            "label": "21",  
            "payload": json.dumps(task_mark_payload, separators=(",", ":")),  
            "queue_name": str(thread_id),  
            "task_id": self.ws_task_number,  
        }  

        content["payload"]["tasks"].append(task_mark)  

        content["payload"] = json.dumps(content["payload"], separators=(",", ":"))  

        if callback is not None and callable(callback):  
            self.req_callbacks[self.ws_req_number] = callback  

        try:  
            self.mqtt.publish(  
                topic="/ls_req",  
                payload=json.dumps(content, separators=(",", ":")),  
                qos=1,  
                retain=False,  
            )  
            return True  
        except Exception as e:  
            print(f"Error Publishing Message: {e}")  
            return False
            

class nguyennhat:
    def __init__(self, cookie, mqtt_broker="broker.hivemq.com", mqtt_port=1883):
        self.cookie = cookie
        self.user_id = self.id_user()
        self.fb_dtsg = None
        self.jazoest = None
        self.rev = None
        self.init_params()

        # BỎ callback_api_version để không lỗi
        self.mqtt_client = mqtt.Client(
            client_id=f"messenger_{self.user_id}_{int(time.time())}"
        )
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_broker = mqtt_broker
        self.mqtt_port = mqtt_port
        self.mqtt_topic_base = "messenger/spam"

    def id_user(self):  
        try:  
            match = re.search(r"c_user=(\d+)", self.cookie)  
            if not match:  
                raise Exception("> Cookie không hợp lệ")  
            return match.group(1)  
        except Exception as e:  
            raise Exception(f"> Lỗi khi lấy user_id: {str(e)}")  

    def init_params(self):  
        headers = {  
            'Cookie': self.cookie,  
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',  
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',  
            'Accept-Language': 'en-US,en;q=0.5',  
            'Connection': 'keep-alive',  
            'Upgrade-Insecure-Requests': '1',  
            'Sec-Fetch-Dest': 'document',  
            'Sec-Fetch-Mode': 'navigate',  
            'Sec-Fetch-Site': 'none',  
            'Sec-Fetch-User': '?1'  
        }  
        result = get_fb_dtsg_from_cookie(self.cookie)  
        if result['success']:  
            self.fb_dtsg = result['fb_dtsg']  
            self.jazoest = result['jazoest']  
            self.rev = result['rev']  
            print(f"> Lấy được fb_dtsg: {self.fb_dtsg}, jazoest: {self.jazoest}, rev: {self.rev}")  
        else:  
            raise Exception("> Không thể lấy được fb_dtsg từ cookie")  

    def gui_tn(self, recipient_id, message):  
        if not self.fb_dtsg or not self.jazoest or not self.rev:  
            self.init_params()  
        timestamp = int(time.time() * 1000)  
        data = {  
            'thread_fbid': recipient_id,  
            'action_type': 'ma-type:user-generated-message',  
            'body': message,  
            'client': 'mercury',  
            'author': f'fbid:{self.user_id}',  
            'timestamp': timestamp,  
            'source': 'source:chat:web',  
            'offline_threading_id': str(timestamp),  
            'message_id': str(timestamp),  
            'ephemeral_ttl_mode': '',  
            '__user': self.user_id,  
            '__a': '1',  
            '__req': '1b',  
            '__rev': self.rev,  
            'fb_dtsg': self.fb_dtsg,  
            'jazoest': self.jazoest  
        }  

        headers = {  
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',  
            'Content-Type': 'application/x-www-form-urlencoded',  
            'Origin': 'https://www.facebook.com',  
            'Referer': f'https://www.facebook.com/messages/t/{recipient_id}',  
            'Cookie': self.cookie  
        }  

        try:  
            response = requests.post('https://www.facebook.com/messaging/send/', data=data, headers=headers, timeout=10)  
            if response.status_code != 200:  
                print(f"> Gửi thất bại. Status: {response.status_code}")  
                return {'success': False}  

            if 'for (;;);' in response.text:  
                json_data = json.loads(response.text.replace('for (;;);', ''))  
                if 'error' in json_data:  
                    print(f"> Lỗi từ Facebook: {json_data.get('errorDescription', 'Unknown error')}")  
                    return {'success': False}  

            print("> Messenger Sent .")  
            return {'success': True}  
        except Exception as e:  
            print(f"> :( : {str(e)}")  
            return {'success': False}  

    # Callback khi kết nối
    def on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print(f"[MQTT] Kết nối thành công tới broker: {self.mqtt_broker} (port {self.mqtt_port})!")
            client.subscribe(f"{self.mqtt_topic_base}/#", qos=1)
            print(f"[MQTT] Đã subscribe topic: {self.mqtt_topic_base}/#")
        else:
            print(f"[MQTT] Kết nối MQTT thất bại, mã lỗi: {rc}")

    # Callback khi nhận message
    def on_message(self, client, userdata, msg):
        try:
            topic = msg.topic
            payload = msg.payload.decode('utf-8')
            print(f"[MQTT] Nhận từ {topic}: {payload}")

            recipient_id = topic.split('/')[-1]
            message = json.loads(payload).get('message', '')
            if not message:
                print("[MQTT] Nội dung rỗng, bỏ qua.")
                return

            result = self.gui_tn(recipient_id, message)
            if result.get('success'):
                print(f"[MQTT] Gửi thành công tới {recipient_id}")
            else:
                print(f"[MQTT] Gửi thất bại tới {recipient_id}")

        except Exception as e:
            print(f"[MQTT] Lỗi xử lý message: {str(e)}")

    # Callback khi disconnect
    def on_disconnect(self, client, userdata, rc):
        print(f"[MQTT] Đã ngắt kết nối với broker (rc={rc})")
        if rc != 0:
            print("[MQTT] Mất kết nối bất thường. Đang thử reconnect...")
            try:
                client.reconnect()
            except Exception as e:
                print(f"[MQTT] Reconnect thất bại: {e}")
            
# Chỉnh sửa hàm send_messages_with_cookie để chỉ hỗ trợ option 1 (Treo Ngôn)
def send_messages_with_cookie(cookies, thread_ids, message_files, delay):
    global cookie_attempts, active_threads
    threads = []

    def process_single_cookie(cookie):
        cookie_hash = hashlib.md5(cookie.encode()).hexdigest()

        try:
            fb = nguyennhat(cookie)
            sender = MessageSender(fbTools({
                "FacebookID": fb.user_id,
                "fb_dtsg": fb.fb_dtsg,
                "clientRevision": fb.rev,
                "jazoest": fb.jazoest,
                "cookieFacebook": cookie
            }), {
                "FacebookID": fb.user_id,
                "fb_dtsg": fb.fb_dtsg,
                "clientRevision": fb.rev,
                "jazoest": fb.jazoest,
                "cookieFacebook": cookie
            }, fb)

            sender.get_last_seq_id()
            if not sender.connect_mqtt():
                return

            # Gửi xoay vòng lần lượt cho tất cả box
            while True:
                for thread_id in thread_ids:
                    content = ""
                    if message_files:
                        with open(message_files[0], 'r', encoding='utf-8') as f:
                            content = f.read().strip()

                    success = sender.send_message(content, thread_id)
                    print(f"Cookie {cookie_hash[:10]} - Gửi tin nhắn tới box {thread_id}: {'Thành công' if success else 'Thất bại'}")

                    time.sleep(delay)

        except Exception as e:
            print(f"Cookie {cookie_hash[:10]} - Lỗi: {e}")
            return

    for cookie in cookies:
        t = threading.Thread(target=process_single_cookie, args=(cookie,))
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def publish_messages(broker, port, topic_base, recipient_id, file_txt, delay):
    client = mqtt.Client(
        client_id=f"publisher_{int(time.time())}",
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    try:
        client.connect(broker, port, keepalive=60)
        topic = f"{topic_base}/{recipient_id}"

        print(f"> Publish tới {topic}...")  
        while True:  
            try:  
                with open(file_txt, 'r', encoding='utf-8') as f:  
                    message = f.read().strip()  

                if not message:  
                    print("> Nội dung rỗng, dừng.")  
                    break  

                payload = json.dumps({'message': message})  
                client.publish(topic, payload, qos=1)  
                print(f"> Đã publish: {message}")  

                sys.stdout.write("> Chờ.. ")  
                for _ in range(int(delay)):  
                    sys.stdout.write("Loading..")  
                    sys.stdout.flush()  
                    time.sleep(1)  
                sys.stdout.write("\n")  

            except Exception as e:  
                print(f"> Lỗi publish: {str(e)}")  
                time.sleep(delay)  

    except Exception as e:  
        print(f"> Lỗi kết nối publisher: {str(e)}")  
    finally:  
        client.disconnect()  
        print("> Ngắt kết nối publisher.")

if __name__ == "__main__":
    try:
        clr()
        print_banner()

        cookie_file = input("[ - ] File Cookies: ").strip()  

        num_threads = int(input("[ - ] Nhập số lượng ID: ").strip())  
        thread_ids = []  
        for i in range(num_threads):  
            thread_id = input(f"> ID {i+1} : ").strip()  
            if thread_id:  
                thread_ids.append(thread_id)  
          
        delay = float(input("> Delay : ").strip())  

        print("Tool By Nguyen Nhat @Sea")  
        file_txt = input("[ - ] File: ").strip()  
        if not os.path.isfile(file_txt):  
            print(f"> File không tồn tại: {file_txt}")  
            exit()  
        message_files = [file_txt]  

        if not os.path.isfile(cookie_file):  
            print(f"> File cookie không tồn tại: {cookie_file}")  
            exit()  

        if not thread_ids:  
            print("> Chưa nhập ID box nào.")  
            exit()  

        # Thay vì chỉ đọc cookies, giờ sẽ kiểm tra và lấy fb_dtsg cho tất cả  
        use_validation = input("> Bạn muốn check cookies hay không? (y/n): ").strip().lower()  
          
        if use_validation == 'y':  
            cookie_data_list = read_and_validate_cookies(cookie_file)  
            # Chuyển đổi về format cũ để tương thích  
            cookies = [data['cookie'] for data in cookie_data_list]  
            print(f"> Sẽ sử dụng {len(cookies)} cookies đã được kiểm tra.")  
        else:  
            cookies = read_cookies_from_file(cookie_file)  
            print(f"> Đã đọc {len(cookies)} cookie từ file (không kiểm tra trước).")  

        send_messages_with_cookie(  
            cookies,  
            thread_ids,  
            message_files,  
            delay  
        )  

    except KeyboardInterrupt:  
        print("STOP")  
    except Exception as e:  
        print(f"> Lỗi: {str(e)}")