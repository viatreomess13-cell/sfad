import discord
import json
import os
import asyncio
import aiofiles
import aiohttp
import asyncio
import random
from datetime import datetime
from discord.ext import commands, tasks
import gc
import threading
import time
import requests
from typing import Optional
import urllib
import re
from discord.ui import Button, View, Modal, TextInput
from discord import app_commands
from urllib.parse import urlparse
import random
import string
import uuid
import hashlib
import time
import signal
import os, json
import threading
import asyncio, aiohttp
import pkgutil, hashlib
import inspect, importlib, functools
import munch
import base64
import datetime
from bs4 import BeautifulSoup
from main.fb import *
from main import *
from main.client import *
import websockets
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

user_keys = {}
user_nhapkey_count = {}
scheduler = AsyncIOScheduler()

intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

active_senders = {}

def clr():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def extract_keys(html):
    soup = BeautifulSoup(html, 'html.parser')
    code_div = soup.find('div', class_='plaintext')
    if code_div:
        keys = [line.strip() for line in code_div.get_text().split('\n') if line.strip()]
        return keys
    return []

def decode_ascii_payload(payload_array):
    try:
        decoded_string = ''.join(chr(code) for code in payload_array)
        if not decoded_string.endswith('}'):
            open_braces = decoded_string.count('{')
            close_braces = decoded_string.count('}')
            if open_braces > close_braces:
                decoded_string += '}' * (open_braces - close_braces)
        return json.loads(decoded_string)
    except Exception as e:
        return f"Lỗi decode ASCII payload: {e}"


def check_task_limit():
    if not os.path.exists('data'):
        return 0
    
    task_count = 0
    for folder in os.listdir('data'):
        folder_path = f"data/{folder}"
        if os.path.isdir(folder_path) and os.path.exists(f"{folder_path}/luutru.txt"):
            task_count += 1
    
    return task_count

def load_config():
    if os.path.exists('config.json'):
        with open('config.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def save_config(config):
    with open('config.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)

def create_initial_config():
    token = input("Nhập Token Bot Discord Của Bạn > ")
    owner_vip_id = input("Nhập Owner VIP ID > ")
    prefix = input("Nhập Prefix Cho Bot > ")
    config = {
        "tokenbot": token,
        "prefix": prefix,
        "ownerVIP": owner_vip_id,
        "task": {}
    }
    save_config(config)
    return config


config = load_config()
if config:
    choice = input("Bạn Có Muốn Sử Dụng Lại Token, Owner VIP và Prefix Cũ Không (Y/N) > ").lower()
    if choice != 'y':
        config = create_initial_config()
else:
    config = create_initial_config()

bot = commands.Bot(command_prefix=config['prefix'], intents=intents)

if not os.path.exists('data'):
    os.makedirs('data')

@tasks.loop(minutes=5)
async def cleanup_memory():
    gc.collect()

def get_user_task_count(user_id: str):
    if not os.path.exists('data'):
        return 0
    
    count = 0
    user_id_str = str(user_id)
    
    for folder in os.listdir('data'):
        folder_path = f"data/{folder}"
        luutru_path = f"{folder_path}/luutru.txt"
        
        if os.path.isdir(folder_path) and os.path.exists(luutru_path):
            try:
                with open(luutru_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                parts = content.split(" | ")
                
                task_owner_id = None
                if len(parts) >= 5:
                    if parts[3] == "nhay_top_tag" and len(parts) >= 7:
                        task_owner_id = parts[6]
                    elif parts[3] == "nhay_zalo" and len(parts) >= 8:
                        task_owner_id = parts[4]
                    elif len(parts) >= 5:
                        task_owner_id = parts[4]

                if task_owner_id == user_id_str:
                    count += 1
            except Exception:
                continue
    return count

@tasks.loop(seconds=30)
async def heartbeat():
    try:
        await bot.change_presence(activity=discord.Game("Bot Active"))
    except:
        pass

def safe_thread_wrapper(func, *args):
    try:
        func(*args)
    except Exception as e:
        print(f"Thread error: {e}")
        folder_name = args[-1] if args else "unknown"
        folder_path = os.path.join("data", folder_name)
        if os.path.exists(folder_path):
            import shutil
            shutil.rmtree(folder_path)

class ZaloAPIException(Exception):
    pass

class LoginMethodNotSupport(ZaloAPIException):
    def __init__(self, message=None):
        self.message = message
        super().__init__(message)

class ZaloLoginError(ZaloAPIException):
    def __init__(self, message=None):
        self.message = message
        super().__init__(message)

class ZaloUserError(ZaloAPIException):
    def __init__(self, message=None):
        self.message = message
        super().__init__(message)

class EncodePayloadError(ZaloAPIException):
    def __init__(self, message=None):
        self.message = message
        super().__init__(message)

class DecodePayloadError(ZaloAPIException):
    def __init__(self, message=None):
        self.message = message
        super().__init__(message)

import enum

class Enum(enum.Enum):
    def __repr__(self):
        return "{}.{}".format(type(self).__name__, self.name)

class ThreadType(Enum):
    USER = 0
    GROUP = 1

class GroupEventType(Enum):
    JOIN = "join"
    LEAVE = "leave"
    UPDATE = "update"
    UNKNOWN = "unknown"
    REACTION = "reaction"
    NEW_LINK = "new_link"
    ADD_ADMIN = "add_admin"
    REMOVE_ADMIN = "remove_admin"
    JOIN_REQUEST = "join_request"
    BLOCK_MEMBER = "block_member"
    REMOVE_MEMBER = "remove_member"
    UPDATE_SETTING = "update_setting"

class EventType(Enum):
    REACTION = "reaction"

import time, datetime
import urllib.parse, json
import gzip, base64, zlib
from Crypto.Cipher import AES

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Not-A.Brand\";v=\"99\", \"Chromium\";v=\"124\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Linux\"",
    "origin": "https://chat.zalo.me",
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "Accept-Encoding": "gzip",
    "referer": "https://chat.zalo.me/",
    "accept-language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
}

COOKIES = {}

def now():
    return int(time.time() * 1000)

def formatTime(format, ftime=now()):
    dt = datetime.datetime.fromtimestamp(ftime / 1000)
    formatted_time = dt.strftime(format)
    return formatted_time

def getHeader(buffer):
    if len(buffer) < 4:
        raise ValueError("Invalid header")
    return [buffer[0], int.from_bytes(buffer[1:3], "little"), buffer[3]]

def getClientMessageType(msgType):
    if (msgType == "webchat"): return 1
    if (msgType == "chat.voice"): return 31
    if (msgType == "chat.photo"): return 32
    if (msgType == "chat.sticker"): return 36
    if (msgType == "chat.doodle"): return 37
    if (msgType == "chat.recommended"): return 38
    if (msgType == "chat.link"): return 38
    if (msgType == "chat.location.new"): return 43
    if (msgType == "chat.video.msg"): return 44
    if (msgType == "share.file"): return 46
    if (msgType == "chat.gif"): return 49
    return 1

def getGroupEventType(act):
    if (act == "join_request"): return GroupEventType.JOIN_REQUEST
    if (act == "join"): return GroupEventType.JOIN
    if (act == "leave"): return GroupEventType.LEAVE
    if (act == "remove_member"): return GroupEventType.REMOVE_MEMBER
    if (act == "block_member"): return GroupEventType.BLOCK_MEMBER
    if (act == "update_setting"): return GroupEventType.UPDATE_SETTING
    if (act == "update"): return GroupEventType.UPDATE
    if (act == "new_link"): return GroupEventType.NEW_LINK
    if (act == "add_admin"): return GroupEventType.ADD_ADMIN
    if (act == "remove_admin"): return GroupEventType.REMOVE_ADMIN
    return GroupEventType.UNKNOWN

def dict_to_raw_cookies(cookies_dict):
    try:
        cookie_string = "; ".join(f"{key}={value}" for key, value in cookies_dict.items())
        if not cookie_string:
            return None
        return cookie_string
    except:
        return None

def _pad(s, block_size):
    padding_length = block_size - len(s) % block_size
    return s + bytes([padding_length]) * padding_length

def _unpad(s, block_size):
    padding_length = s[-1]
    return s[:-padding_length]

def zalo_encode(params, key):
    try:
        key = base64.b64decode(key)
        iv = bytes.fromhex("00000000000000000000000000000000")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = json.dumps(params).encode()
        padded_plaintext = _pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return base64.b64encode(ciphertext).decode()
    except Exception as e:
        raise EncodePayloadError(f"Unable to encode payload! Error: {e}")

def zalo_decode(params, key):
    try:
        params = urllib.parse.unquote(params)
        key = base64.b64decode(key)
        iv = bytes.fromhex("00000000000000000000000000000000")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = base64.b64decode(params.encode())
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = _unpad(padded_plaintext, AES.block_size)
        plaintext = plaintext.decode("utf-8")
        if isinstance(plaintext, str):
            plaintext = json.loads(plaintext)
        return plaintext
    except Exception as e:
        raise DecodePayloadError(f"Unable to decode payload! Error: {e}")

class State(object):
    def __init__(cls):
        cls._config = {}
        cls._headers = HEADERS
        cls._cookies = COOKIES
        cls._session = requests.Session()
        cls.user_id = None
        cls.user_imei = None
        cls._loggedin = False

    def get_cookies(cls):
        return cls._cookies

    def set_cookies(cls, cookies):
        cls._cookies = cookies

    def get_secret_key(cls):
        return cls._config.get("secret_key")

    def set_secret_key(cls, secret_key):
        cls._config["secret_key"] = secret_key

    def _get(cls, *args, **kwargs):
        sessionObj = cls._session.get(*args, **kwargs, headers=cls._headers, cookies=cls._cookies)
        return sessionObj

    def _post(cls, *args, **kwargs):
        sessionObj = cls._session.post(*args, **kwargs, headers=cls._headers, cookies=cls._cookies)
        return sessionObj

    def is_logged_in(cls):
        return cls._loggedin

    def login(cls, phone, password, imei, session_cookies=None, user_agent=None):
        if cls._cookies and cls._config.get("secret_key"):
            cls._loggedin = True
            return

        if user_agent:
            cls._headers["User-Agent"] = user_agent

        if cls._cookies:
            params = {
                "imei": imei,
            }
            try:
                response = cls._get("https://lengocanh.vercel.app/zlapi/login", params=params)
                data = response.json()

                if data.get("error_code") == 0:
                    cls._config = data.get("data")

                    if cls._config.get("secret_key"):
                        cls._loggedin = True
                        cls.user_id = cls._config.get("send2me_id")
                        cls.user_imei = imei
                    else:
                        cls._loggedin = False
                        raise ZaloLoginError("Unable to get `secret key`.")
                else:
                    error = data.get("error_code")
                    content = data.get("error_message")
                    raise ZaloLoginError(f"Error #{error} when logging in: {content}")

            except ZaloLoginError as e:
                raise ZaloLoginError(str(e))

            except Exception as e:
                raise ZaloLoginError(f"An error occurred while logging in! {str(e)}")
        else:
            raise LoginMethodNotSupport("Login method is not supported yet")

class ZaloAPI(object):
    def __init__(self, phone, password, imei, session_cookies=None, user_agent=None, auto_login=True):
        self._state = State()
        self._condition = threading.Event()
        self._listening = False
        self._start_fix = False

        if auto_login:
            if (
                not session_cookies 
                or not self.setSession(session_cookies) 
                or not self.isLoggedIn()
            ):
                self.login(phone, password, imei, user_agent)

    def uid(self):
        return self.uid

    def _get(self, *args, **kwargs):
        return self._state._get(*args, **kwargs)

    def _post(self, *args, **kwargs):
        return self._state._post(*args, **kwargs)

    def _encode(self, params):
        return zalo_encode(params, self._state._config.get("secret_key"))

    def _decode(self, params):
        return zalo_decode(params, self._state._config.get("secret_key"))

    def isLoggedIn(self):
        return self._state.is_logged_in()

    def getSession(self):
        return self._state.get_cookies()

    def setSession(self, session_cookies):
        try:
            if not isinstance(session_cookies, dict):
                return False
            self._state.set_cookies(session_cookies)
            self.uid = self._state.user_id
        except Exception as e:
            print("Failed loading session")
            return False
        return True

    def getSecretKey(self):
        return self._state.get_secret_key()

    def setSecretKey(self, secret_key):
        try:
            self._state.set_secret_key(secret_key)
            return True
        except:
            return False

    def login(self, phone, password, imei, user_agent=None):
        if not (phone and password):
            raise ZaloUserError("Phone and password not set")

        self._state.login(
            phone,
            password,
            imei,
            user_agent=user_agent
        )
        try:
            self._imei = self._state.user_imei
            self.uid = self._state.user_id
        except:
            self._imei = None
            self.uid = self._state.user_id

    def setTyping(self, thread_id, thread_type):
        params = {
            "zpw_ver": 645,
            "zpw_type": 30
        }

        payload = {
            "params": {
                "imei": self._imei
            }
        }

        if thread_type == ThreadType.USER:
            url = "https://tt-chat1-wpa.chat.zalo.me/api/message/typing"
            payload["params"]["toid"] = str(thread_id)
            payload["params"]["destType"] = 3
        elif thread_type == ThreadType.GROUP:
            url = "https://tt-group-wpa.chat.zalo.me/api/group/typing"
            payload["params"]["grid"] = str(thread_id)
        else:
            raise ZaloUserError("Thread type is invalid")

        payload["params"] = self._encode(payload["params"])

        response = self._post(url, params=params, data=payload)
        data = response.json()
        results = data.get("data") if data.get("error_code") == 0 else None
        if results:
            results = self._decode(results)
            return True

        error_code = data.get("error_code")
        error_message = data.get("error_message") or data.get("data")
        raise ZaloAPIException(f"Error #{error_code} when sending requests: {error_message}")

    def sendMessage(self, message, thread_id, thread_type, mark_message=None, ttl=0):
        params = {
            "zpw_ver": 645,
            "zpw_type": 30,
            "nretry": 0
        }

        payload = {
            "params": {
                "message": message.text,
                "clientId": now(),
                "imei": self._imei,
                "ttl": ttl
            }
        }

        if mark_message and mark_message.lower() in ["important", "urgent"]:
            markType = 1 if mark_message.lower() == "important" else 2
            payload["params"]["metaData"] = {"urgency": markType}

        if message.style:
            payload["params"]["textProperties"] = message.style

        if thread_type == ThreadType.USER:
            url = "https://tt-chat2-wpa.chat.zalo.me/api/message/sms"
            payload["params"]["toid"] = str(thread_id)
        elif thread_type == ThreadType.GROUP:
            url = "https://tt-group-wpa.chat.zalo.me/api/group/sendmsg"
            payload["params"]["visibility"] = 0
            payload["params"]["grid"] = str(thread_id)
        else:
            raise ZaloUserError("Thread type is invalid")

        payload["params"] = self._encode(payload["params"])

        response = self._post(url, params=params, data=payload)
        data = response.json()
        results = data.get("data") if data.get("error_code") == 0 else None
        if results:
            results = self._decode(results)
            results = results.get("data") if results.get("data") else results
            if results == None:
                results = {"error_code": 1337, "error_message": "Data is None"}

            if isinstance(results, str):
                try:
                    results = json.loads(results)
                except:
                    results = {"error_code": 1337, "error_message": results}

            return results

        error_code = data.get("error_code")
        error_message = data.get("error_message") or data.get("data")
        raise ZaloAPIException(f"Error #{error_code} when sending requests: {error_message}")

class Message:
    def __init__(self, text="", style=None):
        self.text = text
        self.style = style

def get_guid():
    section_length = int(time.time() * 1000)
    
    def replace_func(c):
        nonlocal section_length
        r = (section_length + random.randint(0, 15)) % 16
        section_length //= 16
        return hex(r if c == "x" else (r & 7) | 8)[2:]

    return "".join(replace_func(c) if c in "xy" else c for c in "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx")

def get_info_from_uid(cookie, uid):
    user_id, fb_dtsg, jazoest, clientRevision, a, req = get_uid_fbdtsg(cookie)
    if user_id and fb_dtsg:
        fb = facebook(cookie)
        if fb.user_id and fb.fb_dtsg:
            return fb.get_info(uid)
    return {"name": "User", "id": uid}

def get_uid_fbdtsg(ck):
    try:
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,vi;q=0.8',
            'Connection': 'keep-alive',
            'Cookie': ck,
            'Host': 'www.facebook.com',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (like Gecko) Chrome/122.0.0.0 Safari/537.36'
        }
        
        try:
            response = requests.get('https://www.facebook.com/', headers=headers, timeout=30)
            
            if response.status_code != 200:
                print(f"Status Code >> {response.status_code}")
                return None, None, None, None, None, None
                
            html_content = response.text
            
            user_id = None
            fb_dtsg = None
            jazoest = None
            
            script_tags = re.findall(r'<script id="__eqmc" type="application/json[^>]*>(.*?)</script>', html_content)
            for script in script_tags:
                try:
                    json_data = json.loads(script)
                    if 'u' in json_data:
                        user_param = re.search(r'__user=(\d+)', json_data['u'])
                        if user_param:
                            user_id = user_param.group(1)
                            break
                except:
                    continue
            
            fb_dtsg_match = re.search(r'"f":"([^"]+)"', html_content)
            if fb_dtsg_match:
                fb_dtsg = fb_dtsg_match.group(1)
            
            jazoest_match = re.search(r'jazoest=(\d+)', html_content)
            if jazoest_match:
                jazoest = jazoest_match.group(1)
            
            revision_match = re.search(r'"server_revision":(\d+),"client_revision":(\d+)', html_content)
            rev = revision_match.group(1) if revision_match else ""
            
            a_match = re.search(r'__a=(\d+)', html_content)
            a = a_match.group(1) if a_match else "1"
            
            req = "1b"
                
            return user_id, fb_dtsg, rev, req, a, jazoest
                
        except requests.exceptions.RequestException as e:
            print(f"Lỗi Kết Nối Khi Lấy UID/FB_DTSG: {e}")
            return get_uid_fbdtsg(ck)
            
    except Exception as e:
        print(f"Lỗi: {e}")
        return None, None, None, None, None, None

def comment_group_post(cookie, group_id, post_id, message, uidtag=None, nametag=None):
    try:
        user_id, fb_dtsg, jazoest, rev, a, req = get_uid_fbdtsg(cookie)
        
        if not all([user_id, fb_dtsg, jazoest]):
            return False
            
        pstid_enc = base64.b64encode(f"feedback:{post_id}".encode()).decode()
        
        client_mutation_id = str(round(random.random() * 19))
        session_id = get_guid()
        crt_time = int(time.time() * 1000)
        
        variables = {
            "feedLocation": "DEDICATED_COMMENTING_SURFACE",
            "feedbackSource": 110,
            "groupID": group_id,
            "input": {
                "client_mutation_id": client_mutation_id,
                "actor_id": user_id,
                "attachments": None,
                "feedback_id": pstid_enc,
                "formatting_style": None,
                "message": {
                    "ranges": [],
                    "text": message
                },
                "attribution_id_v2": f"SearchCometGlobalSearchDefaultTabRoot.react,comet.search_results.default_tab,tap_search_bar,{crt_time},775647,391724414624676,,",
                "vod_video_timestamp": None,
                "is_tracking_encrypted": True,
                "tracking": [],
                "feedback_source": "DEDICATED_COMMENTING_SURFACE",
                "session_id": session_id
            },
            "inviteShortLinkKey": None,
            "renderLocation": None,
            "scale": 3,
            "useDefaultActor": False,
            "focusCommentID": None,
            "__relay_internal__pv__IsWorkUserrelayprovider": False
        }
        
        if uidtag and nametag:
            name_position = message.find(nametag)
            if name_position != -1:
                variables["input"]["message"]["ranges"] = [
                    {
                        "entity": {
                            "id": uidtag
                        },
                        "length": len(nametag),
                        "offset": name_position
                    }
                ]
            
        payload = {
            'av': user_id,
            '__crn': 'comet.fbweb.CometGroupDiscussionRoute',
            'fb_dtsg': fb_dtsg,
            'jazoest': jazoest,
            'fb_api_caller_class': 'RelayModern',
            'fb_api_req_friendly_name': 'useCometUFICreateCommentMutation',
            'variables': json.dumps(variables),
            'server_timestamps': 'true',
            'doc_id': '10047708791980503'
        }
        
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'identity',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': cookie,
            'Origin': 'https://www.facebook.com',
            'Referer': f'https://www.facebook.com/groups/{group_id}',
            'User-Agent': 'python-http/0.27.0'
        }
        
        response = requests.post('https://www.facebook.com/api/graphql', data=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        print(f"Lỗi khi gửi bình luận: {e}")
        return False

def gen_threading_id():
    return str(
        int(format(int(time.time() * 1000), "b") + 
        ("0000000000000000000000" + 
        format(int(random.random() * 4294967295), "b"))
        [-22:], 2)
    )

def restore_tasks():
    if not os.path.exists('data'):
        return
    for folder in os.listdir('data'):
        folder_path = f"data/{folder}"
        if os.path.isdir(folder_path) and os.path.exists(f"{folder_path}/luutru.txt"):
            try:
                with open(f"{folder_path}/luutru.txt", "r", encoding="utf-8") as f:
                    content = f.read().strip()
                parts = content.split(" | ")
                if len(parts) >= 4:
                    cookie = parts[0]
                    task_type = parts[3]
                    if task_type == "treo_media" and len(parts) >= 6:
                        idbox = parts[1]
                        delay = parts[2]
                        media_url = parts[5]
                        if os.path.exists(f"{folder_path}/messages.txt"):
                            with open(f"{folder_path}/messages.txt", "r", encoding="utf-8") as msg_f:
                                message = msg_f.read()
                            for file in os.listdir(folder_path):
                                if file not in ['luutru.txt', 'messages.txt']:
                                    local_file_path = os.path.join(folder_path, file)
                                    thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_media_func, cookie, idbox, local_file_path, message, delay, folder))
                                    thread.daemon = True
                                    thread.start()
                                    break
                    elif task_type == "treo_contact" and len(parts) >= 6:
                        idbox = parts[1]
                        delay = parts[2]
                        uid_contact = parts[5]
                        if os.path.exists(f"{folder_path}/messages.txt"):
                            with open(f"{folder_path}/messages.txt", "r", encoding="utf-8") as msg_f:
                                message = msg_f.read()
                            thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_contact_func, cookie, idbox, uid_contact, message, delay, folder))
                            thread.daemon = True
                            thread.start()
                    elif task_type == "treo_normal":
                        idbox = parts[1]
                        delay = parts[2]
                        if os.path.exists(f"{folder_path}/message.txt"):
                            with open(f"{folder_path}/message.txt", "r", encoding="utf-8") as msg_f:
                                message = msg_f.read()
                            thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_mess_func, cookie, idbox, message, delay, folder))
                            thread.daemon = True
                            thread.start()
                    elif task_type == "nhay_normal":
                        idbox = parts[1]
                        delay = parts[2]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_func, cookie, idbox, delay, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "nhay_tag" and len(parts) >= 6:
                        idbox = parts[1]
                        delay = parts[2]
                        uid_tag = parts[5]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_tag_func, cookie, idbox, uid_tag, delay, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "nhay_top_tag" and len(parts) >= 7:
                        group_id = parts[1]
                        post_id = parts[2]
                        uid_tag = parts[3]
                        delay = parts[4]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_top_tag_func, cookie, group_id, post_id, uid_tag, delay, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "treoso":
                        idbox = parts[1]
                        delay = parts[2]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_treoso_func, cookie, idbox, delay, folder))
                        thread.daemon = True
                        thread.start()    
                    elif task_type == "nhay_poll":
                        idbox = parts[1]
                        delay = parts[2]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_poll_func, cookie, idbox, delay, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "nhay_namebox":
                        idbox = parts[1]
                        delay = parts[2]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_namebox_func, cookie, idbox, delay, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "nhay_zalo" and len(parts) >= 8:
                        thread_id = parts[1]
                        delay = parts[2]
                        imei = parts[5]
                        session_cookies = parts[6]
                        thread_type = parts[7]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_zalo_func, imei, session_cookies, thread_id, delay, thread_type, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "nhay_discord" and len(parts) >= 6:
                        channel_id = parts[1]
                        delay = parts[2]
                        tokens = parts[5]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_discord_func, tokens, channel_id, delay, folder))
                        thread.daemon = True
                        thread.start()
                    elif task_type == "nhay_tag_discord" and len(parts) >= 7:
                        channel_id = parts[1]
                        delay = parts[2]
                        tokens = parts[5]
                        uid_mention = parts[6]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_tag_discord_func, tokens, channel_id, uid_mention, delay, folder))
                    elif task_type == "treo_discord" and len(parts) >= 7:
                        channel_id = parts[1]
                        delay = parts[2]
                        tokens = parts[5]
                        message = parts[6]
                        thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_discord_func, tokens, channel_id, message, delay, folder))
                        thread.daemon = True
                        thread.start()

                    print(f"Đã Khôi Phục Task: {folder} - {task_type}")
            except Exception as e:
                print(f"Lỗi khi khôi phục task {folder}: {e}")

import warnings
warnings.simplefilter("always")

def send_msg(token, channel_id, message):
    try:
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json'
        }
        payload = {
            'content': message
        }
        url = f'https://discord.com/api/v10/channels/{channel_id}/messages'
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        print(f"Send Message - Status: {response.status_code}")
        if response.status_code not in [200, 201]:
            print(f"Error response: {response.text}")
        
        return response.status_code
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

def faketyping_discord(token, channel_id):
    try:
        headers = {
            'Authorization': token,
            'Content-Type': 'application/json'
        }
        url = f'https://discord.com/api/v10/channels/{channel_id}/typing'
        response = requests.post(url, headers=headers, timeout=10)
        
        return response.status_code
    except Exception as e:
        print(f"Error sending typing: {e}")
        return None

def start_nhay_zalo_func(imei, session_cookies, thread_id, delay_str, thread_type, folder_name):
    delay = float(delay_str)
    folder_path = os.path.join("data", folder_name)
    
    try:
        zalo = ZaloAPI(
            phone="",
            password="", 
            imei=imei,
            session_cookies=session_cookies,
            auto_login=True
        )
        
        if not zalo.isLoggedIn():
            pass
            return
            
        if thread_type == "1":
            thread_type_enum = ThreadType.GROUP
        else:
            thread_type_enum = ThreadType.USER
            
        running = True
        while running:
            try:
                folder_path = os.path.join("data", folder_name)
                if not os.path.exists(folder_path):
                    running = False
                    break
                    
                current_dir = os.path.dirname(os.path.abspath(__file__))
                nhay_path = os.path.join(current_dir, "nhay.txt")
                
                if not os.path.exists(nhay_path):
                    with open(nhay_path, "w", encoding="utf-8") as f:
                        f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
                
                with open(nhay_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    
                for line in lines:
                    folder_path = os.path.join("data", folder_name)
                    if not os.path.exists(folder_path):
                        running = False
                        break
                        
                    msg = line.strip()
                    if msg:
                        zalo.setTyping(thread_id, thread_type_enum)
                        time.sleep(1)
                        
                        from main.zalo_utils import Message
                        message = Message(text=msg)
                        zalo.sendMessage(message, thread_id, thread_type_enum)
                        
                        time.sleep(delay)
                        
            except Exception as e:
                print(f"Error during nhây zalo: {e}")
                time.sleep(10)
                
    except Exception as e:
        print(f"Error initializing Zalo API: {e}")

def start_treo_media_func(cookie, idbox, file_path, ngon, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
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
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    print("Failed to connect MQTT, retrying...")
                    retry_count += 1
                    time.sleep(10)
                    continue
                
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        sender.send_message_with_attachment(ngon, idbox, file_path)
                        time.sleep(delay)
                    except Exception as e:
                        print(f"Error during sending message with media: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

def mainRequests(url, data, cookie):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'vi,en-US;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://www.facebook.com',
        'Cookie': cookie,
        'Referer': 'https://www.facebook.com/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }
    return {
        'url': url,
        'data': data,
        'headers': headers,
        'timeout': 30
    }

def tenbox(newTitle, threadID, dataFB):
    if not newTitle or not threadID or not dataFB:
        return {
            "success": False,
            "error": "Thiếu thông tin bắt buộc: newTitle, threadID, hoặc dataFB"
        }
    try:
        messageAndOTID = gen_threading_id()
        current_timestamp = int(time.time() * 1000)
        form_data = {
            "client": "mercury",
            "action_type": "ma-type:log-message",
            "author": f"fbid:{dataFB['FacebookID']}",
            "thread_id": str(threadID),
            "timestamp": current_timestamp,
            "timestamp_relative": str(int(time.time())),
            "source": "source:chat:web",
            "source_tags[0]": "source:chat",
            "offline_threading_id": messageAndOTID,
            "message_id": messageAndOTID,
            "threading_id": gen_threading_id(),
            "thread_fbid": str(threadID),
            "thread_name": str(newTitle),
            "log_message_type": "log:thread-name",
            "fb_dtsg": dataFB["fb_dtsg"],
            "jazoest": dataFB["jazoest"],
            "__user": str(dataFB["FacebookID"]),
            "__a": "1",
            "__req": "1",
            "__rev": dataFB.get("clientRevision", "1015919737")
        }
        url = "https://www.facebook.com/messaging/set_thread_name/"
        response = requests.post(**mainRequests(url, form_data, dataFB["cookieFacebook"]))
        if response.status_code == 200:
            try:
                response_data = response.json()
                if "error" in response_data:
                    return {
                        "success": False
                    }
                return {
                    "success": True
                }
            except:
                return {
                    "success": True
                }
        else:
            return {
                "success": False,
                "error": f"HTTP Error: {response.status_code}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def start_treo_discord_func(tokens, channel_id, message, delay_str, folder_name):
    delay = float(delay_str)
    folder_path = os.path.join("data", folder_name)
    
    token_list = [token.strip() for token in tokens.split('\n') if token.strip()]
    valid_tokens = []
    
    running = True
    while running:
        try:
            folder_path = os.path.join("data", folder_name)
            if not os.path.exists(folder_path):
                running = False
                break
            
            for token in token_list:
                if token not in valid_tokens:
                    status = faketyping_discord(token, channel_id)  #check statúe
                    if status in [200, 201, 204]:
                        valid_tokens.append(token)
                    elif status in [400, 401, 403]:
                        continue
            
            for token in valid_tokens:
                folder_path = os.path.join("data", folder_name)
                if not os.path.exists(folder_path):
                    running = False
                    break
                
                
                send_msg(token, channel_id, message)
                time.sleep(delay)
                
        except Exception as e:
            print(f"Error in treo discord: {e}")
            time.sleep(10)

def start_nhay_discord_func(tokens, channel_id, delay_str, folder_name):
    delay = float(delay_str)
    folder_path = os.path.join("data", folder_name)
    
    token_list = [token.strip() for token in tokens.split('\n') if token.strip()]
    valid_tokens = []
    
    running = True
    while running:
        try:
            folder_path = os.path.join("data", folder_name)
            if not os.path.exists(folder_path):
                running = False
                break
            
            for token in token_list:
                if token not in valid_tokens:
                    status = faketyping_discord(token, channel_id)
                    if status in [200, 201, 204]:
                        valid_tokens.append(token)
                    elif status in [400, 401, 403]:
                        continue
            
            current_dir = os.path.dirname(os.path.abspath(__file__))
            nhay_path = os.path.join(current_dir, "nhay.txt")
            
            if not os.path.exists(nhay_path):
                with open(nhay_path, "w", encoding="utf-8") as f:
                    f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
            
            with open(nhay_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            for line in lines:
                folder_path = os.path.join("data", folder_name)
                if not os.path.exists(folder_path):
                    running = False
                    break
                
                msg = line.strip()
                if msg:
                    for token in valid_tokens:
                        faketyping_discord(token, channel_id)
                        time.sleep(1)
                        send_msg(token, channel_id, msg)
                        time.sleep(delay)
                        
        except Exception as e:
            print(f"Error in nhay discord: {e}")
            time.sleep(10)


def start_nhay_tag_discord_func(tokens, channel_id, uid_mention, delay_str, folder_name):
    delay = float(delay_str)
    folder_path = os.path.join("data", folder_name)
    
    token_list = [token.strip() for token in tokens.split('\n') if token.strip()]
    valid_tokens = []
    
    running = True
    while running:
        try:
            folder_path = os.path.join("data", folder_name)
            if not os.path.exists(folder_path):
                running = False
                break
            
            for token in token_list:
                if token not in valid_tokens:
                    status = faketyping_discord(token, channel_id)
                    if status in [200, 201, 204]:
                        valid_tokens.append(token)
                    elif status in [400, 401, 403]:
                        continue
            
            current_dir = os.path.dirname(os.path.abspath(__file__))
            nhay_path = os.path.join(current_dir, "nhay.txt")
            
            if not os.path.exists(nhay_path):
                with open(nhay_path, "w", encoding="utf-8") as f:
                    f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
            
            with open(nhay_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            for line in lines:
                folder_path = os.path.join("data", folder_name)
                if not os.path.exists(folder_path):
                    running = False
                    break
                
                msg = line.strip()
                if msg:
                    for token in valid_tokens:
                        faketyping_discord(token, channel_id)
                        time.sleep(1)
                        
                        import random
                        tagged_msg = random.choice([f"{msg} <@{uid_mention}>", f"<@{uid_mention}> {msg}"])
                        send_msg(token, channel_id, tagged_msg)
                        time.sleep(delay)
                        
        except Exception as e:
            print(f"Error in nhay tag discord: {e}")
            time.sleep(10)

def start_nhay_namebox_func(cookie, idbox, delay_str, folder_name):
    delay = float(delay_str)
    folder_path = os.path.join("data", folder_name)
    running = True
    
    while running:
        if not os.path.exists(folder_path):
            break
        try:
            user_id, fb_dtsg, jazoest, rev, a, req = get_uid_fbdtsg(cookie)
            if not all([user_id, fb_dtsg, jazoest]):
                time.sleep(10)
                continue
                
            dataFB = {
                "FacebookID": user_id,
                "fb_dtsg": fb_dtsg,
                "jazoest": jazoest,
                "clientRevision": rev,
                "cookieFacebook": cookie
            }
            
            current_dir = os.path.dirname(os.path.abspath(__file__))
            nhay_path = os.path.join(current_dir, "nhay.txt")
            with open(nhay_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines:
                folder_path = os.path.join("data", folder_name)
                if not os.path.exists(folder_path):
                    running = False
                    break
                msg = line.strip()
                if msg:
                    result = tenbox(msg, idbox, dataFB)
                    if result["success"]:
                        print(f"Đổi tên thành công: {msg}")
                    else:
                        print(f"Lỗi đổi tên: {result['error']}")
                    time.sleep(delay)
        except Exception as e:
            print(f"Error in start_nhay_namebox_func: {e}")
            time.sleep(10)

class TreoDiscordModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Treo Discord", timeout=None)
        self.tokens = discord.ui.TextInput(
            label="Nhập User Token",
            placeholder="1 Token 1 Dòng Nếu Treo Đa Token",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.tokens)
        
        self.channel_id = discord.ui.TextInput(
            label="Nhập ID Kênh",
            required=True
        )
        self.add_item(self.channel_id)
        
        self.content = discord.ui.TextInput(
            label="Nhập Nội Dung",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.content)
        
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"discord_tokens | {self.channel_id.value} | {self.delay.value} | treo_discord | {interaction.user.id} | {self.tokens.value} | {self.content.value}")

        thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_discord_func, self.tokens.value, self.channel_id.value, self.content.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()

        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class NhayDiscordModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Discord", timeout=None)
        self.tokens = discord.ui.TextInput(
            label="Nhập User Token",
            placeholder="1 Token 1 Dòng Nếu Treo Đa Token",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.tokens)
        
        self.channel_id = discord.ui.TextInput(
            label="Nhập ID Kênh",
            required=True
        )
        self.add_item(self.channel_id)
        
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"discord_tokens | {self.channel_id.value} | {self.delay.value} | nhay_discord | {interaction.user.id} | {self.tokens.value}")

        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")

        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_discord_func, self.tokens.value, self.channel_id.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()

        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class NhayTagDiscordModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Tag Discord", timeout=None)
        self.tokens = discord.ui.TextInput(
            label="Nhập User Token",
            placeholder="1 Token 1 Dòng Nếu Treo Đa Token",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.tokens)
        
        self.channel_id = discord.ui.TextInput(
            label="Nhập ID Kênh",
            required=True
        )
        self.add_item(self.channel_id)
        
        self.uid_mention = discord.ui.TextInput(
            label="Nhập UID Cần Mention",
            required=True
        )
        self.add_item(self.uid_mention)
        
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"discord_tokens | {self.channel_id.value} | {self.delay.value} | nhay_tag_discord | {interaction.user.id} | {self.tokens.value} | {self.uid_mention.value}")

        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")

        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_tag_discord_func, self.tokens.value, self.channel_id.value, self.uid_mention.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()

        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class TreoSoModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Treo Sớ", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
           
        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path, exist_ok=True)
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | treoso | {interaction.user.id}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "so.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
        thread = threading.Thread(target=safe_thread_wrapper, args=(start_treoso_func, self.cookies.value, self.idbox.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()
        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class TreoSoView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
        
        return True

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary, emoji="🚀")
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TreoSoModal()
        await interaction.response.send_modal(modal)

class NhayNameBoxModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Name Box", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)

        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)

        self.delay = discord.ui.TextInput(
            label="Nhập Delay (>= 3 giây)",
            required=True,
            placeholder="Ví dụ: 3"
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            delay_value = float(self.delay.value)
            if delay_value < 3:
                await interaction.response.send_message(
                    "❌ Delay Phải Lớn Hơn 3s Hoặc Bằng 3s.", ephemeral=True
                )
                return
        except ValueError:
            await interaction.response.send_message(
                "❌ Delay Phải Là 1 Con Số Hợp Lệ.", ephemeral=True
            )
            return

        current_tasks = check_task_limit()
        if current_tasks >= 150:
            embed = discord.Embed(
                title="Bot Đã Đạt Giới Hạn 150/150 Tab Vui Lòng Đợi Người Khác Xóa Tab Hoặc Xóa Tab Nào Đó Bạn Không Dùng Để Có Thể Chạy Tiếp",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | nhay_namebox | {interaction.user.id}")

        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")

        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_namebox_func, self.cookies.value, self.idbox.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()

        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)



class NhayNameBoxView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
        
        return True

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary)
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayNameBoxModal()
        await interaction.response.send_modal(modal)

def start_treo_contact_func(cookie, idbox, contact_uid, ngon, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
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
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    print("Failed to connect MQTT, retrying...")
                    retry_count += 1
                    time.sleep(10)
                    continue
                
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        sender.share_contact(ngon, contact_uid, idbox)
                        time.sleep(delay)
                    except Exception as e:
                        print(f"Error during sharing contact: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

def start_treo_mess_func(cookie, idbox, ngon, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
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
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    print("Failed to connect MQTT, retrying...")
                    retry_count += 1
                    time.sleep(10)
                    continue
                    
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        sender.send_message(ngon, idbox)
                        time.sleep(delay)
                    except Exception as e:
                        print(f"Error during sending message: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

def start_nhay_func(cookie, idbox, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
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
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    print("Failed to connect MQTT, retrying...")
                    retry_count += 1
                    time.sleep(10)
                    continue
                
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        current_dir = os.path.dirname(os.path.abspath(__file__))
                        nhay_path = os.path.join(current_dir, "nhay.txt")
                        with open(nhay_path, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        for line in lines:
                            folder_path = os.path.join("data", folder_name)
                            if not os.path.exists(folder_path):
                                running = False
                                break
                            msg = line.strip()
                            if msg:
                                sender.send_typing_indicator(idbox)
                                sender.send_message(msg, idbox)
                                time.sleep(delay)
                    except Exception as e:
                        print(f"Error During Nhây Message: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error Initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

def start_nhay_tag_func(cookie, idbox, uid_tag, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
                uid = uid_tag
                user_info = fb.get_info(uid)
                ten = user_info.get("name", "User")
                facebook_data = {
                    "FacebookID": fb.user_id,
                    "fb_dtsg": fb.fb_dtsg,
                    "clientRevision": fb.rev,
                    "jazoest": fb.jazoest,
                    "cookieFacebook": cookie
                }
                sender = MessageSender(fbTools(facebook_data), facebook_data, fb)
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    print("Failed to connect MQTT, retrying...")
                    retry_count += 1
                    time.sleep(10)
                    continue
                
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        current_dir = os.path.dirname(os.path.abspath(__file__))
                        nhay_path = os.path.join(current_dir, "nhay.txt")
                        with open(nhay_path, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        for line in lines:
                            folder_path = os.path.join("data", folder_name)
                            if not os.path.exists(folder_path):
                                running = False
                                break
                            msg = line.strip()
                            if msg:
                                msg_with_tag = random.choice([f"{ten} {msg}", f"{msg} {ten}"])
                                mention = {"id": uid, "tag": ten}
                                sender.send_typing_indicator(idbox)
                                sender.send_message(text=msg_with_tag, mention=mention, thread_id=idbox)
                                time.sleep(delay)
                    except Exception as e:
                        print(f"Error During Nhây Tag Message: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error Initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

def start_nhay_top_tag_func(cookie, group_id, post_id, uid_tag, delay_str, folder_name):
    delay = float(delay_str)
    folder_path = os.path.join("data", folder_name)
    user_info = get_info_from_uid(cookie, uid_tag)
    ten_tag = user_info.get("name", "User")
    running = True
    
    while running:
        if not os.path.exists(folder_path):
            break
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            nhay_path = os.path.join(current_dir, "nhay.txt")
            with open(nhay_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines:
                if not os.path.exists(folder_path):
                    running = False
                    break
                msg = line.strip()
                if msg:
                    msg_with_tag = random.choice([f"{ten_tag} {msg}", f"{msg} {ten_tag}"])
                    comment_group_post(cookie, group_id, post_id, msg_with_tag, uid_tag, ten_tag)
                    time.sleep(delay)
        except Exception as e:
            print(f"Error in start_nhay_top_tag_func: {e}")
            time.sleep(10)

def start_treoso_func(cookie, idbox, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
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
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    print("Failed to connect MQTT, retrying...")
                    retry_count += 1
                    time.sleep(10)
                    continue
                
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        current_dir = os.path.dirname(os.path.abspath(__file__))
                        nhay_path = os.path.join(current_dir, "so.txt")
                        with open(nhay_path, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        for line in lines:
                            folder_path = os.path.join("data", folder_name)
                            if not os.path.exists(folder_path):
                                running = False
                                break
                            msg = line.strip()
                            if msg:
                                sender.send_typing_indicator(idbox)
                                sender.send_message(msg, idbox)
                                time.sleep(delay)
                    except Exception as e:
                        print(f"Error During Nhây Message: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error Initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

def start_nhay_poll_func(cookie, idbox, delay_str, folder_name):
    delay = float(delay_str)
    retry_count = 0
    max_retries = 3
    
    while retry_count < max_retries:
        try:
            fb = facebook(cookie)
            if fb.user_id and fb.fb_dtsg:
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
                
                active_senders[folder_name] = sender
                sender.get_last_seq_id()
                
                if not sender.connect_mqtt():
                    retry_count += 1
                    time.sleep(10)
                    continue
                
                current_dir = os.path.dirname(os.path.abspath(__file__))
                nhay_path = os.path.join(current_dir, "nhay.txt")
                if not os.path.exists(nhay_path):
                    with open(nhay_path, "w", encoding="utf-8") as f:
                        f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
                
                running = True
                while running:
                    try:
                        folder_path = os.path.join("data", folder_name)
                        if not os.path.exists(folder_path):
                            running = False
                            break
                        
                        with open(nhay_path, "r", encoding="utf-8") as f:
                            lines = [line.strip() for line in f.readlines() if line.strip()]
                        
                        if len(lines) < 3:
                            time.sleep(delay)
                            continue
                        
                        for line in lines:
                            folder_path = os.path.join("data", folder_name)
                            if not os.path.exists(folder_path):
                                running = False
                                break
                            
                            title = line.strip()
                            if title:
                                available_options = [opt for opt in lines if opt != title]
                                if len(available_options) >= 2:
                                    options = random.sample(available_options, 2)
                                else:
                                    options = available_options + random.choices(lines, k=2-len(available_options))
                                
                                sender.ws_req_number += 1
                                sender.ws_task_number += 1
                                
                                task_payload = {
                                    "question_text": title,
                                    "thread_key": int(idbox),
                                    "options": options,
                                    "sync_group": 1,
                                }
                                
                                task = {
                                    "failure_count": None,
                                    "label": "163",
                                    "payload": json.dumps(task_payload, separators=(",", ":")),
                                    "queue_name": "poll_creation",
                                    "task_id": sender.ws_task_number,
                                }
                                
                                content = {
                                    "app_id": "2220391788200892",
                                    "payload": {
                                        "data_trace_id": None,
                                        "epoch_id": int(generate_offline_threading_id()),
                                        "tasks": [task],
                                        "version_id": "7158486590867448",
                                    },
                                    "request_id": sender.ws_req_number,
                                    "type": 3,
                                }
                                
                                content["payload"] = json.dumps(content["payload"], separators=(",", ":"))
                                
                                try:
                                    sender.mqtt.publish(
                                        topic="/ls_req",
                                        payload=json.dumps(content, separators=(",", ":")),
                                        qos=1,
                                        retain=False,
                                    )
                                except Exception as e:
                                    print(f"Error publishing poll: {e}")
                                
                                time.sleep(delay)
                    except Exception as e:
                        print(f"Error during nhây poll: {e}")
                        if "connection" in str(e).lower():
                            break
                        time.sleep(10)
                
                if folder_name in active_senders:
                    active_senders[folder_name].stop()
                    del active_senders[folder_name]
                break
                
        except Exception as e:
            print(f"Error initializing Facebook API: {e}")
            retry_count += 1
            time.sleep(10)

class MetaAI:
    def __init__(self):
        self.session = requests.Session()
        self.access_token = None
        self.cookies = {}
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            'sec-ch-ua-platform': "\"Windows\"",
            'sec-ch-ua': "\"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
            'sec-ch-ua-mobile': "?0",
            'origin': "https://www.meta.ai",
            'sec-fetch-site': "same-site",
            'sec-fetch-mode': "cors",
            'sec-fetch-dest': "empty",
            'referer': "https://www.meta.ai/",
            'accept-language': "vi-VN,vi;q=0.9",
            'priority': "u=1, i",
        }
    
    def extract_value(self, text: str, start_str: str, end_str: str) -> str:
        try:
            start = text.index(start_str) + len(start_str)
            end = text.index(end_str, start)
            return text[start:end]
        except ValueError:
            return ""
    
    def extract_chat(self, response_text: str) -> Dict[str, str]:
        try:
            latest_messages = {
                "user": "",
                "assistant": ""
            }
            
            lines = response_text.strip().split('\n')
            for line in reversed(lines):
                if not line.strip():
                    continue
                    
                try:
                    json_data = json.loads(line)
                    
                    if "data" not in json_data:
                        continue
                        
                    node = json_data.get("data", {}).get("node", {})
                    if not node:
                        continue

                    user_msg = node.get("user_request_message", {})
                    if user_msg and "snippet" in user_msg and not latest_messages["user"]:
                        latest_messages["user"] = user_msg["snippet"]
              
                    bot_msg = node.get("bot_response_message", {})
                    if bot_msg and "snippet" in bot_msg:
                        if bot_msg.get("streaming_state") == "OVERALL_DONE":
                            content = bot_msg["snippet"].replace("**", "").strip()
                            if content and not latest_messages["assistant"]:
                                latest_messages["assistant"] = content
                                break
                            
                except json.JSONDecodeError:
                    continue
                    
            return latest_messages
                
        except Exception as e:
            print(f"Error parsing chat: {str(e)}")
            return {"user": "", "assistant": ""}
    
    def initialize_session(self) -> bool:
        try:
            response = self.session.get('https://meta.ai', headers=self.headers)
            __csr = self.extract_value(response.text, '"client_revision":', ',"')
            
            self.cookies = {
                "_js_datr": self.extract_value(response.text, '_js_datr":{"value":"', '",'),
                "datr": self.extract_value(response.text, 'datr":{"value":"', '",'),
                "lsd": self.extract_value(response.text, '"LSD",[],{"token":"', '"}'),
                "fb_dtsg": self.extract_value(response.text, 'DTSGInitData",[],{"token":"', '"'),
                "abra_csrf": self.extract_value(response.text, 'abra_csrf":{"value":"', '",')
            }

            url = "https://www.meta.ai/api/graphql/"
            payload = {
                "lsd": self.cookies["lsd"],
                "fb_api_caller_class": "RelayModern",
                "fb_api_req_friendly_name": "useAbraAcceptTOSForTempUserMutation",
                "variables": {
                    "dob": "1999-01-01",
                    "icebreaker_type": "TEXT",
                    "__relay_internal__pv__WebPixelRatiorelayprovider": 1,
                },
                "doc_id": "7604648749596940",
            }

            payload = urllib.parse.urlencode(payload)
            headers = {
                "content-type": "application/x-www-form-urlencoded",
                "cookie": f'_js_datr={self.cookies["_js_datr"]}; abra_csrf={self.cookies["abra_csrf"]}; datr={self.cookies["datr"]};',
                "sec-fetch-site": "same-origin",
                "x-fb-friendly-name": "useAbraAcceptTOSForTempUserMutation",
            }
            
            response = self.session.post(url, headers=headers, data=payload)
            auth_json = response.json()
            self.access_token = auth_json["data"]["xab_abra_accept_terms_of_service"]["new_temp_user_auth"]["access_token"]
            
            return True
            
        except Exception as e:
            print(f"Error initializing session: {str(e)}")
            return False
    
    def ask_question(self, question: str) -> Optional[str]:
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                if not self.access_token:
                    if not self.initialize_session():
                        return None
                
                url = "https://graph.meta.ai/graphql?locale=user"
                payload = {
                    'av': '0',
                    'access_token': self.access_token,
                    '__user': '0',
                    '__a': '1',
                    '__req': '5',
                    '__hs': '20139.HYP:abra_pkg.2.1...0',
                    'dpr': '1',
                    '__ccg': 'GOOD',
                    '__rev': '1020250634',
                    '__s': 'ukq0lm:22y2yf:rx88gm',
                    '__hsi': '7473469487460105169',
                    '__dyn': '7xeUmwlEnwn8K2Wmh0no6u5U4e0yoW3q32360CEbo19oe8hw2nVE4W099w8G1Dz81s8hwnU2lwv89k2C1Fwc60D85m1mzXwae4UaEW4U2FwNwmE2eU5O0EoS0raazo11E2ZwrUdUco9E3Lwr86C1nw4xxW2W5-fwmU3yw',
                    '__csr': '',
                    '__comet_req': '46',
                    'lsd': self.cookies['lsd'],
                    'jazoest': '',
                    '__spin_r': '1020250634',
                    '__spin_b': 'trunk',
                    '__spin_t': str(int(time.time() * 1000)),
                    '__jssesw': '1',
                    'fb_api_caller_class': 'RelayModern',
                    'fb_api_req_friendly_name': 'useAbraSendMessageMutation',
                    'variables': json.dumps({
                        "message": {"sensitive_string_value": question},
                        "externalConversationId": str(uuid.uuid4()),
                        "offlineThreadingId": str(int(time.time() * 1000)),
                        "suggestedPromptIndex": None,
                        "flashVideoRecapInput": {"images": []},
                        "flashPreviewInput": None,
                        "promptPrefix": None,
                        "entrypoint": "ABRA__CHAT__TEXT",
                        "icebreaker_type": "TEXT_V2",
                        "attachments": [],
                        "attachmentsV2": [],
                        "activeMediaSets": None,
                        "activeCardVersions": [],
                        "activeArtifactVersion": None,
                        "userUploadEditModeInput": None,
                        "reelComposeInput": None,
                        "qplJoinId": "fc43f4e563f41b383",
                        "gkAbraArtifactsEnabled": False,
                        "model_preference_override": None,
                        "threadSessionId": str(uuid.uuid4()),
                        "__relay_internal__pv__AbraPinningConversationsrelayprovider": False,
                        "__relay_internal__pv__AbraArtifactsEnabledrelayprovider": False,
                        "__relay_internal__pv__WebPixelRatiorelayprovider": 1,
                        "__relay_internal__pv__AbraSearchInlineReferencesEnabledrelayprovider": True,
                        "__relay_internal__pv__AbraComposedTextWidgetsrelayprovider": False,
                        "__relay_internal__pv__AbraSearchReferencesHovercardEnabledrelayprovider": True,
                        "__relay_internal__pv__AbraCardNavigationCountrelayprovider": True,
                        "__relay_internal__pv__AbraDebugDevOnlyrelayprovider": False,
                        "__relay_internal__pv__AbraHasNuxTourrelayprovider": True,
                        "__relay_internal__pv__AbraQPSidebarNuxTriggerNamerelayprovider": "meta_dot_ai_abra_web_message_actions_sidebar_nux_tour",
                        "__relay_internal__pv__AbraSurfaceNuxIDrelayprovider": "12177",
                        "__relay_internal__pv__AbraFileUploadsrelayprovider": False,
                        "__relay_internal__pv__AbraQPDocUploadNuxTriggerNamerelayprovider": "meta_dot_ai_abra_web_doc_upload_nux_tour",
                        "__relay_internal__pv__AbraQPFileUploadTransparencyDisclaimerTriggerNamerelayprovider": "meta_dot_ai_abra_web_file_upload_transparency_disclaimer",
                        "__relay_internal__pv__AbraUpsellsKillswitchrelayprovider": True,
                        "__relay_internal__pv__AbraIcebreakerImagineFetchCountrelayprovider": 20,
                        "__relay_internal__pv__AbraImagineYourselfIcebreakersrelayprovider": False,
                        "__relay_internal__pv__AbraEmuReelsIcebreakersrelayprovider": False,
                        "__relay_internal__pv__AbraArtifactsDisplayHeaderV2relayprovider": False,
                        "__relay_internal__pv__AbraArtifactEditorDebugModerelayprovider": False,
                        "__relay_internal__pv__AbraArtifactSharingrelayprovider": False,
                        "__relay_internal__pv__AbraArtifactEditorSaveEnabledrelayprovider": False,
                        "__relay_internal__pv__AbraArtifactEditorDownloadHTMLEnabledrelayprovider": False,
                        "__relay_internal__pv__AbraArtifactsRenamingEnabledrelayprovider": False
                    }),
                    'server_timestamps': 'true',
                    'doc_id': '9614969011880432'
                }

                response = self.session.post(url, data=payload, headers=self.headers, timeout=30)
                
                if response.status_code != 200:
                    raise Exception(f"HTTP {response.status_code}")
                
                time.sleep(2)
                
                ai_response = self.extract_chat(response.text)
                
                if ai_response and ai_response.get("assistant") and ai_response["assistant"].strip():
                    return ai_response["assistant"]
                else:
                    retry_count += 1
                    if retry_count < max_retries:
                        print(f"Retry {retry_count}/{max_retries} - No response content")
                        time.sleep(1)
                        self.access_token = None
                        continue
                    
            except Exception as e:
                retry_count += 1
                print(f"Error asking question (attempt {retry_count}): {str(e)}")
                if retry_count < max_retries:
                    time.sleep(2)
                    self.access_token = None
                    continue
                
        return None

meta_ai = MetaAI()

@bot.event
async def on_ready():
    print(f'{bot.user} Đã Online!')
    await asyncio.get_event_loop().run_in_executor(None, meta_ai.initialize_session)
    cleanup_memory.start()
    heartbeat.start()
    restore_tasks()
    
    scheduler.start()
    
    scheduler.add_job(
        reset_daily_data,
        CronTrigger(hour=12, minute=0),
        id='reset_daily_data'
    )
    
    scheduler.add_job(
        reset_user_tasks,
        CronTrigger(hour=6, minute=0),
        id='reset_user_tasks'
    )
    
discord_client = DiscordClient()

user_tickets = {}
discord_tasks = {}

def load_discord_tasks():
    if os.path.exists('discord_tasks.json'):
        with open('discord_tasks.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_discord_tasks():
    with open('discord_tasks.json', 'w', encoding='utf-8') as f:
        json.dump(discord_tasks, f, ensure_ascii=False, indent=2)

async def get_next_ticket_number(guild):
    existing_channels = [ch.name for ch in guild.channels if ch.name.startswith('ticket-')]
    ticket_numbers = []
    for ch_name in existing_channels:
        try:
            num = int(ch_name.split('-')[1])
            ticket_numbers.append(num)
        except:
            continue
    
    if not ticket_numbers:
        return 1
    return max(ticket_numbers) + 1

async def load_proxies():
    if os.path.exists('proxies.txt'):
        async with aiofiles.open('proxies.txt', 'r', encoding='utf-8') as f:
            content = await f.read()
            proxies = [line.strip() for line in content.split('\n') if line.strip()]
            return proxies
    return []

class CloseTicketView(discord.ui.View):
    def __init__(self, channel_id):
        super().__init__(timeout=None)
        self.channel_id = channel_id
    
    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger, emoji="🔐")
    async def close_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        channel = bot.get_channel(self.channel_id)
        if channel:
            await channel.delete()
        await interaction.response.defer()

class TokenUploadView(discord.ui.View):
    def __init__(self, user_id, action_type):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.action_type = action_type
        self.tokens = []
        self.step = "upload"
        self.server_link = None
        self.name_input = None
        self.avatar_url = None
   
def generate_random_key(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def load_user_data():
    try:
        if os.path.exists('user_data.json'):
            with open('user_data.json', 'r', encoding='utf-8') as f:
                return json.load(f)
    except:
        pass
    return {"user_keys": {}, "user_nhapkey_count": {}}

def save_user_data():
    data = {
        "user_keys": user_keys,
        "user_nhapkey_count": user_nhapkey_count
    }
    with open('user_data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

async def reset_daily_data():
    global user_keys, user_nhapkey_count
    user_keys.clear()
    user_nhapkey_count.clear()
    save_user_data()

async def reset_user_tasks():
    config = load_config()
    if 'task' not in config:
        return
    if 'task_used' not in config:
        config['task_used'] = {}
    if 'admin_added_users' not in config:
        config['admin_added_users'] = {}

    for user_id in list(config['task'].keys()):
        if user_id in config['admin_added_users']:
            continue
            
        current_task = config['task'].get(user_id, 0)
        used_task = config['task_used'].get(user_id, 0)
        user_nhapkey_count_val = user_nhapkey_count.get(user_id, 0)

        if user_nhapkey_count_val < used_task:
            diff = used_task - user_nhapkey_count_val
            new_task = max(0, current_task - diff)
            config['task'][user_id] = new_task

        if user_nhapkey_count_val == 0:
            config['task'][user_id] = 0

    config['task_used'] = {}
    save_config(config)
    
    total_users = len(config['task'])
    admin_added_count = len(config['admin_added_users'])
    reset_count = total_users - admin_added_count

@bot.event
async def on_disconnect():
    print("Bot disconnected, attempting to reconnect...")

@bot.event
async def on_resumed():
    print("Bot connection resumed")

def check_ownervip():
    def predicate(ctx):
        return str(ctx.author.id) in config['ownerVIP']
    return commands.check(predicate)

@bot.command(name='meta')

async def meta_command(ctx, *, question: str = None):
    if not question:
        embed = discord.Embed(
            title="❌ Lỗi",
            description="Vui Lòng Nhập Câu Hỏi\nVí Dụ: meta hôm này thời tiết thế nào?`",
            color=0xFF69B4
        )
        await ctx.reply(embed=embed)
        return
    
    loading_embed = discord.Embed(
        title="⏳ Đang Xử Lý...",
        description="Meta AI Đang Suy Nghĩ Vui Lòng Đợi...",
        color=0xFF69B4
    )
    loading_message = await ctx.reply(embed=loading_embed)
    
    try:
        answer = await asyncio.get_event_loop().run_in_executor(
            None, meta_ai.ask_question, question
        )
        
        if answer:
            if len(answer) > 1900:
                answer = answer[:1900] + "..."
            
            embed = discord.Embed(
                title="👤 Meta AI 👤",
                description=f"**Câu Hỏi:** {question}\n\n**Câu Trả Lời:** {answer}",
                color=0xFF69B4
            )
            embed.set_footer(text=f"Được Hỏi Bởi {ctx.author.display_name}", icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
        else:
            embed = discord.Embed(
                title="❌ Lỗi",
                description="Không Thể Lấy Được Câu Trả Lời, Vui Lòng Thử Lại Sau.",
                color=0xFF69B4
            )
        
        await loading_message.edit(embed=embed)
        
    except Exception as e:
        error_embed = discord.Embed(
            title="❌ Lỗi",
            description=f"Đã xảy ra lỗi: {str(e)}",
            color=0xFF69B4
        )
        await loading_message.edit(embed=error_embed)

class TreoView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
        
        return True

    @discord.ui.button(label="Treo Ảnh/Video", style=discord.ButtonStyle.primary)
    async def treo_media(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TreoMediaModal()
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="Treo Share Contact", style=discord.ButtonStyle.secondary)
    async def treo_contact(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TreoContactModal()
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="Treo Normal", style=discord.ButtonStyle.success)
    async def treo_normal(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TreoNormalModal()
        await interaction.response.send_modal(modal)

class ListBoxModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="🍪 Nhập Cookies Facebook", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Cookies Facebook",
            placeholder="Nhập Cookies Facebook Của Bạn...",
            style=discord.TextStyle.paragraph,
            required=True,
            max_length=4000
        )
        self.add_item(self.cookies)

    async def on_submit(self, interaction: discord.Interaction):
        loading_embed = discord.Embed(
            title="⏰ Đang Xử Lý...",
            description="Bot Đang Lấy List Box, Vui Lòng Đợi...",
            color=0xFFD700
        )
        await interaction.response.send_message(embed=loading_embed, ephemeral=True)
        
        try:
            fb = facebook(self.cookies.value)
            fbt = fbTools(fb.data)
            
            success = fbt.getAllThreadList()
            if success:
                thread_data = fbt.getListThreadID()
                if "threadIDList" in thread_data and "threadNameList" in thread_data:
                    thread_ids = thread_data["threadIDList"]
                    thread_names = thread_data["threadNameList"]
                    
                    if len(thread_ids) > 10:
                        pages = []
                        for i in range(0, len(thread_ids), 10):
                            page_data = []
                            for j in range(i, min(i + 10, len(thread_ids))):
                                page_data.append({
                                    "index": j + 1,
                                    "name": thread_names[j],
                                    "id": thread_ids[j]
                                })
                            pages.append(page_data)
                        
                        view = PaginationView(pages, len(thread_ids))
                        initial_embed = view.create_embed()
                        await interaction.followup.send(embed=initial_embed, view=view, ephemeral=False)
                    else:
                        embed = discord.Embed(
                            title="📋 Danh Sách Box Facebook",
                            color=0x00FF00,
                            timestamp=datetime.datetime.utcnow()
                        )
                        
                        description = ""
                        for i in range(len(thread_ids)):
                            description += f"**{i+1}.** {thread_names[i]}\n`{thread_ids[i]}`\n\n"
                        
                        embed.description = description
                        embed.set_footer(text=f"Tổng Cộng: {len(thread_ids)} Box")
                        
                        await interaction.followup.send(embed=embed, ephemeral=False)
                else:
                    error_embed = discord.Embed(
                        title="❌ Lỗi",
                        description="Không Thể Lấy List Box Từ Data",
                        color=0xFF0000
                    )
                    await interaction.followup.send(embed=error_embed, ephemeral=False)
            else:
                error_embed = discord.Embed(
                    title="❌ Lỗi Cookies",
                    description="Không Thể Lấy Danh Sách Nhóm, Vui Lòng Check Lại Cookies.",
                    color=0xFF0000
                )
                await interaction.followup.send(embed=error_embed, ephemeral=False)
        except Exception as e:
            error_embed = discord.Embed(
                title="⚠️ Đã Xảy Ra Lỗi",
                description=f"{e}",
                color=0xFF0000
            )
            await interaction.followup.send(embed=error_embed, ephemeral=False)

class ListBoxView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary, emoji="🚀")
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = ListBoxModal()
        await interaction.response.send_modal(modal)

class PaginationView(discord.ui.View):
    def __init__(self, pages, total_items):
        super().__init__(timeout=300)
        self.pages = pages
        self.current_page = 0
        self.total_items = total_items

    def create_embed(self):
        embed = discord.Embed(
            title="📋 Danh Sách Box Facebook",
            color=0x00FF00,
            timestamp=datetime.datetime.utcnow()
        )
        
        current_page_data = self.pages[self.current_page]
        description = ""
        
        for item in current_page_data:
            description += f"**{item['index']}.** {item['name']}\n`{item['id']}`\n\n"
        
        embed.description = description
        
        embed.set_footer(
            text=f"Trang {self.current_page + 1}/{len(self.pages)} • Tổng Cộng: {self.total_items} Box"
        )
        
        return embed

    @discord.ui.button(emoji="⬅️", style=discord.ButtonStyle.secondary, disabled=True)
    async def previous_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.current_page > 0:
            self.current_page -= 1
            
            self.previous_page.disabled = self.current_page == 0
            self.next_page.disabled = False
            
            embed = self.create_embed()
            await interaction.response.edit_message(embed=embed, view=self)
        else:
            await interaction.response.defer()

    @discord.ui.button(emoji="➡️", style=discord.ButtonStyle.secondary)
    async def next_page(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.current_page < len(self.pages) - 1:
            self.current_page += 1
            
            self.next_page.disabled = self.current_page == len(self.pages) - 1
            self.previous_page.disabled = False
            
            embed = self.create_embed()
            await interaction.response.edit_message(embed=embed, view=self)
        else:
            await interaction.response.defer()

    @discord.ui.button(label="Đóng", emoji="❌", style=discord.ButtonStyle.danger)
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = discord.Embed(
            title="✅ Đã Đóng",
            description="Danh Sách Đã Được Đóng",
            color=0x808080
        )
        await interaction.response.edit_message(embed=embed, view=None)

    async def on_timeout(self):
        for item in self.children:
            item.disabled = True

class TreoMediaModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Treo Ảnh/Video", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.media_url = discord.ui.TextInput(
            label="Nhập Link Tải Ảnh/Video",
            required=True
        )
        self.add_item(self.media_url)
        self.message = discord.ui.TextInput(
            label="Nhập Ngôn",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.message)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    def download_media(self, url, folder_path):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
            }
            response = requests.get(url, headers=headers, stream=True, timeout=30)
            response.raise_for_status()
            if "Content-Disposition" in response.headers:
                content_disposition = response.headers["Content-Disposition"]
                filename = re.findall("filename=(.+)", content_disposition)[0].strip('"')
            else:
                filename = os.path.basename(urlparse(url).path)
                if not filename:
                    content_type = response.headers.get('Content-Type', '').split('/')[1]
                    if content_type:
                        filename = f"media_{int(time.time())}.{content_type}"
                    else:
                        filename = f"media_{int(time.time())}"
            local_file_path = os.path.join(folder_path, filename)
            with open(local_file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return local_file_path
        except Exception as e:
            print(f"Error downloading media: {e}")
            return None

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        try:
            folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            folder_path = f"data/{folder_id}"
            os.makedirs(folder_path)
            with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
                f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | treo_media | {interaction.user.id} | {self.media_url.value}")
            with open(f"{folder_path}/messages.txt", "w", encoding="utf-8") as f:
                f.write(self.message.value)
            local_file_path = self.download_media(self.media_url.value, folder_path)
            if not local_file_path:
                embed = discord.Embed(
                    title="❌ Lỗi Khi Tải Ảnh/Video",
                    description="Không Thể Tải File Từ Url Đã Cung Cấp",
                    color=0xFF0000
                )
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return
            thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_media_func, self.cookies.value, self.idbox.value, local_file_path, self.message.value, self.delay.value, folder_id))
            thread.daemon = True
            thread.start()
            embed = discord.Embed(
                title="✅ Tạo Tasks Thành Công ✅",
                description=f"ID Tasks: {folder_id}\nBạn còn lại **{user_max_tasks - (user_current_tasks + 1)}** lượt tạo task.",
                color=0x00FF00
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
        except Exception as e:
            embed = discord.Embed(
                title="❌ Lỗi Tạo Tasks ❌",
                description=f"Lỗi: {str(e)}",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)

class TreoContactModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Treo Share Contact", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)
        self.uid_contact = discord.ui.TextInput(
            label="Nhập UID Contact",
            required=True
        )
        self.add_item(self.uid_contact)
        self.message = discord.ui.TextInput(
            label="Nhập Ngôn",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.message)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
           
        try:
            folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            folder_path = f"data/{folder_id}"
            os.makedirs(folder_path)
            with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
                f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | treo_contact | {interaction.user.id} | {self.uid_contact.value}")
            with open(f"{folder_path}/messages.txt", "w", encoding="utf-8") as f:
                f.write(self.message.value)
            thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_contact_func, self.cookies.value, self.idbox.value, self.uid_contact.value, self.message.value, self.delay.value, folder_id))
            thread.daemon = True
            thread.start()
            embed = discord.Embed(
                title="✅ Tạo Tasks Thành Công ✅",
                description=f"ID Tasks: {folder_id}",
                color=0x00FF00
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
        except Exception as e:
            embed = discord.Embed(
                title="❌ Lỗi Tạo Tasks ❌",
                description=f"Lỗi: {str(e)}",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)

class NhayPollModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Poll Mess", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | nhay_poll | {interaction.user.id}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_poll_func, self.cookies.value, self.idbox.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()
        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class NhayPollView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary)
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayPollModal()
        await interaction.response.send_modal(modal)

class TreoNormalModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Treo Normal", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)
        self.message = discord.ui.TextInput(
            label="Nhập Ngôn",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.message)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
           
        try:
            folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
            folder_path = f"data/{folder_id}"
            os.makedirs(folder_path)
            with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
                f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | treo_normal | {interaction.user.id}")
            with open(f"{folder_path}/message.txt", "w", encoding="utf-8") as f:
                f.write(self.message.value)
            thread = threading.Thread(target=safe_thread_wrapper, args=(start_treo_mess_func, self.cookies.value, self.idbox.value, self.message.value, self.delay.value, folder_id))
            thread.daemon = True
            thread.start()
            embed = discord.Embed(
                title="✅ Tạo Tasks Thành Công ✅",
                description=f"ID Tasks: {folder_id}",
                color=0x00FF00
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
        except Exception as e:
            embed = discord.Embed(
                title="❌ Lỗi Tạo Tasks ❌",
                description=f"Lỗi: {str(e)}",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.command()

async def treo(ctx):
    embed = discord.Embed(
        title="Chọn Chức Năng Treo Bên Dưới",
        description="Button Treo Ảnh/Video Là Treo Gửi Ảnh Hoặc Video\nButton Treo Share Contact Là Treo + Share Contact Của UID\nButton Treo Normal Là Button Gửi Tin Nhắn Kiểu Bình Thường",
        color=0xFFC0CB
    )
    view = TreoView()
    await ctx.send(embed=embed, view=view)

class NhayView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
        
        return True
    
    @discord.ui.button(label="Nhây", style=discord.ButtonStyle.primary)
    async def nhay_normal(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayModal()
        await interaction.response.send_modal(modal)
    
    @discord.ui.button(label="Nhây Tag", style=discord.ButtonStyle.secondary)
    async def nhay_tag(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayTagModal()
        await interaction.response.send_modal(modal)

class NhayModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Thường", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
           
        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | nhay_normal | {interaction.user.id}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_func, self.cookies.value, self.idbox.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()
        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class NhayZaloView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
        
        return True

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary)
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayZaloModal()
        await interaction.response.send_modal(modal)

class NhayZaloView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary)
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayZaloModal()
        await interaction.response.send_modal(modal)

class NhayZaloModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Zalo", timeout=None)
        
        self.imei = discord.ui.TextInput(
            label="Nhập Imei:",
            required=True
        )
        self.add_item(self.imei)
        
        self.session_cookies = discord.ui.TextInput(
            label="Nhập Session Cookies:",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.session_cookies)
        
        self.thread_id = discord.ui.TextInput(
            label="Nhập ID Cần Nhây Zalo (User Lẫn Box Tùy Chọn):",
            required=True
        )
        self.add_item(self.thread_id)
        
        self.delay = discord.ui.TextInput(
            label="Nhập Delay:",
            required=True,
            placeholder="Ví dụ: 3"
        )
        self.add_item(self.delay)
        
        self.thread_type = discord.ui.TextInput(
            label="Nhập Kiểu (GROUP = 1 | USER = 0):",
            required=True,
            placeholder="0 hoặc 1"
        )
        self.add_item(self.thread_type)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        try:
            delay_value = float(self.delay.value)
            if delay_value < 3:
                await interaction.response.send_message(
                    "❌ Delay Phải Lớn Hơn 3s Hoặc Bằng 3s.", ephemeral=True
                )
                return
        except ValueError:
            await interaction.response.send_message(
                "❌ Delay Phải Là 1 Con Số Hợp Lệ.", ephemeral=True
            )
            return
            
        if self.thread_type.value not in ["0", "1"]:
            await interaction.response.send_message(
                "❌ Kiểu Thread Phải Là 0 (USER) hoặc 1 (GROUP).", ephemeral=True
            )
            return

        current_tasks = check_task_limit()
        if current_tasks >= 150:
            embed = discord.Embed(
                title="Bot Đã Đạt Giới Hạn 150/150 Tab Vui Lòng Đợi Người Khác Xóa Tab Hoặc Xóa Tab Nào Đó Bạn Không Dùng Để Có Thể Chạy Tiếp",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"zalo_cookies | {self.thread_id.value} | {self.delay.value} | nhay_zalo | {interaction.user.id} | {self.imei.value} | {self.session_cookies.value} | {self.thread_type.value}")

        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")

        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_zalo_func, self.imei.value, self.session_cookies.value, self.thread_id.value, self.delay.value, self.thread_type.value, folder_id))
        thread.daemon = True
        thread.start()

        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

class NhayTagModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Tag", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.idbox = discord.ui.TextInput(
            label="Nhập ID Box",
            required=True
        )
        self.add_item(self.idbox)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay",
            required=True
        )
        self.add_item(self.delay)
        self.uid_tag = discord.ui.TextInput(
            label="Nhập UID Cần Tag",
            required=True
        )
        self.add_item(self.uid_tag)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
           
        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"{self.cookies.value} | {self.idbox.value} | {self.delay.value} | nhay_tag | {interaction.user.id} | {self.uid_tag.value}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_tag_func, self.cookies.value, self.idbox.value, self.uid_tag.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()
        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.command()

async def nhay(ctx):
    embed = discord.Embed(
        title="Bạn Muốn Sử Dụng Phương Thức Nhây Nào?",
        description="Button Nhây Sẽ Là Nhây Thường - Fake Typing\nButton Nhây Tag Sẽ Là Nhây Có Tag - Fake Typing",
        color=0x0099FF
    )
    view = NhayView()
    await ctx.send(embed=embed, view=view)

class NhayTopView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Start", style=discord.ButtonStyle.primary)
    async def start_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayTopModal()
        await interaction.response.send_modal(modal)

class NhayTopModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Nhây Top Tag", timeout=None)
        self.cookies = discord.ui.TextInput(
            label="Nhập Cookies:",
            style=discord.TextStyle.paragraph,
            required=True
        )
        self.add_item(self.cookies)
        self.id_group = discord.ui.TextInput(
            label="Nhập ID Group:",
            required=True
        )
        self.add_item(self.id_group)
        self.id_post = discord.ui.TextInput(
            label="Nhập ID Post:",
            required=True
        )
        self.add_item(self.id_post)
        self.uid_tag = discord.ui.TextInput(
            label="Nhập UID Cần Tag:",
            required=True
        )
        self.add_item(self.uid_tag)
        self.delay = discord.ui.TextInput(
            label="Nhập Delay:",
            required=True
        )
        self.add_item(self.delay)

    async def on_submit(self, interaction: discord.Interaction):
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
           
        folder_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        folder_path = f"data/{folder_id}"
        os.makedirs(folder_path)
        with open(f"{folder_path}/luutru.txt", "w", encoding="utf-8") as f:
            f.write(f"{self.cookies.value} | {self.id_group.value} | {self.id_post.value} | {self.uid_tag.value} | {self.delay.value} | nhay_top_tag | {interaction.user.id}")
        current_dir = os.path.dirname(os.path.abspath(__file__))
        nhay_path = os.path.join(current_dir, "nhay.txt")
        if not os.path.exists(nhay_path):
            with open(nhay_path, "w", encoding="utf-8") as f:
                f.write("cay ak\ncn choa\nsua em\nsua de\nmanh em\ncay ak\ncn nqu")
        thread = threading.Thread(target=safe_thread_wrapper, args=(start_nhay_top_tag_func, self.cookies.value, self.id_group.value, self.id_post.value, self.uid_tag.value, self.delay.value, folder_id))
        thread.daemon = True
        thread.start()
        embed = discord.Embed(
            title="✅ Tạo Tasks Thành Công ✅",
            description=f"ID Tasks: {folder_id}",
            color=0x00FF00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.command()

async def nhaytop(ctx):
    embed = discord.Embed(
        title="Vui Lòng Ấn Vào Nút Start Để Nhập Thông Tin",
        color=0xFFC0CB
    )
    view = NhayTopView()
    await ctx.send(embed=embed, view=view)

@bot.command()

async def danhsachtask(ctx):
    user_id = str(ctx.author.id)
    is_vip = user_id == config['ownerVIP']
    tasks = []
    if os.path.exists('data'):
        for folder in os.listdir('data'):
            folder_path = f"data/{folder}"
            if os.path.isdir(folder_path) and os.path.exists(f"{folder_path}/luutru.txt"):
                with open(f"{folder_path}/luutru.txt", "r", encoding="utf-8") as f:
                    content = f.read().strip()
                parts = content.split(" | ")
                if len(parts) >= 4:
                    task_owner = "Unknown"
                    if parts[3] == "nhay_top_tag" and len(parts) >= 7:
                        task_owner = parts[6]
                    elif parts[3] == "treoso" and len(parts) >= 5:
                        task_owner = parts[4]
                    elif parts[3] == "nhay_zalo" and len(parts) >= 8:
                        task_owner = parts[4]
                    elif len(parts) >= 5:
                        task_owner = parts[4]
                    
                    if is_vip or task_owner == user_id:
                        created_timestamp = os.path.getctime(folder_path)
                        created_time = datetime.datetime.fromtimestamp(created_timestamp).strftime("%d-%m-%Y")
                        method_map = {
                            "treo_media": "Treo Ảnh/Video",
                            "treo_contact": "Treo Share Contact",
                            "treo_normal": "Treo Normal",
                            "nhay_normal": "Nhây Thường",
                            "nhay_tag": "Nhây Tag",
                            "nhay_top_tag": "Nhây Top Tag",
                            "nhay_zalo": "Nhây Zalo",
                            "treoso": "Treo Sớ",
                            "nhay_poll": "Nhây Poll",
                            "treo_discord": "Treo Discord",
                            "nhay_discord": "Nhây Discord",
                            "nhay_tag_discord": "Nhây Tag Discord"
                        }
                        method = method_map.get(parts[3], parts[3])
                        if parts[3] == "nhay_top_tag" and len(parts) >= 7:
                            task_info = f"ID Task: {folder} | ID Group: {parts[1]} | ID Post: {parts[2]} | Tạo Lúc: {created_time} | Lệnh Đã Tạo: {config['prefix']}nhaytop"
                            if is_vip:
                                task_info += f" | Lệnh Được Tạo Bởi: <@{task_owner}>"
                        elif parts[3] == "treoso":
                            task_info = f"ID Tasks: {folder} | ID Box: {parts[1]} | Tạo Lúc: {created_time} | Lệnh Đã Tạo: {config['prefix']}treoso"
                            if is_vip:
                                task_info += f" | Lệnh Được Tạo Bởi: <@{task_owner}>"
                        elif parts[3] == "nhay_zalo" and len(parts) >= 8:
                            thread_type_display = "Threads" if parts[7] == "1" else "User"
                            task_info = f"ID Tasks: {folder} | ID {thread_type_display}: {parts[1]} | Tạo Lúc: {created_time} | Lệnh Đã Tạo: {config['prefix']}nhayzalo"
                            if is_vip:
                                task_info += f" | Lệnh Được Tạo Bởi: <@{task_owner}>"
                        elif parts[3] in ["nhay_normal", "nhay_tag"]:
                            task_info = f"ID Tasks: {folder} | ID Box: {parts[1]} | Tạo Lúc: {created_time} | Lệnh Đã Tạo: {config['prefix']}nhay | Phương Thức: {method}"
                            if is_vip:
                                task_info += f" | Lệnh Được Tạo Bởi: <@{task_owner}>"
                        else:
                            task_info = f"ID Tasks: {folder} | ID Box: {parts[1]} | Tạo Lúc: {created_time} | Lệnh Đã Tạo: {config['prefix']}treo | Phương Thức: {method}"
                            if is_vip:
                                task_info += f" | Lệnh Được Tạo Bởi: <@{task_owner}>"
                        tasks.append(task_info)
    
    if not tasks:
        embed = discord.Embed(
            title="Bạn Chưa Có Tạo Tasks Nào Hiện Tại Cả ❌",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return

    tasks_per_page = 10
    total_pages = (len(tasks) + tasks_per_page - 1) // tasks_per_page
    current_page = 1

    def create_embed(page):
        start_idx = (page - 1) * tasks_per_page
        end_idx = start_idx + tasks_per_page
        page_tasks = tasks[start_idx:end_idx]
        description = "\n".join(page_tasks) + "\n\nBot By: Ng Quang Huy (Dzi)🪽"
        embed = discord.Embed(
            title="🌟 Danh Sách Tasks 🌟",
            description=description,
            color=0x0099FF
        )
        embed.set_footer(text=f"Đang Ở Trang {page}/{total_pages}")
        return embed

    embed = create_embed(current_page)
    if total_pages == 1:
        await ctx.send(embed=embed)
        return

    view = discord.ui.View(timeout=None)

    async def prev_callback(interaction):
        nonlocal current_page
        if current_page > 1:
            current_page -= 1
            embed = create_embed(current_page)
            await interaction.response.edit_message(embed=embed, view=view)
        else:
            await interaction.response.defer()

    async def next_callback(interaction):
        nonlocal current_page
        if current_page < total_pages:
            current_page += 1
            embed = create_embed(current_page)
            await interaction.response.edit_message(embed=embed, view=view)
        else:
            await interaction.response.defer()

    prev_button = discord.ui.Button(emoji="◀️", style=discord.ButtonStyle.primary)
    next_button = discord.ui.Button(emoji="▶️", style=discord.ButtonStyle.primary)
    prev_button.callback = prev_callback
    next_button.callback = next_callback
    view.add_item(prev_button)
    view.add_item(next_button)

    message = await ctx.send(embed=embed, view=view)

    async def on_timeout():
        for item in view.children:
            item.disabled = True
        try:
            await message.edit(view=view)
        except:
            pass

    view.on_timeout = on_timeout

class DiscordView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        config_data = load_config()
        user_id_str = str(interaction.user.id)

        if check_task_limit() >= 200:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Toàn Bot",
                description="Bot Đã Chạy Tối Đa 200/200 Tasks Vui Lòng Thử Lại Sau..",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False

        if user_id_str not in config_data.get("task", {}):
            embed = discord.Embed(
                title="❌ Không Có Quyền",
                description="Bạn Không Có Quyền Tạo Task, Vui Lòng Liên Hệ Admin Để Mua Task.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
            
        user_current_tasks = get_user_task_count(user_id_str)
        user_max_tasks = int(config_data["task"].get(user_id_str, 0))
        
        if user_current_tasks >= user_max_tasks:
            embed = discord.Embed(
                title="❌ Đã Đạt Giới Hạn Task Cá Nhân",
                description=f"Bạn Đã Tạo Tối Đa **{user_max_tasks}** Task Được Cho Phép.",
                color=0xFF0000
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return False
        
        return True

    @discord.ui.button(label="Treo", style=discord.ButtonStyle.primary)
    async def treo_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = TreoDiscordModal()
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Nhây", style=discord.ButtonStyle.secondary)
    async def nhay_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayDiscordModal()
        await interaction.response.send_modal(modal)

    @discord.ui.button(label="Nhây Tag", style=discord.ButtonStyle.success)
    async def nhay_tag_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        modal = NhayTagDiscordModal()
        await interaction.response.send_modal(modal)
        
import aiofiles

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    
    if message.channel.name and message.channel.name.startswith('ticket-'):
        user_id = str(message.author.id)
        
        if user_id in user_tickets:
            ticket_info = user_tickets[user_id]
            
            if message.attachments and ticket_info['step'] == 'upload':
                attachment = message.attachments[0]
                if attachment.filename.endswith('.txt'):
                    content = await attachment.read()
                    text_content = content.decode('utf-8')
                    
                    tokens = [line.strip() for line in text_content.split('\n') if line.strip()]
                    
                    if not tokens:
                        await message.channel.send("❌ File Trống Hoặc Không Hợp Lệ !")
                        return
                    
                    user_task_count = discord_tasks.get(user_id, {}).get(ticket_info['action_type'], 0)
                    
                    if user_task_count == 0:
                        await message.channel.send("❌ Bạn Không Có Task Nào Để Thực Hiện !\nVui Lòng Liên Hệ Admin Để Mua")
                        return
                    
                    if len(tokens) > user_task_count:
                        import random
                        tokens = random.sample(tokens, user_task_count)
                    
                    ticket_info['tokens'] = tokens
                    ticket_info['step'] = 'input'
                    
                    if ticket_info['action_type'] == 'join':
                        await message.channel.send("✅ Đã Nhận File Token !\nVui Lòng Nhập Link Server Cần Joiner Lên Kênh Này")
                    elif ticket_info['action_type'] == 'rename':
                        await message.channel.send("✅ Đã Nhận File Token !\nVui Lòng Nhập Tên Muốn Đổi Lên Kênh Này")
                    elif ticket_info['action_type'] == 'avatar':
                        await message.channel.send("✅ Đã Nhận File Token !\nVui Lòng Nhập Link Ảnh Cần Đổi Avatar")
                else:
                    await message.channel.send("❌ Vui Lòng Upload File .txt!")
            
            elif ticket_info['step'] == 'input' and not message.attachments:
                content = message.content.strip()
                
                if ticket_info['action_type'] == 'join':
                    if 'discord.gg/' in content or 'discord.com/invite/' in content:
                        invite_code = content.split('/')[-1]
                        await process_join_server(message.channel, user_id, ticket_info['tokens'], invite_code)
                    else:
                        await message.channel.send("❌ Link Server Không Hợp Lệ !")
                
                elif ticket_info['action_type'] == 'rename':
                    if len(content) > 32:
                        await message.channel.send("❌ Tên Quá Dài (Tối Đa 32 Ký Tự)!")
                        return
                    await process_rename(message.channel, user_id, ticket_info['tokens'], content)
                
                elif ticket_info['action_type'] == 'avatar':
                    if content.startswith('http'):
                        await process_change_avatar(message.channel, user_id, ticket_info['tokens'], content)
                    else:
                        await message.channel.send("❌ Link Ảnh Không Hợp Lệ !")
    
    await bot.process_commands(message)

async def process_join_server(channel, user_id, tokens, invite_code):
    proxies = await load_proxies()
    
    embed = discord.Embed(
        title="🚀 Đang Xử Lý Join Server",
        description="Vui Lòng Đợi...",
        color=0x00FF00
    )
    status_msg = await channel.send(embed=embed)
    
    success_count = 0
    captcha_count = 0
    invalid_count = 0
    error_count = 0
    total_processed = 0
    
    for i, token in enumerate(tokens):
        proxy = proxies[i % len(proxies)] if proxies else None
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, discord_client.join_server, token, invite_code, proxy
            )
            
            if result["status"] == "success":
                success_count += 1
                discord_tasks[user_id]["join"] -= 1
                save_discord_tasks()
            elif result["status"] == "captcha":
                captcha_count += 1
            elif result["status"] == "invalid":
                invalid_count += 1
            else:
                error_count += 1
            
            total_processed += 1
            
            embed = discord.Embed(
                title="🚀 Đang Xử Lý Join Server",
                description=f"Đã Xử Lý: {total_processed}/{len(tokens)}\nThành Công: {success_count}",
                color=0x00FF00
            )
            await status_msg.edit(embed=embed)
            
            await asyncio.sleep(1)
            
        except Exception as e:
            error_count += 1
            total_processed += 1
            print(f"Error processing token: {e}")
    
    final_embed = discord.Embed(
        title="✅ Hoàn Thành Join Server",
        description=f"Join Thành Công > {success_count}\nInvaild > {invalid_count}\nHcaptcha > {captcha_count}\n\nTask Còn Lại: {discord_tasks.get(user_id, {}).get('join', 0)}",
        color=0x00FF00
    )
    await status_msg.edit(embed=final_embed)

async def process_rename(channel, user_id, tokens, new_name):
    proxies = await load_proxies()
    
    embed = discord.Embed(
        title="✏️ Đang Xử Lý Đổi Tên",
        description="Vui Lòng Đợi...",
        color=0x00FF00
    )
    status_msg = await channel.send(embed=embed)
    
    success_count = 0
    total_processed = 0
    
    for i, token in enumerate(tokens):
        proxy = proxies[i % len(proxies)] if proxies else None
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, discord_client.change_globalname, token, new_name, proxy
            )
            
            if result["status"] == "success":
                success_count += 1
            
            total_processed += 1
            
            if result["status"] in ["success"]:
                discord_tasks[user_id]["rename"] -= 1
                save_discord_tasks()
            
            embed = discord.Embed(
                title="✏️ Đang Xử Lý Đổi Tên",
                description=f"Đã Xử Lý: {total_processed}/{len(tokens)}\nThành Công: {success_count}",
                color=0x00FF00
            )
            await status_msg.edit(embed=embed)
            
            await asyncio.sleep(2.5)
            
        except Exception as e:
            print(f"Error processing token: {e}")
    
    final_embed = discord.Embed(
        title="✅ Hoàn Thành Đổi Tên",
        description=f"Tổng Token Xử Lý: {total_processed}\nThành Công: {success_count}\nTask Còn Lại: {discord_tasks.get(user_id, {}).get('rename', 0)}",
        color=0x00FF00
    )
    await status_msg.edit(embed=final_embed)

async def process_change_avatar(channel, user_id, tokens, avatar_url):
    proxies = await load_proxies()
    
    embed = discord.Embed(
        title="🖼️ Đang Xử Lý Đổi Avatar",
        description="Vui Lòng Đợi...",
        color=0x00FF00
    )
    status_msg = await channel.send(embed=embed)
    
    success_count = 0
    total_processed = 0
    
    for i, token in enumerate(tokens):
        proxy = proxies[i % len(proxies)] if proxies else None
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, discord_client.change_avatar, token, avatar_url, proxy
            )
            
            if result["status"] == "success":
                success_count += 1
            
            total_processed += 1
            
            if result["status"] in ["success"]:
                discord_tasks[user_id]["avatar"] -= 1
                save_discord_tasks()
            
            embed = discord.Embed(
                title="🖼️ Đang Xử Lý Đổi Avatar",
                description=f"Đã Xử Lý: {total_processed}/{len(tokens)}\nThành Công: {success_count}",
                color=0x00FF00
            )
            await status_msg.edit(embed=embed)
            
            await asyncio.sleep(2.5)
            
        except Exception as e:
            print(f"Error processing token: {e}")
    
    final_embed = discord.Embed(
        title="✅ Hoàn Thành Đổi Avatar",
        description=f"Tổng Token Xử Lý: {total_processed}\nThành Công: {success_count}\nTask Còn Lại: {discord_tasks.get(user_id, {}).get('avatar', 0)}",
        color=0x00FF00
    )
    await status_msg.edit(embed=final_embed)

@bot.command()
@check_ownervip()
async def addtaskdis(ctx, user: discord.User, quantity: int, task_type: str):
    if user is None or quantity is None or task_type is None:
        await ctx.send("Format: `addtaskdis @user <số_lượng> <loại>`\nLoại: join, rename, avatar")
        return

    if quantity <= 0:
        await ctx.send("Số Lượng Task Phải Lớn Hơn 0.")
        return

    if task_type not in ["join", "rename", "avatar"]:
        await ctx.send("Loại Task Phải Là: join, rename hoặc avatar")
        return

    global discord_tasks
    discord_tasks = load_discord_tasks()

    user_id_str = str(user.id)
    
    if user_id_str not in discord_tasks:
        discord_tasks[user_id_str] = {"join": 0, "rename": 0, "avatar": 0}
    
    discord_tasks[user_id_str][task_type] += quantity
    save_discord_tasks()

    task_names = {"join": "Join Server", "rename": "Đổi Tên", "avatar": "Đổi Avatar"}
    
    embed = discord.Embed(
        title="✅ Thêm Discord Task Thành Công",
        description=f"Đã Cấp Cho {user.mention} **{quantity}** Task **{task_names[task_type]}**",
        color=0x00FF00
    )
    embed.add_field(
        name="📊 Thông Tin Task Discord",
        value=f"• Join Server: {discord_tasks[user_id_str]['join']}\n• Đổi Tên: {discord_tasks[user_id_str]['rename']}\n• Đổi Avatar: {discord_tasks[user_id_str]['avatar']}",
        inline=False
    )
    await ctx.send(embed=embed)

@bot.command()
async def joinsv(ctx):
    user_id = str(ctx.author.id)
    
    global discord_tasks
    discord_tasks = load_discord_tasks()
    
    if user_id not in discord_tasks or discord_tasks[user_id].get("join", 0) == 0:
        embed = discord.Embed(
            title="❌ Không Có Task",
            description="Bạn Không Có Task Join Server Nào!",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return
    
    ticket_num = await get_next_ticket_number(ctx.guild)
    channel_name = f"ticket-{ticket_num}"
    
    overwrites = {
        ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
        ctx.author: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        bot.user: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    }
    
    ticket_channel = await ctx.guild.create_text_channel(channel_name, overwrites=overwrites)
    
    embed = discord.Embed(
        title="🎯 Join Server Discord",
        description=f"Bot Đã Tạo Cho Bạn Một Kênh Để Nhập Các Thông Tin Cần Thiết\nKênh > {ticket_channel.mention}\nLink Kênh > {ticket_channel.jump_url}",
        color=0x7289da
    )
    embed.set_thumbnail(url="https://cdn.discordapp.com/emojis/852449650185830420.png")
    await ctx.send(embed=embed)
    
    user_tickets[user_id] = {
        'channel_id': ticket_channel.id,
        'action_type': 'join',
        'step': 'upload',
        'tokens': []
    }
    
    welcome_embed = discord.Embed(
        title="📁 Upload File Token",
        description=f"Vui Lòng Tải File Chứa Token Lên Kênh {ctx.author.mention}\nLưu Ý: Mỗi Token Sẽ 1 Dòng File Sẽ Định Dạng Là .txt",
        color=0x00FF00
    )
    
    close_view = CloseTicketView(ticket_channel.id)
    await ticket_channel.send(embed=welcome_embed, view=close_view)

@bot.command()
async def rename(ctx):
    user_id = str(ctx.author.id)
    
    global discord_tasks
    discord_tasks = load_discord_tasks()
    
    if user_id not in discord_tasks or discord_tasks[user_id].get("rename", 0) == 0:
        embed = discord.Embed(
            title="❌ Không Có Task",
            description="Bạn Không Có Task Đổi Tên Nào!",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return
    
    ticket_num = await get_next_ticket_number(ctx.guild)
    channel_name = f"ticket-{ticket_num}"
    
    overwrites = {
        ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
        ctx.author: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        bot.user: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    }
    
    ticket_channel = await ctx.guild.create_text_channel(channel_name, overwrites=overwrites)
    
    embed = discord.Embed(
        title="✏️ Đổi Tên Discord",
        description=f"Bot Đã Tạo Cho Bạn Một Kênh Để Nhập Các Thông Tin Cần Thiết\nKênh > {ticket_channel.mention}\nLink Kênh > {ticket_channel.jump_url}",
        color=0xffa500
    )
    embed.set_thumbnail(url="https://cdn.discordapp.com/emojis/852449650185830420.png")
    await ctx.send(embed=embed)
    
    user_tickets[user_id] = {
        'channel_id': ticket_channel.id,
        'action_type': 'rename',
        'step': 'upload',
        'tokens': []
    }
    
    welcome_embed = discord.Embed(
        title="📁 Upload File Token",
        description=f"Vui Lòng Tải File Chứa Token Lên Kênh {ctx.author.mention}\nLưu Ý: Mỗi Token Sẽ 1 Dòng File Sẽ Định Dạng Là .txt",
        color=0x00FF00
    )
    
    close_view = CloseTicketView(ticket_channel.id)
    await ticket_channel.send(embed=welcome_embed, view=close_view)

@bot.command()
async def changeavt(ctx):
    user_id = str(ctx.author.id)
    
    global discord_tasks
    discord_tasks = load_discord_tasks()
    
    if user_id not in discord_tasks or discord_tasks[user_id].get("avatar", 0) == 0:
        embed = discord.Embed(
            title="❌ Không Có Task",
            description="Bạn Không Có Task Đổi Avatar Nào!",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return
    
    ticket_num = await get_next_ticket_number(ctx.guild)
    channel_name = f"ticket-{ticket_num}"
    
    overwrites = {
        ctx.guild.default_role: discord.PermissionOverwrite(read_messages=False),
        ctx.author: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        bot.user: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    }
    
    ticket_channel = await ctx.guild.create_text_channel(channel_name, overwrites=overwrites)
    
    embed = discord.Embed(
        title="🖼️ Đổi Avatar Discord",
        description=f"Bot Đã Tạo Cho Bạn Một Kênh Để Nhập Các Thông Tin Cần Thiết\nKênh > {ticket_channel.mention}\nLink Kênh > {ticket_channel.jump_url}",
        color=0x9932cc
    )
    embed.set_thumbnail(url="https://cdn.discordapp.com/emojis/852449650185830420.png")
    await ctx.send(embed=embed)
    
    user_tickets[user_id] = {
        'channel_id': ticket_channel.id,
        'action_type': 'avatar',
        'step': 'upload',
        'tokens': []
    }
    
    welcome_embed = discord.Embed(
        title="📁 Upload File Token",
        description=f"Vui Lòng Tải File Chứa Token Lên Kênh {ctx.author.mention}\nLưu Ý: Mỗi Token Sẽ 1 Dòng File Sẽ Định Dạng Là .txt",
        color=0x00FF00
    )
    
    close_view = CloseTicketView(ticket_channel.id)
    await ticket_channel.send(embed=welcome_embed, view=close_view)

@bot.command()
async def dis(ctx):
    embed = discord.Embed(
        title="Bảng Chức Năng Discord",
        description="Button Treo - Dùng Để Treo Discord\nButton Nhây - Dùng Để Nhây Discord Có Fake Typing\nButton Nhây Tag - Nhây Tag Discord Có Fake Typing",
        color=0xFFFFFF
    )
    view = DiscordView()
    await ctx.send(embed=embed, view=view)

DATA_FILE = "udata.json"
CONFIG_FILE = "con..json"

def generate_random_key():
    return "nqh2006"

def load_user_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("Lỗi đọc file JSON, khởi tạo dữ liệu mới.")
            return {"user_keys": {}, "user_nhapkey_count": {}}
    return {"user_keys": {}, "user_nhapkey_count": {}}

def save_user_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("Lỗi đọc file config JSON, khởi tạo dữ liệu mới.")
            return {"task": {}, "task_used": {}}
    return {"task": {}, "task_used": {}}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

@bot.command()
async def getkey(ctx):
    user_id = str(ctx.author.id)
    try:
        data = load_user_data()
        user_keys = data.get("user_keys", {})
        user_nhapkey_count = data.get("user_nhapkey_count", {})
        random_key = generate_random_key()
        user_keys[user_id] = {
            "key": random_key,
            "created_at": datetime.datetime.now().isoformat()
        }
        data["user_keys"] = user_keys
        data["user_nhapkey_count"] = user_nhapkey_count
        save_user_data(data)
        base_url = f"https://tuankiet.com/key?key={random_key}"
        api_url = f"https://link4m.co/st?api=674f23dba1eccf10bc5be3f0&url={base_url}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Referer': 'https://link4m.co/'
        }
        session = requests.Session()
        response = session.get(api_url, headers=headers, allow_redirects=True, timeout=15)
        if response.status_code in [200, 403]:
            shortened_link = response.url
            if shortened_link and shortened_link != api_url:
                current_count = user_nhapkey_count.get(user_id, 0)
                next_task_count = 2 if current_count == 0 else 1
                embed = discord.Embed(
                    title="Vượt Link Để Get Key",
                    description=f"Vượt Lần Đầu Trong Ngày Link Đầu Được 2 Task Lần Sau 1 Task, Task Được Tính Cộng Dồn\n\nLink Get Key > {shortened_link}",
                    color=0xFFFFFF
                )
                embed.add_field(
                    name="📋 Thông Tin",
                    value=f"• Lần Nhập Key Thành Công: {current_count}\n• Task Sẽ Nhận: {next_task_count}",
                    inline=False
                )
                embed.set_footer(text="Sử Dụng Lệnh nhapkey <key> Để Nhận Tasks")
                await ctx.send(embed=embed)
            else:
                embed = discord.Embed(
                    title="Vượt Link Để Get Key",
                    description=f"Vượt Lần Đầu Trong Ngày Link Đầu Được 2 Task Lần Sau 1 Task, Task Được Tính Cộng Dồn\nLink Get Key > {base_url}",
                    color=0xFFFFFF
                )
                embed.add_field(
                    name="📋 Thông Tin",
                    value=f"• Lần Nhập Key Thành Công: {user_nhapkey_count.get(user_id, 0)}\n• Task Sẽ Nhận: {2 if user_nhapkey_count.get(user_id, 0) == 0 else 1}\n• Key: `{random_key}`",
                    inline=False
                )
                embed.set_footer(text="Sử Dụng Lệnh nhapkey <key> Để Nhận Tasks")
                await ctx.send(embed=embed)
        else:
            await ctx.send(f"❌ Lỗi API! Status: {response.status_code}")
    except Exception as e:
        await ctx.send(f"❌ Lỗi: {str(e)}")

@bot.command()
async def nhapkey(ctx, key: str = None):
    if not key:
        embed = discord.Embed(
            title="❌ Lỗi",
            description="Vui Lòng Nhập Key!\nCách Dùng: `!nhapkey <key>`",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return
    
    user_id = str(ctx.author.id)
    
    if key != "nqh2006":
        embed = discord.Embed(
            title="❌ Key Không Đúng",
            description="Key Bạn Nhập Không Đúng!",
            color=0xFF0000
        )
        await ctx.send(embed=embed)
        return
    
    data = load_user_data()
    user_nhapkey_count = data.get("user_nhapkey_count", {})
    
    if user_id not in user_nhapkey_count:
        user_nhapkey_count[user_id] = 0
    
    user_nhapkey_count[user_id] += 1
    data["user_nhapkey_count"] = user_nhapkey_count
    save_user_data(data)
    
    task_count = 2 if user_nhapkey_count[user_id] == 1 else 1
    
    config = load_config()
    if 'task' not in config:
        config['task'] = {}
    if 'task_used' not in config:
        config['task_used'] = {}
    
    current_task = config['task'].get(user_id, 0)
    new_task_count = current_task + task_count
    config['task'][user_id] = new_task_count
    
    used_task = config['task_used'].get(user_id, 0)
    config['task_used'][user_id] = used_task + task_count
    
    save_config(config)
    
    embed = discord.Embed(
        title="✅ Nhận Task Thành Công",
        description=f"Bạn Đã Nhận Được **{task_count}** Task!\n\nTask Hiện Tại: **{new_task_count}**",
        color=0x00FF00
    )
    embed.set_footer(text="Task Đã Được Cộng Dồn Vào Tài Khoản Của Bạn")
    
    await ctx.send(embed=embed)

@bot.command()
async def stoptask(ctx, task_id: str = None):
    if not task_id:
        await ctx.send("Vui Lòng Nhập ID Tasks !")
        return
    
    user_id = str(ctx.author.id)
    is_vip = user_id == config['ownerVIP']
    
    if task_id.lower() == "all":
        if is_vip:
            if os.path.exists('data'):
                import shutil
                shutil.rmtree('data')
                os.makedirs('data')
            embed = discord.Embed(
                title="✅ Đã Xóa Toàn Bộ Task Thành Công ✅",
                color=0x00FF00
            )
            await ctx.send(embed=embed)
            return
        else:
            if not os.path.exists('data'):
                embed = discord.Embed(
                    title="❌ Không Có Task Nào Để Xóa ❌",
                    color=0xFF0000
                )
                await ctx.send(embed=embed)
                return
            
            user_tasks = []
            for folder in os.listdir('data'):
                folder_path = f"data/{folder}"
                if os.path.isdir(folder_path) and os.path.exists(f"{folder_path}/luutru.txt"):
                    with open(f"{folder_path}/luutru.txt", "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    parts = content.split(" | ")
                    task_owner = "Unknown"
                    if parts[3] == "nhay_top_tag" and len(parts) >= 7:
                        task_owner = parts[6]
                    elif parts[3] == "treoso" and len(parts) >= 5:
                        task_owner = parts[4]
                    elif len(parts) >= 5:
                        task_owner = parts[4]
                    
                    if task_owner == user_id:
                        user_tasks.append(folder)
            
            if not user_tasks:
                embed = discord.Embed(
                    title="❌ Không Có Task Nào Để Xóa ❌",
                    color=0xFF0000
                )
                await ctx.send(embed=embed)
                return
            
            for task in user_tasks:
                if task in active_senders:
                    active_senders[task].stop()
                    del active_senders[task]
                import shutil
                shutil.rmtree(f"data/{task}")
            
            embed = discord.Embed(
                title="✅ Đã Xóa Toàn Bộ Task Thành Công ✅",
                color=0x00FF00
            )
            await ctx.send(embed=embed)
            return
    
    elif task_id.lower() == "random":
        if not is_vip:
            embed = discord.Embed(
                title="❌ Chỉ Owner VIP Mới Có Thể Sử Dụng Lệnh Này ❌",
                color=0xFF0000
            )
            await ctx.send(embed=embed)
            return
        
        if not os.path.exists('data'):
            embed = discord.Embed(
                title="❌ Không Có Task Nào Để Xóa ❌",
                color=0xFF0000
            )
            await ctx.send(embed=embed)
            return
        
        all_folders = [f for f in os.listdir('data') if os.path.isdir(f"data/{f}")]
        
        if not all_folders:
            embed = discord.Embed(
                title="❌ Không Có Task Nào Để Xóa ❌",
                color=0xFF0000
            )
            await ctx.send(embed=embed)
            return
        
        import random
        num_to_delete = min(int(random.uniform(5, 15)), len(all_folders))
        folders_to_delete = random.sample(all_folders, num_to_delete)
        
        deleted_tasks = []
        for folder in folders_to_delete:
            if folder in active_senders:
                active_senders[folder].stop()
                del active_senders[folder]
            import shutil
            shutil.rmtree(f"data/{folder}")
            deleted_tasks.append(folder)
        
        task_list = "\n".join([f"> {task}" for task in deleted_tasks])
        
        embed = discord.Embed(
            title="Đã Random Xóa Thành Công Các Task Như Sau",
            description=f"{task_list}\n\nChúc Mn May Mắn Để Không Dính Task Của Mình 🤣🤣",
            color=discord.Colour.from_rgb(255, 20, 147)
        )
        await ctx.send(embed=embed)
        return
    
    else:
        folder_path = f"data/{task_id}"
        if not os.path.exists(folder_path):
            embed = discord.Embed(
                title="❌ ID Tasks Này Không Tồn Tại Hoặc Không Thuộc Quyền Sỡ Hữu Của Bạn ❌",
                color=0xFF0000
            )
            await ctx.send(embed=embed)
            return
        
        if os.path.exists(f"{folder_path}/luutru.txt"):
            with open(f"{folder_path}/luutru.txt", "r", encoding="utf-8") as f:
                content = f.read().strip()
            parts = content.split(" | ")
            task_owner = "Unknown"
            if parts[3] == "nhay_top_tag" and len(parts) >= 7:
                task_owner = parts[6]
            elif parts[3] == "treoso" and len(parts) >= 5:
                task_owner = parts[4]
            elif len(parts) >= 5:
                task_owner = parts[4]
            
            if not is_vip and task_owner != user_id:
                embed = discord.Embed(
                    title="❌ ID Tasks Này Không Tồn Tại Hoặc Không Thuộc Quyền Sỡ Hữu Của Bạn ❌",
                    color=0xFF0000
                )
                await ctx.send(embed=embed)
                return
        
        if task_id in active_senders:
            active_senders[task_id].stop()
            del active_senders[task_id]
        
        import shutil
        shutil.rmtree(folder_path)
        embed = discord.Embed(
            title=f"✅ Xóa Thành Công Tasks > {task_id} ✅",
            color=0x00FF00
        )
        await ctx.send(embed=embed)
        
@bot.command()

async def listbox(ctx):
    embed = discord.Embed(
        title="📋 Lấy Danh Sách Box Facebook",
        description="Ấn Vào Nút **Start** Để Nhập Cookies",
        color=0xFF69B4,
        timestamp=datetime.datetime.utcnow()
    )
    embed.add_field(
        name="📌 Hướng Dẫn",
        value="• Nhập Cookies Facebook\n• Bot Sẽ Tự Động Lấy Tất Cả Box Có Trong Cookies\n• Kết Quả Sẽ Được Hiển Thị Theo Trang",
        inline=False
    )
    embed.set_footer(text="Developed By Ng Quang Huy (Dzi)🪽", icon_url=bot.user.avatar.url if bot.user.avatar else None)
    
    view = ListBoxView()
    await ctx.send(embed=embed, view=view)

@bot.command()

async def nhayzalo(ctx):
    embed = discord.Embed(
        title="Click Vào Nút Start Để Nhập Thông Tin Cần Thiết",
        color=0xFFFFFF
    )
    view = NhayZaloView()
    await ctx.send(embed=embed, view=view)

@bot.command()

async def nhaynamebox(ctx):
    embed = discord.Embed(
        title="Nhây Name Box",
        description="Ấn Vào Button Start Để Bắt Đầu Đổi Tên Box Theo File nhay.txt",
        color=0xFF69B4
    )
    view = NhayNameBoxView()
    await ctx.send(embed=embed, view=view)

@bot.command()

async def nhaypoll(ctx):
    embed = discord.Embed(
        title="Click Vào Nút Bắt Đầu Để Nhập Thông Tin",
        color=0xFFFFFF
    )
    view = NhayPollView()
    await ctx.send(embed=embed, view=view)

@bot.command()
@check_ownervip()
async def addtask(ctx, user: discord.User, quantity: int):
    if user is None or quantity is None:
        await ctx.send("Format: `addtask @user <số_lượng>`")
        return

    if quantity <= 0:
        await ctx.send("Số Lượng Task Phải Lớn Hơn 0.")
        return

    config = load_config()
    if 'task' not in config:
        config['task'] = {}
    if 'admin_added_users' not in config:
        config['admin_added_users'] = {}

    user_id_str = str(user.id)
    
    config['task'][user_id_str] = quantity
    
    config['admin_added_users'][user_id_str] = True
    
    save_config(config)

    embed = discord.Embed(
        title="✅ Thêm Task Thành Công",
        description=f"Đã Cấp Cho {user.mention} Quyền Tạo Tối Đa **{quantity}** Task.\n\n",
        color=0x00FF00
    )
    embed.add_field(
        name="📊 Thông Tin",
        value=f"• Task Được Cấp: {quantity}\n• Loại: Admin Added\n• Sẽ Không Bị Reset Hàng Ngày",
        inline=False
    )
    await ctx.send(embed=embed)

@bot.command()
@check_ownervip()
async def removetask(ctx, user: discord.User):
    if user is None:
        await ctx.send("Format: `removetask @user`")
        return

    config = load_config()
    user_id_str = str(user.id)

    if 'task' in config and user_id_str in config['task']:
        del config['task'][user_id_str]
        save_config(config)
        embed = discord.Embed(
            title="✅ Xóa Task Thành Công",
            description=f"Đã Xóa Quyền Tạo Task Của > {user.mention}.",
            color=0x00FF00
        )
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
            title="❌ Người Dùng Không Tồn Tại",
            description=f"{user.mention} Không Có Trong Danh Sách Được Cấp Tasks.",
            color=0xFF0000
        )
        await ctx.send(embed=embed)

@bot.command()
async def menu(ctx):
    embed = discord.Embed(
        title="📜・MENU BOT",
        description="✨ Bot By **Ng Quang Huy (Dzi)** ✨\n",
        color=discord.Colour.from_rgb(0, 255, 255)
    )
    embed.add_field(
        name="👑・Owner VIP Commands",
        value=(
            f"🔹 **`{config['prefix']}addtask`** — Thêm Task Cho Người Dùng\n"
            f"🔹 **`{config['prefix']}removetask`** — Xoá Task Của Người Dùng\n"
            f"🔹 **`{config['prefix']}addtaskdis`** — Thêm Discord Task (join/rename/avatar)\n\n"
        ),
        inline=False
    )
    embed.add_field(
        name="🔑・Key System",
        value=(
            f"🔑 **`{config['prefix']}getkey`** — Lấy Key Free Để Nhận Task\n"
            f"🔐 **`{config['prefix']}nhapkey`** — Nhập Key Để Nhận Task\n\n"
        ),
        inline=False
    )
    embed.add_field(
        name="🎮・Discord Token Commands",
        value=(
            f"🎯 **`{config['prefix']}joinsv`** — Join Server Discord\n"
            f"✏️ **`{config['prefix']}rename`** — Đổi Tên Discord\n"
            f"🖼️ **`{config['prefix']}changeavt`** — Đổi Avatar Discord\n\n"
        ),
        inline=False
    )
    embed.add_field(
        name="🤖・Mess Commands",
        value=(
            f"📑 **`{config['prefix']}menu`** — Xem Menu Của Bot\n"
            f"💤 **`{config['prefix']}treo`** — Treo Mess (3 Chức Năng)\n"
            f"🎭 **`{config['prefix']}nhay`** — Nhây/Nhây Tag, Mess Fake Soạn\n"
            f"🎯 **`{config['prefix']}nhaytop`** — Nhây Top Tag Post Group\n"
            f"📜 **`{config['prefix']}treoso`** — Treo Sớ Super Múp, Fake Soạn\n"
            f"📝 **`{config['prefix']}danhsachtask`** — Xem Danh Sách Task Của Bạn\n"
            f"🔁 **`{config['prefix']}nhaypoll`** — Nhây Poll Mess Độc Quyền\n"
            f"👤 **`{config['prefix']}listbox`** - Xem Danh Sách Box Của Cookies\n"
            f"🤖 **`{config['prefix']}meta`** — Hỏi Meta AI\n"
            f"💀 **`{config['prefix']}nhaynamebox`** — Nhây Name Box\n\n"
        ),
        inline=False
    )
    embed.add_field(
        name="💿・Zalo Commands",
        value=(
            f"🧩 **`{config['prefix']}nhayzalo`** — Nhây Zalo User And Group\n\n"
        ),
        inline=False
    )
    embed.add_field(
        name="🎭 ・Discord Commands",
        value=(
            f"🔑 **`{config['prefix']}dis`** — Khi Dùng Lệnh Sẽ Ra All Chức Năng Discord\n"
        ),
        inline=False
    )
    embed.add_field(
        name="🤖・Globals Commands",
        value=(
            f"⛔ **`{config['prefix']}stoptask`** — Dừng Task Theo ID Tasks"
        ),
        inline=False
    )
    embed.set_footer(text="✨ Bot by:Ng Quang Huy (Dzi)✨")
    embed.set_thumbnail(url="https://i.postimg.cc/fTx68pTk/IMG-0037.jpg")
    await ctx.send(embed=embed)

@bot.command()
async def treoso(ctx):
    embed = discord.Embed(
        title="Ấn Vào Button Start Để Bắt Đầu Nhập Thông Tin Cần Thiết 📘",
        color=0x0099FF
    )
    view = TreoSoView()
    await ctx.send(embed=embed, view=view)

@bot.event
async def on_disconnect():
    pass

@bot.event
async def on_resumed():
    pass

@bot.event
async def on_error(event, *args, **kwargs):
    print(f"An error occurred in {event}: {args}")

async def main():
    while True:
        try:
            await bot.start(config['tokenbot'], reconnect=True)
        except discord.HTTPException as e:
            if e.status == 429:
                await asyncio.sleep(60)
            else:
                print(f"HTTP Exception: {e}")
                await asyncio.sleep(5)
        except discord.ConnectionClosed:
            print("Connection closed. Reconnecting...")
            await asyncio.sleep(5)
        except Exception as e:
            print(f"Unexpected error: {e}")
            await asyncio.sleep(10)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Bot stopped by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        import sys
        sys.exit(1)