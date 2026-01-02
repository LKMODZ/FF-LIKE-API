from flask import Flask, request, jsonify
import asyncio
import random
import json
import binascii
import requests
import aiohttp
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson

import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

# =====================================================
# CONFIG FIXA
# =====================================================
SECRET_KEY = "lkteam"
SERVER_REGION = "BR"

PLAYER_INFO_URL = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
LIKE_URL = "https://client.us.freefiremobile.com/LikeProfile"

TOKENS_URL = "https://raw.githubusercontent.com/TSun-FreeFire/TSun-FreeFire-Storage/main/Spam-api/token_bd.json"

# =====================================================
# LOAD TOKENS (APENAS token_bd.json)
# =====================================================
def load_tokens():
    try:
        r = requests.get(TOKENS_URL, timeout=10)
        r.raise_for_status()
        data = r.json()

        if not isinstance(data, list) or len(data) == 0:
            return None

        return data
    except Exception as e:
        app.logger.error(f"Erro ao carregar tokens: {e}")
        return None

# =====================================================
# CRYPTO
# =====================================================
def encrypt_message(data):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return binascii.hexlify(cipher.encrypt(pad(data, AES.block_size))).decode()
    except:
        return None

# =====================================================
# LIKE PROTOBUF
# =====================================================
def create_like_proto(uid):
    msg = like_pb2.like()
    msg.uid = int(uid)
    msg.region = SERVER_REGION
    return msg.SerializeToString()

async def send_like(enc, token):
    headers = {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            LIKE_URL,
            data=bytes.fromhex(enc),
            headers=headers
        ):
            pass

async def send_multiple_likes(uid):
    proto = create_like_proto(uid)
    enc = encrypt_message(proto)
    tokens = load_tokens()

    if not enc or not tokens:
        return

    random.shuffle(tokens)
    tokens = tokens[:150]

    tasks = [
        send_like(enc, t["token"])
        for t in tokens
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

# =====================================================
# UID INFO
# =====================================================
def create_uid_proto(uid):
    msg = uid_generator_pb2.uid_generator()
    msg.saturn_ = int(uid)
    msg.garena = 1
    return msg.SerializeToString()

def enc_uid(uid):
    return encrypt_message(create_uid_proto(uid))

def get_player_info(enc, token):
    headers = {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    r = requests.post(
        PLAYER_INFO_URL,
        data=bytes.fromhex(enc),
        headers=headers,
        verify=False
    )

    info = like_count_pb2.Info()
    info.ParseFromString(r.content)
    return info

# =====================================================
# API
# =====================================================
@app.route("/like", methods=["GET"])
def like_api():
    uid = request.args.get("uid")
    key = request.args.get("key")

    if key != SECRET_KEY:
        return jsonify({"error": "Access denied"}), 403

    if not uid:
        return jsonify({"error": "UID obrigatório"}), 400

    tokens = load_tokens()
    if not tokens:
        return jsonify({"error": "Erro ao carregar tokens"}), 500

    token = tokens[0]["token"]
    enc = enc_uid(uid)

    before = get_player_info(enc, token)
    before_data = json.loads(MessageToJson(before))
    before_likes = int(before_data["AccountInfo"]["Likes"])

    asyncio.run(send_multiple_likes(uid))

    after = get_player_info(enc, token)
    after_data = json.loads(MessageToJson(after))
    after_likes = int(after_data["AccountInfo"]["Likes"])

    return jsonify({
        "UID": uid,
        "PlayerNickname": after_data["AccountInfo"]["PlayerNickname"],
        "LikesBefore": before_likes,
        "LikesAfter": after_likes,
        "LikesGiven": after_likes - before_likes,
        "status": 1 if after_likes > before_likes else 2
    })

# =====================================================
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
