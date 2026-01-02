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
from google.protobuf.message import DecodeError

import like_pb2
import like_count_pb2
import uid_generator_pb2

app = Flask(__name__)

# =====================================================
# LOAD TOKENS — SEMPRE token_bd.json
# =====================================================
def load_tokens():
    url = "https://raw.githubusercontent.com/TSun-FreeFire/TSun-FreeFire-Storage/main/Spam-api/token_bd.json"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()

        if not isinstance(data, list) or len(data) == 0:
            app.logger.error("token_bd.json vazio ou inválido")
            return None

        return data
    except Exception as e:
        app.logger.error(f"Erro ao carregar tokens: {e}")
        return None


# =====================================================
# CRYPTO
# =====================================================
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()
    except Exception as e:
        app.logger.error(f"Erro encrypt: {e}")
        return None


# =====================================================
# LIKE PROTOBUF
# =====================================================
def create_like_protobuf(uid, region):
    msg = like_pb2.like()
    msg.uid = int(uid)
    msg.region = region
    return msg.SerializeToString()


async def send_like(encrypted, token, url):
    try:
        headers = {
            "User-Agent": "Dalvik/2.1.0",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2018.4.11f1",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(encrypted), headers=headers) as r:
                return r.status == 200
    except:
        return False


async def send_multiple_likes(uid, region, url):
    proto = create_like_protobuf(uid, region)
    encrypted = encrypt_message(proto)
    tokens = load_tokens()

    if not encrypted or not tokens:
        return

    random.shuffle(tokens)
    tokens = tokens[:150]

    tasks = [send_like(encrypted, t["token"], url) for t in tokens]
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


def get_player_info(enc, server, token):
    urls = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "PK": "https://clientpk.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    }
    url = urls.get(server, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")

    headers = {
        "User-Agent": "Dalvik/2.1.0",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    r = requests.post(url, data=bytes.fromhex(enc), headers=headers, verify=False)
    data = like_count_pb2.Info()
    data.ParseFromString(r.content)
    return data


# =====================================================
# API ENDPOINT
# =====================================================
@app.route("/like", methods=["GET"])
def like_api():
    uid = request.args.get("uid")
    server = request.args.get("server_name", "").upper()
    key = request.args.get("key")

    if key != "lkteam":
        return jsonify({"error": "Access denied"}), 403

    if not uid or not server:
        return jsonify({"error": "UID ou server_name ausente"}), 400

    tokens = load_tokens()
    if not tokens:
        return jsonify({"error": "Falha ao carregar tokens"}), 500

    token = tokens[0]["token"]
    enc = enc_uid(uid)

    before = get_player_info(enc, server, token)
    before_data = json.loads(MessageToJson(before))
    before_likes = int(before_data["AccountInfo"]["Likes"])

    like_urls = {
        "IND": "https://client.ind.freefiremobile.com/LikeProfile",
        "PK": "https://clientpk.freefiremobile.com/LikeProfile",
        "BR": "https://client.us.freefiremobile.com/LikeProfile",
        "US": "https://client.us.freefiremobile.com/LikeProfile",
        "SAC": "https://client.us.freefiremobile.com/LikeProfile",
        "NA": "https://client.us.freefiremobile.com/LikeProfile",
    }

    asyncio.run(send_multiple_likes(uid, server, like_urls[server]))

    after = get_player_info(enc, server, token)
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
