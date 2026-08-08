import os
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, redirect, request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from jose import jwt

app = Flask(__name__)

EVE_CLIENT_ID = os.environ["EVE_CLIENT_ID"]
EVE_CLIENT_SECRET = os.environ["EVE_CLIENT_SECRET"]
EVE_CALLBACK_URL = os.environ["EVE_CALLBACK_URL"]

FREEBORN_CORPORATION_ID = int(os.environ["FREEBORN_CORPORATION_ID"])

DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
DISCORD_PUBLIC_KEY = os.environ["DISCORD_PUBLIC_KEY"]
DISCORD_APPLICATION_ID = os.environ["DISCORD_APPLICATION_ID"]
DISCORD_GUILD_ID = os.environ["DISCORD_GUILD_ID"]
DISCORD_MEMBER_ROLE_ID = os.environ["DISCORD_MEMBER_ROLE_ID"]

FLASK_SECRET_KEY = os.environ["FLASK_SECRET_KEY"]

EVE_AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize/"
EVE_TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"
EVE_METADATA_URL = "https://login.eveonline.com/.well-known/oauth-authorization-server"
ESI_BASE_URL = "https://esi.evetech.net/latest"

DISCORD_API = "https://discord.com/api/v10"

state_serializer = URLSafeTimedSerializer(FLASK_SECRET_KEY)


def verify_discord_signature(req):
    signature = req.headers.get("X-Signature-Ed25519")
    timestamp = req.headers.get("X-Signature-Timestamp")

    if not signature or not timestamp:
        return False

    body = req.get_data()

    try:
        verify_key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))
        verify_key.verify(
            timestamp.encode() + body,
            bytes.fromhex(signature),
        )
        return True
    except BadSignatureError:
        return False


def get_eve_identity(access_token):
    metadata = requests.get(EVE_METADATA_URL, timeout=15).json()
    jwks_url = metadata["jwks_uri"]
    jwks = requests.get(jwks_url, timeout=15).json()

    header = jwt.get_unverified_header(access_token)
    key = next(
        key for key in jwks["keys"]
        if key["kid"] == header["kid"]
    )

    payload = jwt.decode(
        access_token,
        key,
        algorithms=["RS256"],
        audience=EVE_CLIENT_ID,
        issuer="https://login.eveonline.com/",
        options={
            "verify_aud": False,
        },
    )

    audiences = payload.get("aud", [])

    if isinstance(audiences, str):
        audiences = [audiences]

    if EVE_CLIENT_ID not in audiences or "EVE Online" not in audiences:
        raise ValueError("Invalid EVE token audience")

    character_id = payload["sub"].split(":")[-1]
    character_name = payload.get("name", "Unknown")

    return character_id, character_name


@app.route("/")
def home():
    return """
    <h1>Freeborn Verify</h1>
    <p>Use <strong>/verify</strong> on the Freeborn Legacy Discord server.</p>
    """


@app.route("/health")
def health():
    return {"status": "ok", "service": "freeborn-verify"}


@app.route("/interactions", methods=["POST"])
def interactions():
    if not verify_discord_signature(request):
        return "Invalid request signature", 401

    data = request.json

    # Discord PING
    if data["type"] == 1:
        return jsonify({"type": 1})

    # Slash command
    if data["type"] == 2 and data["data"]["name"] == "verify":
        discord_user_id = data["member"]["user"]["id"]
        guild_id = data["guild_id"]

        if guild_id != DISCORD_GUILD_ID:
            return jsonify({
                "type": 4,
                "data": {
                    "content": "❌ Cette commande est réservée à Freeborn Legacy.",
                    "flags": 64,
                },
            })

        state = state_serializer.dumps({
            "discord_user_id": discord_user_id,
            "guild_id": guild_id,
        })

        params = {
            "response_type": "code",
            "redirect_uri": EVE_CALLBACK_URL,
            "client_id": EVE_CLIENT_ID,
            "state": state,
        }

        login_url = f"{EVE_AUTHORIZE_URL}?{urlencode(params)}"

        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    "🔐 **Vérification Freeborn Legacy**\n\n"
                    f"[Clique ici pour vérifier ton personnage EVE]({login_url})"
                ),
                "flags": 64,
            },
        })

    return jsonify({
        "type": 4,
        "data": {
            "content": "Commande inconnue.",
            "flags": 64,
        },
    })


@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")

    if not code or not state:
        return "EVE authentication failed.", 400

    try:
        state_data = state_serializer.loads(
            state,
            max_age=600,
        )
    except SignatureExpired:
        return "Verification link expired. Run /verify again.", 400
    except BadSignature:
        return "Invalid verification request.", 400

    discord_user_id = state_data["discord_user_id"]
    guild_id = state_data["guild_id"]

    token_response = requests.post(
        EVE_TOKEN_URL,
        auth=(EVE_CLIENT_ID, EVE_CLIENT_SECRET),
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        timeout=15,
    )

    if token_response.status_code != 200:
        return "Unable to obtain EVE access token.", 400

    access_token = token_response.json()["access_token"]

    try:
        character_id, character_name = get_eve_identity(access_token)
    except Exception:
        return "Unable to validate EVE identity.", 400

    character_response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/",
        timeout=15,
    )

    if character_response.status_code != 200:
        return "Unable to retrieve character information.", 400

    character_data = character_response.json()
    corporation_id = character_data["corporation_id"]

    if corporation_id != FREEBORN_CORPORATION_ID:
        return f"""
        <h1>Freeborn Verify</h1>
        <p><strong>{character_name}</strong></p>
        <h2>❌ REFUSED</h2>
        <p>Ce personnage n'appartient pas à Freeborn Legacy.</p>
        """

    role_url = (
        f"{DISCORD_API}/guilds/{guild_id}/members/"
        f"{discord_user_id}/roles/{DISCORD_MEMBER_ROLE_ID}"
    )

    role_response = requests.put(
        role_url,
        headers={
            "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        },
        timeout=15,
    )

    if role_response.status_code not in (204, 200):
        return (
            "EVE verification succeeded, but Discord role assignment failed.",
            500,
        )

    return f"""
    <h1>Freeborn Verify</h1>
    <p><strong>Character:</strong> {character_name}</p>
    <p><strong>Corporation:</strong> Freeborn Legacy</p>

    <h2>✅ VERIFIED</h2>

    <p>Le rôle Discord <strong>Membre</strong> a été attribué.</p>
    <p>Tu peux maintenant retourner sur Discord.</p>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
