import os
import secrets
import base64
import json
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

EVE_CLIENT_ID = os.environ["EVE_CLIENT_ID"]
EVE_CLIENT_SECRET = os.environ["EVE_CLIENT_SECRET"]
EVE_CALLBACK_URL = os.environ["EVE_CALLBACK_URL"]
FREEBORN_CORPORATION_ID = int(os.environ["FREEBORN_CORPORATION_ID"])

EVE_AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize/"
EVE_TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"
ESI_BASE_URL = "https://esi.evetech.net/latest"


@app.route("/")
def home():
    return """
    <h1>Freeborn Verify</h1>
    <p>EVE Online authentication for Freeborn Legacy.</p>
    <p><a href="/login">Verify with EVE Online</a></p>
    """


@app.route("/health")
def health():
    return {"status": "ok", "service": "freeborn-verify"}


@app.route("/login")
def login():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = {
        "response_type": "code",
        "redirect_uri": EVE_CALLBACK_URL,
        "client_id": EVE_CLIENT_ID,
        "state": state,
    }

    return redirect(f"{EVE_AUTHORIZE_URL}?{urlencode(params)}")


@app.route("/callback")
def callback():
    if request.args.get("state") != session.get("oauth_state"):
        return "Invalid OAuth state.", 400

    code = request.args.get("code")

    if not code:
        return "EVE authentication failed.", 400

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

    payload_part = access_token.split(".")[1]
    payload_part += "=" * (-len(payload_part) % 4)

    payload = json.loads(
        base64.urlsafe_b64decode(payload_part).decode("utf-8")
    )

    character_id = payload["sub"].split(":")[-1]
    character_name = payload.get("name", "Unknown")

    character_response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/",
        timeout=15,
    )

    if character_response.status_code != 200:
        return "Unable to retrieve character information.", 400

    character_data = character_response.json()
    corporation_id = character_data["corporation_id"]

    corporation_response = requests.get(
        f"{ESI_BASE_URL}/corporations/{corporation_id}/",
        timeout=15,
    )

    if corporation_response.status_code != 200:
        return "Unable to retrieve corporation information.", 400

    corporation_data = corporation_response.json()
    corporation_name = corporation_data["name"]

    if corporation_id == FREEBORN_CORPORATION_ID:
        status = "✅ VERIFIED — Freeborn Legacy member"
    else:
        status = "❌ REFUSED — Character is not a Freeborn Legacy member"

    return f"""
    <h1>Freeborn Verify</h1>

    <p><strong>Character:</strong> {character_name}</p>
    <p><strong>Corporation:</strong> {corporation_name}</p>

    <h2>{status}</h2>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
