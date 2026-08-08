import os
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "temporary-dev-key")

EVE_CLIENT_ID = os.environ["EVE_CLIENT_ID"]
EVE_CLIENT_SECRET = os.environ["EVE_CLIENT_SECRET"]
EVE_CALLBACK_URL = os.environ["EVE_CALLBACK_URL"]

EVE_AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize/"
EVE_TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"


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

    return """
    <h1>Freeborn Verify</h1>
    <p>Authentication with EVE Online succeeded.</p>
    <p>Next step: character and corporation verification.</p>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
