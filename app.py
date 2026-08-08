import os
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from jose import jwt


# ============================================================
# FREEBORN VERIFY
# EVE Online SSO <-> Discord
# ============================================================

app = Flask(__name__)


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

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


# ============================================================
# URLS
# ============================================================

EVE_AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize/"
EVE_TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"
EVE_METADATA_URL = (
    "https://login.eveonline.com/.well-known/oauth-authorization-server"
)

ESI_BASE_URL = "https://esi.evetech.net/latest"

DISCORD_API = "https://discord.com/api/v10"


# ============================================================
# STATE SECURITY
# ============================================================

state_serializer = URLSafeTimedSerializer(FLASK_SECRET_KEY)


# ============================================================
# DISCORD SIGNATURE VERIFICATION
# ============================================================

def verify_discord_signature(req):

    signature = req.headers.get("X-Signature-Ed25519")
    timestamp = req.headers.get("X-Signature-Timestamp")

    if not signature or not timestamp:
        return False

    body = req.get_data()

    try:

        verify_key = VerifyKey(
            bytes.fromhex(DISCORD_PUBLIC_KEY)
        )

        verify_key.verify(
            timestamp.encode() + body,
            bytes.fromhex(signature),
        )

        return True

    except (BadSignatureError, ValueError):
        return False


# ============================================================
# EVE TOKEN VERIFICATION
# ============================================================

def get_eve_identity(access_token):

    metadata_response = requests.get(
        EVE_METADATA_URL,
        timeout=15,
    )

    metadata_response.raise_for_status()

    metadata = metadata_response.json()

    jwks_response = requests.get(
        metadata["jwks_uri"],
        timeout=15,
    )

    jwks_response.raise_for_status()

    jwks = jwks_response.json()

    header = jwt.get_unverified_header(access_token)

    key = next(
        key
        for key in jwks["keys"]
        if key["kid"] == header["kid"]
    )

    payload = jwt.decode(
        access_token,
        key,
        algorithms=["RS256"],
        issuer="https://login.eveonline.com/",
        options={
            "verify_aud": False,
        },
    )

    audiences = payload.get("aud", [])

    if isinstance(audiences, str):
        audiences = [audiences]

    if (
        EVE_CLIENT_ID not in audiences
        and "EVE Online" not in audiences
    ):
        raise ValueError("Invalid EVE token audience")

    character_id = payload["sub"].split(":")[-1]
    character_name = payload.get("name", "Unknown")

    return character_id, character_name


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return """
    <h1>Freeborn Verify</h1>

    <p>
    Service de vérification EVE Online
    pour Freeborn Legacy.
    </p>

    <p>
    Utilisez <strong>/verify</strong>
    sur le serveur Discord Freeborn Legacy.
    </p>
    """


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return {
        "status": "ok",
        "service": "freeborn-verify",
    }


# ============================================================
# DISCORD INTERACTIONS
# ============================================================

@app.route("/interactions", methods=["POST"])
def interactions():

    if not verify_discord_signature(request):
        return "Invalid request signature", 401

    data = request.get_json()


    # --------------------------------------------------------
    # DISCORD PING
    # --------------------------------------------------------

    if data["type"] == 1:

        return jsonify({
            "type": 1
        })


    # --------------------------------------------------------
    # /verify
    # --------------------------------------------------------

    if (
        data["type"] == 2
        and data["data"]["name"] == "verify"
    ):

        discord_user_id = data["member"]["user"]["id"]
        guild_id = data["guild_id"]


        # Security check:
        # command must originate from Freeborn Legacy

        if guild_id != DISCORD_GUILD_ID:

            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "❌ Cette commande est réservée "
                        "au serveur Freeborn Legacy.",
                    "flags": 64,
                },
            })


        # Secure state linking:
        # Discord user <-> EVE authentication

        state = state_serializer.dumps({
            "discord_user_id": discord_user_id,
            "guild_id": guild_id,
        })


        # EVE SSO URL

        params = {
            "response_type": "code",
            "redirect_uri": EVE_CALLBACK_URL,
            "client_id": EVE_CLIENT_ID,
            "state": state,
        }

        login_url = (
            f"{EVE_AUTHORIZE_URL}?"
            f"{urlencode(params)}"
        )


        # Private Discord response

        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    "🔐 **Freeborn Verify**\n\n"
                    "Pour vérifier ton appartenance "
                    "à **Freeborn Legacy**, connecte "
                    "ton personnage EVE Online :\n\n"
                    f"[Vérifier mon personnage EVE]"
                    f"({login_url})"
                ),
                "flags": 64,
            },
        })


    # Unknown command

    return jsonify({
        "type": 4,
        "data": {
            "content": "Commande inconnue.",
            "flags": 64,
        },
    })


# ============================================================
# EVE CALLBACK
# ============================================================

@app.route("/callback")
def callback():

    code = request.args.get("code")
    state = request.args.get("state")


    if not code or not state:

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Authentication failed</h2>
        """, 400


    # --------------------------------------------------------
    # VALIDATE STATE
    # --------------------------------------------------------

    try:

        state_data = state_serializer.loads(
            state,
            max_age=600,
        )

    except SignatureExpired:

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Verification link expired</h2>
        <p>Relance /verify sur Discord.</p>
        """, 400

    except BadSignature:

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Invalid verification request</h2>
        """, 400


    discord_user_id = state_data["discord_user_id"]
    guild_id = state_data["guild_id"]


    # --------------------------------------------------------
    # EXCHANGE CODE FOR EVE TOKEN
    # --------------------------------------------------------

    token_response = requests.post(
        EVE_TOKEN_URL,
        auth=(
            EVE_CLIENT_ID,
            EVE_CLIENT_SECRET,
        ),
        data={
            "grant_type": "authorization_code",
            "code": code,
        },
        timeout=15,
    )


    if token_response.status_code != 200:

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Unable to obtain EVE access token</h2>
        """, 400


    access_token = token_response.json()["access_token"]


    # --------------------------------------------------------
    # VERIFY EVE IDENTITY
    # --------------------------------------------------------

    try:

        character_id, character_name = (
            get_eve_identity(access_token)
        )

    except Exception as error:

        print(
            "EVE identity verification failed:",
            repr(error),
        )

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Unable to validate EVE identity</h2>
        """, 400


    # --------------------------------------------------------
    # GET CHARACTER INFORMATION FROM ESI
    # --------------------------------------------------------

    character_response = requests.get(
        f"{ESI_BASE_URL}/characters/{character_id}/",
        timeout=15,
    )


    if character_response.status_code != 200:

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Unable to retrieve character information</h2>
        """, 400


    character_data = character_response.json()

    corporation_id = character_data["corporation_id"]


    # --------------------------------------------------------
    # FREEBORN LEGACY CORPORATION CHECK
    # --------------------------------------------------------

    if corporation_id != FREEBORN_CORPORATION_ID:

        return f"""
        <h1>Freeborn Verify</h1>

        <p>
        <strong>Character:</strong>
        {character_name}
        </p>

        <h2>❌ REFUSED</h2>

        <p>
        Ce personnage n'appartient pas
        à Freeborn Legacy.
        </p>
        """


    # --------------------------------------------------------
    # ADD DISCORD MEMBER ROLE
    # --------------------------------------------------------

    role_url = (
        f"{DISCORD_API}/guilds/"
        f"{guild_id}/members/"
        f"{discord_user_id}/roles/"
        f"{DISCORD_MEMBER_ROLE_ID}"
    )


    role_response = requests.put(
        role_url,
        headers={
            "Authorization":
                f"Bot {DISCORD_BOT_TOKEN}",
        },
        timeout=15,
    )


    if role_response.status_code not in (200, 204):

        print(
            "Discord role assignment failed:",
            role_response.status_code,
            role_response.text,
        )

        return """
        <h1>Freeborn Verify</h1>

        <h2>⚠️ EVE verification succeeded</h2>

        <p>
        Mais l'attribution du rôle Discord
        a échoué.
        </p>
        """, 500


    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    return f"""
    <h1>Freeborn Verify</h1>

    <p>
    <strong>Character:</strong>
    {character_name}
    </p>

    <p>
    <strong>Corporation:</strong>
    Freeborn Legacy
    </p>

    <h2>✅ VERIFIED</h2>

    <p>
    Le rôle Discord <strong>Membre</strong>
    a été attribué.
    </p>

    <p>
    Tu peux maintenant retourner sur Discord.
    </p>
    """


# ============================================================
# REGISTER DISCORD /verify COMMAND
# ============================================================

def register_verify_command():

    url = (
        f"{DISCORD_API}/applications/"
        f"{DISCORD_APPLICATION_ID}/guilds/"
        f"{DISCORD_GUILD_ID}/commands"
    )


    commands = [
        {
            "name": "verify",
            "description":
                "Vérifier ton personnage EVE pour Freeborn Legacy",
            "type": 1,
        }
    ]


    try:

        response = requests.put(
            url,
            headers={
                "Authorization":
                    f"Bot {DISCORD_BOT_TOKEN}",
                "Content-Type":
                    "application/json",
            },
            json=commands,
            timeout=15,
        )


        if response.status_code == 200:

            print(
                "Discord command /verify registered."
            )

        else:

            print(
                "Unable to register Discord command:",
                response.status_code,
                response.text,
            )

    except Exception as error:

        print(
            "Discord command registration error:",
            repr(error),
        )


# Register command when Render starts

register_verify_command()


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            10000,
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
    )
