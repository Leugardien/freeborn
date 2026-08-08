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

FREEBORN_CORPORATION_ID = int(
    os.environ["FREEBORN_CORPORATION_ID"]
)

DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
DISCORD_PUBLIC_KEY = os.environ["DISCORD_PUBLIC_KEY"]
DISCORD_APPLICATION_ID = os.environ["DISCORD_APPLICATION_ID"]
DISCORD_GUILD_ID = os.environ["DISCORD_GUILD_ID"]
DISCORD_MEMBER_ROLE_ID = os.environ["DISCORD_MEMBER_ROLE_ID"]

FLASK_SECRET_KEY = os.environ["FLASK_SECRET_KEY"]


# ============================================================
# URLS
# ============================================================

EVE_AUTHORIZE_URL = (
    "https://login.eveonline.com/v2/oauth/authorize/"
)

EVE_TOKEN_URL = (
    "https://login.eveonline.com/v2/oauth/token"
)

EVE_METADATA_URL = (
    "https://login.eveonline.com/"
    ".well-known/oauth-authorization-server"
)

ESI_BASE_URL = (
    "https://esi.evetech.net/latest"
)

DISCORD_API = (
    "https://discord.com/api/v10"
)


# ============================================================
# VALID EVE ISSUERS
# ============================================================

VALID_EVE_ISSUERS = {
    "login.eveonline.com",
    "https://login.eveonline.com",
}


# ============================================================
# STATE SECURITY
# ============================================================

state_serializer = URLSafeTimedSerializer(
    FLASK_SECRET_KEY
)


# ============================================================
# DISCORD SIGNATURE VERIFICATION
# ============================================================

def verify_discord_signature(req):

    signature = req.headers.get(
        "X-Signature-Ed25519"
    )

    timestamp = req.headers.get(
        "X-Signature-Timestamp"
    )

    if not signature or not timestamp:
        return False

    body = req.get_data()

    try:

        verify_key = VerifyKey(
            bytes.fromhex(
                DISCORD_PUBLIC_KEY
            )
        )

        verify_key.verify(
            timestamp.encode() + body,
            bytes.fromhex(signature),
        )

        return True

    except (
        BadSignatureError,
        ValueError,
    ):
        return False


# ============================================================
# EVE TOKEN VERIFICATION
# ============================================================

def get_eve_identity(access_token):

    # --------------------------------------------------------
    # GET EVE SSO METADATA
    # --------------------------------------------------------

    metadata_response = requests.get(
        EVE_METADATA_URL,
        timeout=15,
    )

    metadata_response.raise_for_status()

    metadata = metadata_response.json()


    # --------------------------------------------------------
    # GET EVE PUBLIC SIGNING KEYS
    # --------------------------------------------------------

    jwks_response = requests.get(
        metadata["jwks_uri"],
        timeout=15,
    )

    jwks_response.raise_for_status()

    jwks = jwks_response.json()


    # --------------------------------------------------------
    # READ JWT HEADER
    # --------------------------------------------------------

    header = jwt.get_unverified_header(
        access_token
    )

    algorithm = header.get("alg")
    key_id = header.get("kid")


    if algorithm != "RS256":
        raise ValueError(
            f"Unexpected JWT algorithm: {algorithm}"
        )


    # --------------------------------------------------------
    # FIND MATCHING CCP SIGNING KEY
    # --------------------------------------------------------

    matching_keys = [
        key
        for key in jwks["keys"]
        if (
            key.get("kid") == key_id
            and key.get("alg") == algorithm
        )
    ]


    if not matching_keys:
        raise ValueError(
            "Unable to find matching EVE signing key"
        )


    signing_key = matching_keys[0]


    # --------------------------------------------------------
    # VERIFY JWT
    #
    # Signature: VERIFIED
    # Expiration: VERIFIED automatically
    # Audience "EVE Online": VERIFIED
    #
    # Issuer is checked manually below because CCP supports
    # more than one valid issuer representation.
    # --------------------------------------------------------

    payload = jwt.decode(
        access_token,
        key=signing_key,
        algorithms=["RS256"],
        audience="EVE Online",
        options={
            "verify_iss": False,
        },
    )


    # --------------------------------------------------------
    # VERIFY ISSUER MANUALLY
    # --------------------------------------------------------

    issuer = payload.get(
        "iss",
        ""
    )

    normalized_issuer = (
        issuer.rstrip("/")
    )


    if normalized_issuer not in VALID_EVE_ISSUERS:

        raise ValueError(
            f"Invalid EVE issuer: {issuer}"
        )


    # --------------------------------------------------------
    # VERIFY APPLICATION CLIENT ID
    # --------------------------------------------------------

    audiences = payload.get(
        "aud",
        []
    )


    if isinstance(
        audiences,
        str,
    ):
        audiences = [audiences]


    if "EVE Online" not in audiences:

        raise ValueError(
            "EVE Online audience missing"
        )


    if EVE_CLIENT_ID not in audiences:

        raise ValueError(
            "Application Client ID missing "
            "from EVE token audience"
        )


    # --------------------------------------------------------
    # GET CHARACTER IDENTITY
    # --------------------------------------------------------

    subject = payload.get(
        "sub",
        ""
    )


    if not subject.startswith(
        "CHARACTER:EVE:"
    ):

        raise ValueError(
            "Invalid EVE character subject"
        )


    character_id = (
        subject.split(":")[-1]
    )

    character_name = payload.get(
        "name",
        "Unknown",
    )


    return (
        character_id,
        character_name,
    )


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

@app.route(
    "/interactions",
    methods=["POST"],
)
def interactions():

    if not verify_discord_signature(
        request
    ):

        return (
            "Invalid request signature",
            401,
        )


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
        and
        data["data"]["name"] == "verify"
    ):

        discord_user_id = (
            data["member"]["user"]["id"]
        )

        guild_id = (
            data["guild_id"]
        )


        # ----------------------------------------------------
        # VERIFY SERVER
        # ----------------------------------------------------

        if guild_id != DISCORD_GUILD_ID:

            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "❌ Cette commande est "
                        "réservée au serveur "
                        "Freeborn Legacy.",
                    "flags": 64,
                },
            })


        # ----------------------------------------------------
        # CREATE SECURE STATE
        # ----------------------------------------------------

        state = (
            state_serializer.dumps({
                "discord_user_id":
                    discord_user_id,

                "guild_id":
                    guild_id,
            })
        )


        # ----------------------------------------------------
        # CREATE EVE LOGIN URL
        # ----------------------------------------------------

        params = {
            "response_type":
                "code",

            "redirect_uri":
                EVE_CALLBACK_URL,

            "client_id":
                EVE_CLIENT_ID,

            "state":
                state,
        }


        login_url = (
            f"{EVE_AUTHORIZE_URL}?"
            f"{urlencode(params)}"
        )


        # ----------------------------------------------------
        # PRIVATE DISCORD RESPONSE
        # ----------------------------------------------------

        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    "🔐 **Freeborn Verify**\n\n"

                    "Pour vérifier ton "
                    "appartenance à "
                    "**Freeborn Legacy**, "
                    "connecte ton personnage "
                    "EVE Online :\n\n"

                    f"[Vérifier mon personnage EVE]"
                    f"({login_url})"
                ),

                "flags": 64,
            },
        })


    return jsonify({
        "type": 4,
        "data": {
            "content":
                "Commande inconnue.",

            "flags": 64,
        },
    })


# ============================================================
# EVE CALLBACK
# ============================================================

@app.route("/callback")
def callback():

    code = request.args.get(
        "code"
    )

    state = request.args.get(
        "state"
    )


    if not code or not state:

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Authentication failed
        </h2>
        """, 400


    # --------------------------------------------------------
    # VALIDATE STATE
    # --------------------------------------------------------

    try:

        state_data = (
            state_serializer.loads(
                state,
                max_age=600,
            )
        )

    except SignatureExpired:

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Verification link expired
        </h2>

        <p>
        Relance /verify sur Discord.
        </p>
        """, 400


    except BadSignature:

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Invalid verification request
        </h2>
        """, 400


    discord_user_id = (
        state_data[
            "discord_user_id"
        ]
    )

    guild_id = (
        state_data[
            "guild_id"
        ]
    )


    # --------------------------------------------------------
    # SECURITY CHECK
    # --------------------------------------------------------

    if guild_id != DISCORD_GUILD_ID:

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Invalid Discord server
        </h2>
        """, 400


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
            "grant_type":
                "authorization_code",

            "code":
                code,
        },

        timeout=15,
    )


    if token_response.status_code != 200:

        print(
            "EVE token request failed:",
            token_response.status_code,
            token_response.text,
        )

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Unable to obtain EVE access token
        </h2>
        """, 400


    access_token = (
        token_response
        .json()[
            "access_token"
        ]
    )


    # --------------------------------------------------------
    # VERIFY EVE IDENTITY
    # --------------------------------------------------------

    try:

        (
            character_id,
            character_name,
        ) = get_eve_identity(
            access_token
        )


    except Exception as error:

        print(
            "EVE identity verification failed:",
            repr(error),
        )

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Unable to validate EVE identity
        </h2>
        """, 400


    # --------------------------------------------------------
    # GET CHARACTER INFORMATION
    # --------------------------------------------------------

    character_response = requests.get(
        (
            f"{ESI_BASE_URL}/characters/"
            f"{character_id}/"
        ),

        timeout=15,
    )


    if character_response.status_code != 200:

        print(
            "ESI character lookup failed:",
            character_response.status_code,
            character_response.text,
        )

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ❌ Unable to retrieve
        character information
        </h2>
        """, 400


    character_data = (
        character_response.json()
    )

    corporation_id = (
        character_data[
            "corporation_id"
        ]
    )


    # --------------------------------------------------------
    # FREEBORN LEGACY CHECK
    # --------------------------------------------------------

    if (
        corporation_id
        !=
        FREEBORN_CORPORATION_ID
    ):

        return f"""
        <h1>Freeborn Verify</h1>

        <p>
        <strong>Character:</strong>
        {character_name}
        </p>

        <h2>
        ❌ REFUSED
        </h2>

        <p>
        Ce personnage n'appartient
        pas à Freeborn Legacy.
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


    if (
        role_response.status_code
        not in
        (200, 204)
    ):

        print(
            "Discord role assignment failed:",
            role_response.status_code,
            role_response.text,
        )

        return """
        <h1>Freeborn Verify</h1>

        <h2>
        ⚠️ EVE verification succeeded
        </h2>

        <p>
        Mais l'attribution du rôle
        Discord a échoué.
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

    <h2>
    ✅ VERIFIED
    </h2>

    <p>
    Le rôle Discord
    <strong>Membre</strong>
    a été attribué.
    </p>

    <p>
    Tu peux maintenant
    retourner sur Discord.
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
            "name":
                "verify",

            "description":
                "Vérifier ton personnage EVE "
                "pour Freeborn Legacy",

            "type":
                1,
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
                "Discord command "
                "/verify registered."
            )


        else:

            print(
                "Unable to register "
                "Discord command:",

                response.status_code,

                response.text,
            )


    except Exception as error:

        print(
            "Discord command "
            "registration error:",

            repr(error),
        )


# ============================================================
# REGISTER COMMAND
# ============================================================

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
