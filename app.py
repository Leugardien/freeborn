import os
from urllib.parse import urlencode

import psycopg
import requests
from flask import Flask, jsonify, request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from jose import jwt


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
DISCORD_RECRUIT_ROLE_ID = os.environ["DISCORD_RECRUIT_ROLE_ID"]
DISCORD_EVE_VERIFIED_ROLE_ID = os.environ[
    "DISCORD_EVE_VERIFIED_ROLE_ID"
]
DISCORD_MAIN_CHARACTER_ROLE_ID = os.environ[
    "DISCORD_MAIN_CHARACTER_ROLE_ID"
]
DISCORD_ALT_CHARACTER_ROLE_ID = os.environ[
    "DISCORD_ALT_CHARACTER_ROLE_ID"
]

FLASK_SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]


# ============================================================
# URLS
# ============================================================

EVE_AUTHORIZE_URL = "https://login.eveonline.com/v2/oauth/authorize/"
EVE_TOKEN_URL = "https://login.eveonline.com/v2/oauth/token"

EVE_METADATA_URL = (
    "https://login.eveonline.com/"
    ".well-known/oauth-authorization-server"
)

ESI_BASE_URL = "https://esi.evetech.net/latest"
DISCORD_API = "https://discord.com/api/v10"


VALID_EVE_ISSUERS = {
    "login.eveonline.com",
    "https://login.eveonline.com",
}


state_serializer = URLSafeTimedSerializer(
    FLASK_SECRET_KEY
)


# ============================================================
# DATABASE
# ============================================================

def init_database():
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS eve_characters (
                        character_id BIGINT PRIMARY KEY,
                        discord_user_id TEXT NOT NULL,
                        character_name TEXT NOT NULL,
                        character_type TEXT NOT NULL
                            CHECK (
                                character_type IN ('main', 'alt')
                            ),
                        corporation_id BIGINT NOT NULL,
                        verified_at TIMESTAMPTZ
                            NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ
                            NOT NULL DEFAULT NOW()
                    );
                    """
                )

            conn.commit()

        print(
            "Database connection OK - "
            "eve_characters table ready."
        )

    except Exception as error:
        print(
            "Database initialization failed:",
            repr(error),
        )


def has_main_character(discord_user_id):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM eve_characters
                    WHERE discord_user_id = %s
                    AND character_type = 'main'
                );
                """,
                (
                    str(discord_user_id),
                ),
            )

            return cur.fetchone()[0]


def get_character_record(character_id):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    discord_user_id,
                    character_name,
                    character_type
                FROM eve_characters
                WHERE character_id = %s;
                """,
                (
                    int(character_id),
                ),
            )

            return cur.fetchone()


def save_main_character(
    discord_user_id,
    character_id,
    character_name,
    corporation_id,
):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO eve_characters (
                    character_id,
                    discord_user_id,
                    character_name,
                    character_type,
                    corporation_id
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'main',
                    %s
                )
                ON CONFLICT (character_id)
                DO UPDATE SET
                    discord_user_id = EXCLUDED.discord_user_id,
                    character_name = EXCLUDED.character_name,
                    character_type = 'main',
                    corporation_id = EXCLUDED.corporation_id,
                    updated_at = NOW();
                """,
                (
                    int(character_id),
                    str(discord_user_id),
                    character_name,
                    int(corporation_id),
                ),
            )

        conn.commit()


def save_alt_character(
    discord_user_id,
    character_id,
    character_name,
    corporation_id,
):
    existing = get_character_record(
        character_id
    )

    if existing:
        existing_discord_user_id = existing[0]
        existing_character_type = existing[2]

        if (
            existing_discord_user_id
            != str(discord_user_id)
        ):
            raise ValueError(
                "Character already linked "
                "to another Discord account"
            )

        if existing_character_type == "main":
            raise ValueError(
                "Main character cannot be added as alt"
            )

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO eve_characters (
                    character_id,
                    discord_user_id,
                    character_name,
                    character_type,
                    corporation_id
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'alt',
                    %s
                )
                ON CONFLICT (character_id)
                DO UPDATE SET
                    character_name = EXCLUDED.character_name,
                    corporation_id = EXCLUDED.corporation_id,
                    updated_at = NOW();
                """,
                (
                    int(character_id),
                    str(discord_user_id),
                    character_name,
                    int(corporation_id),
                ),
            )

        conn.commit()


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
            bytes.fromhex(DISCORD_PUBLIC_KEY)
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

    header = jwt.get_unverified_header(
        access_token
    )

    algorithm = header.get("alg")
    key_id = header.get("kid")

    if algorithm != "RS256":
        raise ValueError(
            f"Unexpected JWT algorithm: {algorithm}"
        )

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

    payload = jwt.decode(
        access_token,
        key=signing_key,
        algorithms=["RS256"],
        audience="EVE Online",
        options={
            "verify_iss": False,
        },
    )

    issuer = payload.get("iss", "")
    normalized_issuer = issuer.rstrip("/")

    if normalized_issuer not in VALID_EVE_ISSUERS:
        raise ValueError(
            f"Invalid EVE issuer: {issuer}"
        )

    audiences = payload.get(
        "aud",
        [],
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

    subject = payload.get(
        "sub",
        "",
    )

    if not subject.startswith(
        "CHARACTER:EVE:"
    ):
        raise ValueError(
            "Invalid EVE character subject"
        )

    character_id = subject.split(":")[-1]

    character_name = payload.get(
        "name",
        "Unknown",
    )

    return (
        character_id,
        character_name,
    )


# ============================================================
# DISCORD ROLE HELPERS
# ============================================================

def add_discord_role(
    guild_id,
    user_id,
    role_id,
):
    role_url = (
        f"{DISCORD_API}/guilds/"
        f"{guild_id}/members/"
        f"{user_id}/roles/"
        f"{role_id}"
    )

    return requests.put(
        role_url,
        headers={
            "Authorization":
                f"Bot {DISCORD_BOT_TOKEN}",
        },
        timeout=15,
    )


def remove_discord_role(
    guild_id,
    user_id,
    role_id,
):
    role_url = (
        f"{DISCORD_API}/guilds/"
        f"{guild_id}/members/"
        f"{user_id}/roles/"
        f"{role_id}"
    )

    return requests.delete(
        role_url,
        headers={
            "Authorization":
                f"Bot {DISCORD_BOT_TOKEN}",
        },
        timeout=15,
    )


# ============================================================
# HOME
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
    Commandes Discord :
    <strong>/verify</strong> et
    <strong>/alt</strong>.
    </p>
    """


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():
    return {
        "status": "ok",
        "service": "freeborn-verify",
    }


@app.route("/db-health")
def db_health():
    try:
        with psycopg.connect(
            DATABASE_URL
        ) as conn:

            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM eve_characters;
                    """
                )

                character_count = (
                    cur.fetchone()[0]
                )

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM eve_characters
                    WHERE character_type = 'main';
                    """
                )

                main_count = (
                    cur.fetchone()[0]
                )

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM eve_characters
                    WHERE character_type = 'alt';
                    """
                )

                alt_count = (
                    cur.fetchone()[0]
                )

        return {
            "status": "ok",
            "database": "connected",
            "table": "eve_characters",
            "characters": character_count,
            "mains": main_count,
            "alts": alt_count,
        }

    except Exception as error:
        print(
            "Database health check failed:",
            repr(error),
        )

        return {
            "status": "error",
            "database": "unavailable",
        }, 500


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

    if data["type"] == 1:
        return jsonify({
            "type": 1
        })

    if data["type"] != 2:
        return jsonify({
            "type": 4,
            "data": {
                "content":
                    "Commande inconnue.",
                "flags": 64,
            },
        })

    command_name = (
        data["data"]["name"]
    )

    discord_user_id = (
        data["member"]["user"]["id"]
    )

    guild_id = (
        data["guild_id"]
    )

    if guild_id != DISCORD_GUILD_ID:
        return jsonify({
            "type": 4,
            "data": {
                "content":
                    "❌ Cette commande "
                    "est réservée au serveur "
                    "Freeborn Legacy.",
                "flags": 64,
            },
        })

    if command_name == "verify":
        verification_type = "main"

    elif command_name == "alt":
        verification_type = "alt"

        try:
            main_exists = has_main_character(
                discord_user_id
            )

        except Exception as error:
            print(
                "Main character lookup failed:",
                repr(error),
            )

            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "⚠️ Impossible de vérifier "
                        "ton personnage principal "
                        "pour le moment.",
                    "flags": 64,
                },
            })

        if not main_exists:
            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "❌ Tu dois d'abord "
                        "enregistrer ton personnage "
                        "principal avec **/verify** "
                        "avant d'ajouter un alt.",
                    "flags": 64,
                },
            })

    else:
        return jsonify({
            "type": 4,
            "data": {
                "content":
                    "Commande inconnue.",
                "flags": 64,
            },
        })

    state = (
        state_serializer.dumps({
            "discord_user_id":
                discord_user_id,

            "guild_id":
                guild_id,

            "verification_type":
                verification_type,
        })
    )

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

    if verification_type == "main":
        message = (
            "🔐 **Freeborn Verify**\n\n"
            "Pour vérifier ton appartenance "
            "à **Freeborn Legacy**, "
            "connecte ton personnage "
            "principal EVE Online :\n\n"
            f"[Vérifier mon personnage EVE]"
            f"({login_url})"
        )

    else:
        message = (
            "🔗 **Freeborn Alt Verify**\n\n"
            "Sélectionne le personnage EVE "
            "que tu souhaites enregistrer "
            "comme **Alt Character** :\n\n"
            f"[Ajouter mon Alt EVE]"
            f"({login_url})"
        )

    return jsonify({
        "type": 4,
        "data": {
            "content": message,
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
        <h2>❌ Authentication failed</h2>
        """, 400

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
        <h2>❌ Verification link expired</h2>
        <p>Relance la commande sur Discord.</p>
        """, 400

    except BadSignature:
        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Invalid verification request</h2>
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

    verification_type = (
        state_data.get(
            "verification_type",
            "main",
        )
    )

    if guild_id != DISCORD_GUILD_ID:
        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Invalid Discord server</h2>
        """, 400

    if verification_type not in (
        "main",
        "alt",
    ):
        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Invalid verification type</h2>
        """, 400

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
        <h2>❌ Unable to obtain EVE access token</h2>
        """, 400

    access_token = (
        token_response
        .json()[
            "access_token"
        ]
    )

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
        <h2>❌ Unable to validate EVE identity</h2>
        """, 400

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
        <h2>❌ Unable to retrieve character information</h2>
        """, 400

    character_data = (
        character_response.json()
    )

    corporation_id = (
        character_data[
            "corporation_id"
        ]
    )

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

        <h2>❌ REFUSED</h2>

        <p>
        Ce personnage n'appartient
        pas à Freeborn Legacy.
        </p>
        """

    # ========================================================
    # MAIN CHARACTER FLOW
    # ========================================================

    if verification_type == "main":

        member_role_response = (
            add_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_MEMBER_ROLE_ID,
            )
        )

        if (
            member_role_response.status_code
            not in
            (200, 204)
        ):
            return """
            <h1>Freeborn Verify</h1>
            <h2>⚠️ Verification succeeded</h2>
            <p>
            L'attribution du rôle Membre
            a échoué.
            </p>
            """, 500

        eve_verified_response = (
            add_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_EVE_VERIFIED_ROLE_ID,
            )
        )

        if (
            eve_verified_response.status_code
            not in
            (200, 204)
        ):
            return """
            <h1>Freeborn Verify</h1>
            <h2>⚠️ Verification succeeded</h2>
            <p>
            L'attribution du rôle
            EVE Verified a échoué.
            </p>
            """, 500

        main_character_response = (
            add_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_MAIN_CHARACTER_ROLE_ID,
            )
        )

        if (
            main_character_response.status_code
            not in
            (200, 204)
        ):
            return """
            <h1>Freeborn Verify</h1>
            <h2>⚠️ Verification succeeded</h2>
            <p>
            L'attribution du rôle
            Main Character a échoué.
            </p>
            """, 500

        recruit_role_response = (
            remove_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_RECRUIT_ROLE_ID,
            )
        )

        if (
            recruit_role_response.status_code
            not in
            (200, 204)
        ):
            print(
                "Discord recruit role "
                "removal failed:",
                recruit_role_response.status_code,
                recruit_role_response.text,
            )

        try:
            save_main_character(
                discord_user_id,
                character_id,
                character_name,
                corporation_id,
            )

        except Exception as error:
            print(
                "Database main save failed:",
                repr(error),
            )

            return """
            <h1>Freeborn Verify</h1>
            <h2>⚠️ Vérification réussie</h2>
            <p>
            Les rôles ont été appliqués,
            mais l'enregistrement du Main
            a échoué.
            </p>
            """, 500

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
        <strong>{character_name}</strong>
        est enregistré comme
        <strong>Main Character</strong>.
        </p>

        <p>
        Tu peux maintenant retourner
        sur Discord.
        </p>
        """

    # ========================================================
    # ALT CHARACTER FLOW
    # ========================================================

    try:
        main_exists = has_main_character(
            discord_user_id
        )

    except Exception as error:
        print(
            "Main lookup during alt verification failed:",
            repr(error),
        )

        return """
        <h1>Freeborn Verify</h1>
        <h2>⚠️ Database error</h2>
        """, 500

    if not main_exists:
        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ MAIN REQUIRED</h2>
        <p>
        Tu dois d'abord enregistrer
        ton personnage principal avec /verify.
        </p>
        """, 400

    try:
        save_alt_character(
            discord_user_id,
            character_id,
            character_name,
            corporation_id,
        )

    except ValueError as error:
        print(
            "Alt rejected:",
            repr(error),
        )

        if (
            "Main character cannot"
            in str(error)
        ):
            return f"""
            <h1>Freeborn Verify</h1>

            <p>
            <strong>Character:</strong>
            {character_name}
            </p>

            <h2>❌ REFUSED</h2>

            <p>
            Ce personnage est déjà enregistré
            comme ton <strong>Main Character</strong>.
            </p>
            """, 400

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ REFUSED</h2>
        <p>
        Ce personnage est déjà lié
        à un autre compte Discord.
        </p>
        """, 400

    except Exception as error:
        print(
            "Database alt save failed:",
            repr(error),
        )

        return """
        <h1>Freeborn Verify</h1>
        <h2>⚠️ Database error</h2>
        <p>
        L'enregistrement de l'Alt
        a échoué.
        </p>
        """, 500

    alt_role_response = (
        add_discord_role(
            guild_id,
            discord_user_id,
            DISCORD_ALT_CHARACTER_ROLE_ID,
        )
    )

    if (
        alt_role_response.status_code
        not in
        (200, 204)
    ):
        print(
            "Discord Alt Character "
            "role assignment failed:",
            alt_role_response.status_code,
            alt_role_response.text,
        )

        return """
        <h1>Freeborn Verify</h1>

        <h2>⚠️ Alt enregistré</h2>

        <p>
        Le personnage a été enregistré,
        mais l'attribution du rôle
        Alt Character a échoué.
        </p>
        """, 500

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

    <h2>✅ ALT VERIFIED</h2>

    <p>
    <strong>{character_name}</strong>
    a été ajouté comme
    <strong>Alt Character</strong>.
    </p>

    <p>
    Tu peux maintenant retourner
    sur Discord.
    </p>
    """


# ============================================================
# REGISTER COMMANDS
# ============================================================

def register_commands():
    url = (
        f"{DISCORD_API}/applications/"
        f"{DISCORD_APPLICATION_ID}/guilds/"
        f"{DISCORD_GUILD_ID}/commands"
    )

    commands = [
        {
            "name": "verify",
            "description":
                "Vérifier ton Main EVE "
                "pour Freeborn Legacy",
            "type": 1,
        },
        {
            "name": "alt",
            "description":
                "Ajouter un Alt EVE "
                "à ton compte Freeborn",
            "type": 1,
        },
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
                "Discord commands "
                "/verify and /alt registered."
            )

        else:
            print(
                "Unable to register "
                "Discord commands:",
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
# INITIALIZATION
# ============================================================

init_database()

register_commands()


# ============================================================
# START
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
