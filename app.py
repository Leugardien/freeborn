import os
from urllib.parse import urlencode

import psycopg
import requests
from flask import Flask, jsonify, request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)
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

                cur.execute(
                    """
                    ALTER TABLE eve_characters
                    ADD COLUMN IF NOT EXISTS
                    in_corporation BOOLEAN
                    NOT NULL DEFAULT TRUE;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE eve_characters
                    ADD COLUMN IF NOT EXISTS
                    last_checked_at TIMESTAMPTZ;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE eve_characters
                    ADD COLUMN IF NOT EXISTS
                    left_corporation_at TIMESTAMPTZ;
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


def get_main_character(discord_user_id):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    character_id,
                    character_name
                FROM eve_characters
                WHERE discord_user_id = %s
                AND character_type = 'main'
                LIMIT 1;
                """,
                (
                    str(discord_user_id),
                ),
            )

            return cur.fetchone()


def has_main_character(discord_user_id):
    return (
        get_main_character(
            discord_user_id
        )
        is not None
    )


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


def get_all_characters():
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    character_id,
                    discord_user_id,
                    character_name,
                    character_type,
                    corporation_id,
                    in_corporation,
                    last_checked_at,
                    left_corporation_at
                FROM eve_characters
                ORDER BY
                    discord_user_id,
                    CASE
                        WHEN character_type = 'main'
                        THEN 0
                        ELSE 1
                    END,
                    character_name;
                """
            )

            return cur.fetchall()


def get_member_characters(discord_user_id):
    """
    Returns every EVE character linked
    to one Discord account.
    """

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    character_id,
                    character_name,
                    character_type,
                    corporation_id,
                    in_corporation,
                    verified_at,
                    last_checked_at,
                    left_corporation_at
                FROM eve_characters
                WHERE discord_user_id = %s
                ORDER BY
                    CASE
                        WHEN character_type = 'main'
                        THEN 0
                        ELSE 1
                    END,
                    character_name;
                """,
                (
                    str(discord_user_id),
                ),
            )

            return cur.fetchall()


def get_database_stats():
    with psycopg.connect(DATABASE_URL) as conn:
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

            cur.execute(
                """
                SELECT COUNT(*)
                FROM eve_characters
                WHERE in_corporation = FALSE;
                """
            )

            outside_count = (
                cur.fetchone()[0]
            )

    return {
        "characters":
            character_count,

        "mains":
            main_count,

        "alts":
            alt_count,

        "outside_corporation":
            outside_count,
    }


def save_main_character(
    discord_user_id,
    character_id,
    character_name,
    corporation_id,
):
    discord_user_id = str(
        discord_user_id
    )

    character_id = int(
        character_id
    )

    existing_character = (
        get_character_record(
            character_id
        )
    )

    if existing_character:

        existing_discord_user_id = (
            existing_character[0]
        )

        if (
            existing_discord_user_id
            != discord_user_id
        ):
            raise ValueError(
                "Character already linked "
                "to another Discord account"
            )

    existing_main = (
        get_main_character(
            discord_user_id
        )
    )

    if existing_main:

        existing_main_id = int(
            existing_main[0]
        )

        existing_main_name = (
            existing_main[1]
        )

        if (
            existing_main_id
            != character_id
        ):
            raise ValueError(
                "Discord account already has "
                f"main character: {existing_main_name}"
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
                    corporation_id,
                    in_corporation,
                    last_checked_at,
                    left_corporation_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'main',
                    %s,
                    TRUE,
                    NOW(),
                    NULL
                )
                ON CONFLICT (character_id)
                DO UPDATE SET
                    discord_user_id =
                        EXCLUDED.discord_user_id,
                    character_name =
                        EXCLUDED.character_name,
                    character_type =
                        'main',
                    corporation_id =
                        EXCLUDED.corporation_id,
                    in_corporation =
                        TRUE,
                    last_checked_at =
                        NOW(),
                    left_corporation_at =
                        NULL,
                    updated_at =
                        NOW();
                """,
                (
                    character_id,
                    discord_user_id,
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
    existing = (
        get_character_record(
            character_id
        )
    )

    if existing:

        existing_discord_user_id = (
            existing[0]
        )

        existing_character_type = (
            existing[2]
        )

        if (
            existing_discord_user_id
            != str(discord_user_id)
        ):
            raise ValueError(
                "Character already linked "
                "to another Discord account"
            )

        if (
            existing_character_type
            == "main"
        ):
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
                    corporation_id,
                    in_corporation,
                    last_checked_at,
                    left_corporation_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'alt',
                    %s,
                    TRUE,
                    NOW(),
                    NULL
                )
                ON CONFLICT (character_id)
                DO UPDATE SET
                    character_name =
                        EXCLUDED.character_name,
                    corporation_id =
                        EXCLUDED.corporation_id,
                    in_corporation =
                        TRUE,
                    last_checked_at =
                        NOW(),
                    left_corporation_at =
                        NULL,
                    updated_at =
                        NOW();
                """,
                (
                    int(character_id),
                    str(discord_user_id),
                    character_name,
                    int(corporation_id),
                ),
            )

        conn.commit()


def update_character_sync_status(
    character_id,
    corporation_id,
    in_corporation,
):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:

            if in_corporation:

                cur.execute(
                    """
                    UPDATE eve_characters
                    SET
                        corporation_id = %s,
                        in_corporation = TRUE,
                        last_checked_at = NOW(),
                        left_corporation_at = NULL,
                        updated_at = NOW()
                    WHERE character_id = %s;
                    """,
                    (
                        int(corporation_id),
                        int(character_id),
                    ),
                )

            else:

                cur.execute(
                    """
                    UPDATE eve_characters
                    SET
                        corporation_id = %s,
                        in_corporation = FALSE,
                        last_checked_at = NOW(),
                        left_corporation_at =
                            COALESCE(
                                left_corporation_at,
                                NOW()
                            ),
                        updated_at = NOW()
                    WHERE character_id = %s;
                    """,
                    (
                        int(corporation_id),
                        int(character_id),
                    ),
                )

        conn.commit()


# ============================================================
# DISPLAY HELPERS
# ============================================================

def format_datetime(value):
    if value is None:
        return "Jamais"

    try:
        return value.strftime(
            "%d/%m/%Y %H:%M UTC"
        )

    except Exception:
        return str(value)


def build_member_info(
    discord_user_id,
    discord_display_name,
):
    characters = (
        get_member_characters(
            discord_user_id
        )
    )

    if not characters:
        return (
            "👤 **Freeborn Member Info**\n\n"
            f"Discord : **{discord_display_name}**\n\n"
            "❌ Aucun personnage EVE "
            "n'est enregistré pour ce compte.\n\n"
            "Utilise **/verify** pour enregistrer "
            "ton Main Character."
        )

    main_rows = [
        row
        for row in characters
        if row[2] == "main"
    ]

    alt_rows = [
        row
        for row in characters
        if row[2] == "alt"
    ]

    lines = [
        "👤 **Freeborn Member Info**",
        "",
        f"Discord : **{discord_display_name}**",
        f"Discord ID : `{discord_user_id}`",
        "",
    ]

    # --------------------------------------------------------
    # MAIN
    # --------------------------------------------------------

    if main_rows:

        main = main_rows[0]

        (
            main_id,
            main_name,
            main_type,
            main_corporation_id,
            main_in_corporation,
            main_verified_at,
            main_last_checked_at,
            main_left_at,
        ) = main

        main_status = (
            "✅ Freeborn Legacy"
            if main_in_corporation
            else
            "❌ Hors Freeborn Legacy"
        )

        lines.extend([
            "### 🔗 Main Character",
            f"**{main_name}**",
            f"Character ID : `{main_id}`",
            f"Statut : {main_status}",
            (
                "Dernière synchro : "
                f"**{format_datetime(main_last_checked_at)}**"
            ),
            "",
        ])

    else:

        lines.extend([
            "### 🔗 Main Character",
            "❌ Aucun Main enregistré",
            "",
        ])

    # --------------------------------------------------------
    # ALTS
    # --------------------------------------------------------

    lines.append(
        f"### 🔹 Alt Characters ({len(alt_rows)})"
    )

    if not alt_rows:

        lines.append(
            "Aucun Alt Character enregistré."
        )

    else:

        for alt in alt_rows:

            (
                alt_id,
                alt_name,
                alt_type,
                alt_corporation_id,
                alt_in_corporation,
                alt_verified_at,
                alt_last_checked_at,
                alt_left_at,
            ) = alt

            alt_status = (
                "✅ Freeborn Legacy"
                if alt_in_corporation
                else
                "❌ Hors Freeborn Legacy"
            )

            lines.extend([
                "",
                f"**{alt_name}**",
                f"Character ID : `{alt_id}`",
                f"Statut : {alt_status}",
                (
                    "Dernière synchro : "
                    f"**{format_datetime(alt_last_checked_at)}**"
                ),
            ])

    lines.extend([
        "",
        "### 📊 Résumé",
        f"Personnages liés : **{len(characters)}**",
        f"Main : **{len(main_rows)}**",
        f"Alts : **{len(alt_rows)}**",
    ])

    return "\n".join(
        lines
    )


# ============================================================
# DISCORD SIGNATURE
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


def interaction_is_admin(data):
    try:
        permissions = int(
            data["member"]["permissions"]
        )

    except (
        KeyError,
        TypeError,
        ValueError,
    ):
        return False

    return (
        permissions & 8
    ) == 8


# ============================================================
# EVE TOKEN
# ============================================================

def get_eve_identity(access_token):
    metadata_response = requests.get(
        EVE_METADATA_URL,
        timeout=15,
    )

    metadata_response.raise_for_status()

    metadata = (
        metadata_response.json()
    )

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
            and
            key.get("alg") == algorithm
        )
    ]

    if not matching_keys:
        raise ValueError(
            "Unable to find matching EVE signing key"
        )

    signing_key = (
        matching_keys[0]
    )

    payload = jwt.decode(
        access_token,
        key=signing_key,
        algorithms=["RS256"],
        audience="EVE Online",
        options={
            "verify_iss":
                False,
        },
    )

    issuer = payload.get(
        "iss",
        "",
    )

    normalized_issuer = (
        issuer.rstrip("/")
    )

    if (
        normalized_issuer
        not in
        VALID_EVE_ISSUERS
    ):
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
        audiences = [
            audiences
        ]

    if (
        "EVE Online"
        not in audiences
    ):
        raise ValueError(
            "EVE Online audience missing"
        )

    if (
        EVE_CLIENT_ID
        not in audiences
    ):
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
# DISCORD HELPERS
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


def sync_discord_nickname(
    guild_id,
    user_id,
    character_name,
):
    member_url = (
        f"{DISCORD_API}/guilds/"
        f"{guild_id}/members/"
        f"{user_id}"
    )

    return requests.patch(
        member_url,
        headers={
            "Authorization":
                f"Bot {DISCORD_BOT_TOKEN}",

            "Content-Type":
                "application/json",
        },
        json={
            "nick":
                character_name,
        },
        timeout=15,
    )


def revoke_main_access(
    discord_user_id,
):
    role_ids = [
        DISCORD_MEMBER_ROLE_ID,
        DISCORD_EVE_VERIFIED_ROLE_ID,
        DISCORD_MAIN_CHARACTER_ROLE_ID,
        DISCORD_ALT_CHARACTER_ROLE_ID,
    ]

    results = []

    for role_id in role_ids:

        response = (
            remove_discord_role(
                DISCORD_GUILD_ID,
                discord_user_id,
                role_id,
            )
        )

        results.append(
            response.status_code
        )

    return results


def revoke_alt_role_if_needed(
    discord_user_id,
    sync_results,
):
    user_results = [
        item
        for item in sync_results
        if (
            item["discord_user_id"]
            ==
            str(discord_user_id)
        )
    ]

    main_results = [
        item
        for item in user_results
        if (
            item["character_type"]
            ==
            "main"
        )
    ]

    alt_results = [
        item
        for item in user_results
        if (
            item["character_type"]
            ==
            "alt"
        )
    ]

    if not main_results:
        return None

    main = (
        main_results[0]
    )

    if (
        main["status"]
        != "ok"
        or
        not main["in_corporation"]
    ):
        return None

    if not alt_results:
        return None

    if any(
        item["status"] != "ok"
        for item in alt_results
    ):
        return None

    if any(
        item["in_corporation"]
        for item in alt_results
    ):
        return None

    response = (
        remove_discord_role(
            DISCORD_GUILD_ID,
            discord_user_id,
            DISCORD_ALT_CHARACTER_ROLE_ID,
        )
    )

    return response.status_code


# ============================================================
# SYNC ENGINE
# ============================================================

def run_sync(
    apply_changes=False,
):
    characters = (
        get_all_characters()
    )

    sync_results = []

    for character in characters:

        (
            character_id,
            discord_user_id,
            character_name,
            character_type,
            stored_corporation_id,
            stored_in_corporation,
            last_checked_at,
            left_corporation_at,
        ) = character

        result = {
            "character_id":
                int(character_id),

            "discord_user_id":
                str(discord_user_id),

            "character_name":
                character_name,

            "character_type":
                character_type,

            "status":
                "error",

            "in_corporation":
                None,

            "current_corporation_id":
                None,
        }

        try:

            response = requests.get(
                (
                    f"{ESI_BASE_URL}/characters/"
                    f"{character_id}/"
                ),
                timeout=15,
            )

            if response.status_code != 200:

                result["status"] = (
                    "esi_error"
                )

                sync_results.append(
                    result
                )

                continue

            data = (
                response.json()
            )

            if (
                "corporation_id"
                not in data
            ):

                result["status"] = (
                    "esi_error"
                )

                sync_results.append(
                    result
                )

                continue

            current_corporation_id = int(
                data["corporation_id"]
            )

            in_corporation = (
                current_corporation_id
                ==
                FREEBORN_CORPORATION_ID
            )

            result["status"] = (
                "ok"
            )

            result["in_corporation"] = (
                in_corporation
            )

            result[
                "current_corporation_id"
            ] = current_corporation_id

            if apply_changes:

                update_character_sync_status(
                    character_id,
                    current_corporation_id,
                    in_corporation,
                )

        except Exception as error:

            print(
                "Sync ESI error:",
                character_name,
                repr(error),
            )

            result["status"] = (
                "esi_error"
            )

        sync_results.append(
            result
        )

    actions = []

    if apply_changes:

        discord_users = sorted(
            {
                item["discord_user_id"]
                for item in sync_results
            }
        )

        for discord_user_id in discord_users:

            user_results = [
                item
                for item in sync_results
                if (
                    item["discord_user_id"]
                    ==
                    discord_user_id
                )
            ]

            main_results = [
                item
                for item in user_results
                if (
                    item["character_type"]
                    ==
                    "main"
                )
            ]

            if main_results:

                main = (
                    main_results[0]
                )

                if (
                    main["status"]
                    != "ok"
                ):

                    actions.append({
                        "discord_user_id":
                            discord_user_id,

                        "action":
                            "none",

                        "reason":
                            "Main ESI error",
                    })

                    continue

                if not main["in_corporation"]:

                    role_results = (
                        revoke_main_access(
                            discord_user_id
                        )
                    )

                    actions.append({
                        "discord_user_id":
                            discord_user_id,

                        "action":
                            "main_revoked",

                        "character_name":
                            main[
                                "character_name"
                            ],

                        "role_results":
                            role_results,
                    })

                    continue

            alt_result = (
                revoke_alt_role_if_needed(
                    discord_user_id,
                    sync_results,
                )
            )

            if alt_result is not None:

                actions.append({
                    "discord_user_id":
                        discord_user_id,

                    "action":
                        "alt_role_removed",

                    "status_code":
                        alt_result,
                })

    return (
        sync_results,
        actions,
    )


# ============================================================
# FORMAT SYNC
# ============================================================

def build_sync_message(
    sync_results,
    actions=None,
    applied=False,
):
    lines = []

    freeborn_count = 0
    outside_count = 0
    error_count = 0

    for item in sync_results:

        name = (
            item["character_name"]
        )

        character_type = (
            item["character_type"]
        )

        if (
            item["status"]
            != "ok"
        ):

            error_count += 1

            lines.append(
                f"⚠️ **{name}** "
                f"({character_type}) — "
                "ESI indisponible / erreur"
            )

        elif item["in_corporation"]:

            freeborn_count += 1

            lines.append(
                f"✅ **{name}** "
                f"({character_type}) — "
                "Freeborn Legacy"
            )

        else:

            outside_count += 1

            lines.append(
                f"❌ **{name}** "
                f"({character_type}) — "
                "hors Freeborn Legacy"
            )

    if applied:

        title = (
            "⚙️ **Freeborn Sync APPLY**"
        )

        footer = (
            "\n\n🛡️ Les révocations ne sont "
            "effectuées qu'après confirmation "
            "ESI valide."
        )

    else:

        title = (
            "🔎 **Freeborn Sync Check**"
        )

        footer = (
            "\n\n_Mode observation : "
            "aucun rôle n'a été modifié._"
        )

    message = (
        f"{title}\n\n"

        + "\n".join(
            lines
        )

        + "\n\n"

        + f"✅ Freeborn : "
          f"**{freeborn_count}**\n"

        + f"❌ Hors corporation : "
          f"**{outside_count}**\n"

        + f"⚠️ Erreurs ESI : "
          f"**{error_count}**"

        + footer
    )

    if (
        applied
        and actions
    ):

        action_lines = []

        for action in actions:

            if (
                action["action"]
                ==
                "main_revoked"
            ):

                action_lines.append(
                    "🔒 "
                    f"**{action['character_name']}** "
                    "— accès Discord révoqués"
                )

            elif (
                action["action"]
                ==
                "alt_role_removed"
            ):

                action_lines.append(
                    "🔗 Rôle **Alt Character** "
                    "retiré"
                )

            elif (
                action["action"]
                ==
                "none"
            ):

                action_lines.append(
                    "🛡️ Aucune révocation : "
                    "ESI non fiable"
                )

        if action_lines:

            message += (
                "\n\n### Actions\n"
                + "\n".join(
                    action_lines
                )
            )

    return message


# ============================================================
# HOME / HEALTH
# ============================================================

@app.route("/")
def home():
    return """
    <h1>Freeborn Verify</h1>

    <p>
    Service de vérification EVE Online
    pour Freeborn Legacy.
    </p>
    """


@app.route("/health")
def health():
    return {
        "status":
            "ok",

        "service":
            "freeborn-verify",
    }


@app.route("/db-health")
def db_health():

    try:

        stats = (
            get_database_stats()
        )

        return {
            "status":
                "ok",

            "database":
                "connected",

            "table":
                "eve_characters",

            "characters":
                stats["characters"],

            "mains":
                stats["mains"],

            "alts":
                stats["alts"],

            "outside_corporation":
                stats["outside_corporation"],
        }

    except Exception as error:

        print(
            "Database health check failed:",
            repr(error),
        )

        return {
            "status":
                "error",

            "database":
                "unavailable",
        }, 500


# ============================================================
# INTERACTIONS
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
            "type":
                1
        })

    if data["type"] != 2:

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "Commande inconnue.",

                "flags":
                    64,
            },
        })

    command_name = (
        data["data"]["name"]
    )

    discord_user_id = (
        data["member"]["user"]["id"]
    )

    discord_display_name = (
        data["member"].get(
            "nick"
        )
        or
        data["member"][
            "user"
        ].get(
            "global_name"
        )
        or
        data["member"][
            "user"
        ].get(
            "username"
        )
        or
        "Utilisateur Discord"
    )

    guild_id = (
        data["guild_id"]
    )

    if (
        guild_id
        !=
        DISCORD_GUILD_ID
    ):

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "❌ Cette commande est "
                    "réservée à Freeborn Legacy.",

                "flags":
                    64,
            },
        })

    # ========================================================
    # /member-info
    # ========================================================

    if command_name == "member-info":

        try:

            message = build_member_info(
                discord_user_id,
                discord_display_name,
            )

        except Exception as error:

            print(
                "Member info failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "👤 **Freeborn Member Info**\n\n"
                        "⚠️ Impossible de lire "
                        "ton profil EVE actuellement.",

                    "flags":
                        64,
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                "flags":
                    64,
            },
        })

    # ========================================================
    # /db-health
    # ========================================================

    if command_name == "db-health":

        try:

            stats = (
                get_database_stats()
            )

        except Exception as error:

            print(
                "Discord db-health failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "🗄️ **Freeborn Database**\n\n"
                        "❌ Base de données indisponible.",

                    "flags":
                        64,
                },
            })

        message = (
            "🗄️ **Freeborn Database Health**\n\n"

            "✅ Statut : **Connectée**\n"
            "📋 Table : **eve_characters**\n\n"

            f"👥 Personnages : "
            f"**{stats['characters']}**\n"

            f"🔗 Main Characters : "
            f"**{stats['mains']}**\n"

            f"🔹 Alt Characters : "
            f"**{stats['alts']}**\n"

            f"🚪 Hors corporation : "
            f"**{stats['outside_corporation']}**"
        )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                "flags":
                    64,
            },
        })

    # ========================================================
    # /sync-check
    # ========================================================

    if command_name == "sync-check":

        try:

            (
                sync_results,
                actions,
            ) = run_sync(
                apply_changes=False
            )

        except Exception as error:

            print(
                "Sync check failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Erreur lors du "
                        "contrôle Freeborn.",

                    "flags":
                        64,
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    build_sync_message(
                        sync_results,
                        applied=False,
                    ),

                "flags":
                    64,
            },
        })

    # ========================================================
    # /sync-apply
    # ========================================================

    if command_name == "sync-apply":

        if not interaction_is_admin(
            data
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Accès refusé**\n\n"
                        "Cette commande est "
                        "réservée aux administrateurs.",

                    "flags":
                        64,
                },
            })

        try:

            (
                sync_results,
                actions,
            ) = run_sync(
                apply_changes=True
            )

        except Exception as error:

            print(
                "Sync apply failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ La synchronisation "
                        "a rencontré une erreur.",

                    "flags":
                        64,
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    build_sync_message(
                        sync_results,
                        actions=actions,
                        applied=True,
                    ),

                "flags":
                    64,
            },
        })

    # ========================================================
    # TEST COMMANDS
    # ========================================================

    if command_name == "sync-test-out":

        message = (
            "🧪 **Freeborn Sync TEST**\n\n"

            "✅ **LeGardien** (main) — "
            "Freeborn Legacy\n"

            "✅ **Neo Valtheris** (alt) — "
            "Freeborn Legacy\n"

            "❌ **TEST - Former Member** "
            "(main) — hors Freeborn Legacy\n\n"

            "🧪 **SIMULATION UNIQUEMENT**\n"

            "Aucune donnée Neon n'a été modifiée.\n"
            "Aucun rôle Discord n'a été modifié."
        )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                "flags":
                    64,
            },
        })

    if command_name == "sync-test-revoke":

        message = (
            "🧪 **Freeborn Revocation TEST**\n\n"

            "Personnage détecté : "
            "**TEST - Former Member**\n"

            "Statut : ❌ hors Freeborn Legacy\n\n"

            "### Actions prévues\n"

            "➡️ Retirer **Membre**\n"
            "➡️ Retirer **EVE Verified**\n"
            "➡️ Retirer **Main Character**\n"
            "➡️ Retirer **Alt Character**\n\n"

            "🛡️ **MODE SIMULATION**\n"

            "Aucun rôle réel n'a été modifié."
        )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                "flags":
                    64,
            },
        })

    # ========================================================
    # /verify
    # ========================================================

    if command_name == "verify":

        verification_type = (
            "main"
        )

    # ========================================================
    # /alt
    # ========================================================

    elif command_name == "alt":

        verification_type = (
            "alt"
        )

        try:

            main_exists = (
                has_main_character(
                    discord_user_id
                )
            )

        except Exception as error:

            print(
                "Main lookup failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible de lire "
                        "ton Main Character.",

                    "flags":
                        64,
                },
            })

        if not main_exists:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Utilise d'abord "
                        "**/verify** pour ton Main.",

                    "flags":
                        64,
                },
            })

    else:

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "Commande inconnue.",

                "flags":
                    64,
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

    if (
        verification_type
        == "main"
    ):

        message = (
            "🔐 **Freeborn Verify**\n\n"

            "Connecte ton personnage "
            "principal EVE Online :\n\n"

            f"[Vérifier mon personnage EVE]"
            f"({login_url})"
        )

    else:

        message = (
            "🔗 **Freeborn Alt Verify**\n\n"

            "Sélectionne le personnage "
            "à enregistrer comme Alt :\n\n"

            f"[Ajouter mon Alt EVE]"
            f"({login_url})"
        )

    return jsonify({
        "type":
            4,

        "data": {
            "content":
                message,

            "flags":
                64,
        },
    })


# ============================================================
# CALLBACK
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

    if (
        guild_id
        !=
        DISCORD_GUILD_ID
    ):

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Invalid Discord server</h2>
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

    if (
        token_response.status_code
        != 200
    ):

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Unable to obtain EVE access token</h2>
        """, 400

    access_token = (
        token_response.json()[
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

    if (
        character_response.status_code
        != 200
    ):

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ Unable to retrieve character</h2>
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
    # MAIN
    # ========================================================

    if (
        verification_type
        == "main"
    ):

        try:

            save_main_character(
                discord_user_id,
                character_id,
                character_name,
                corporation_id,
            )

        except ValueError as error:

            if (
                "already has main character"
                in str(error)
            ):

                existing_main = (
                    get_main_character(
                        discord_user_id
                    )
                )

                existing_main_name = (
                    existing_main[1]
                    if existing_main
                    else
                    "Unknown"
                )

                return f"""
                <h1>Freeborn Verify</h1>

                <h2>
                ❌ MAIN ALREADY REGISTERED
                </h2>

                <p>
                Ton Main actuel est
                <strong>{existing_main_name}</strong>.
                </p>
                """, 400

            return """
            <h1>Freeborn Verify</h1>
            <h2>❌ CHARACTER ALREADY LINKED</h2>
            """, 400

        except Exception as error:

            print(
                "Database main save failed:",
                repr(error),
            )

            return """
            <h1>Freeborn Verify</h1>
            <h2>⚠️ Database error</h2>
            """, 500

        role_responses = [

            add_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_MEMBER_ROLE_ID,
            ),

            add_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_EVE_VERIFIED_ROLE_ID,
            ),

            add_discord_role(
                guild_id,
                discord_user_id,
                DISCORD_MAIN_CHARACTER_ROLE_ID,
            ),
        ]

        if any(
            response.status_code
            not in (200, 204)
            for response
            in role_responses
        ):

            return """
            <h1>Freeborn Verify</h1>
            <h2>⚠️ Role assignment error</h2>
            """, 500

        remove_discord_role(
            guild_id,
            discord_user_id,
            DISCORD_RECRUIT_ROLE_ID,
        )

        nickname_response = (
            sync_discord_nickname(
                guild_id,
                discord_user_id,
                character_name,
            )
        )

        nickname_changed = (
            nickname_response.status_code
            in
            (200, 204)
        )

        nickname_status = (
            "<p>Le pseudo Discord a été synchronisé "
            f"sur <strong>{character_name}</strong>.</p>"
            if nickname_changed
            else
            "<p>Le pseudo Discord n'a pas pu être modifié "
            "(hiérarchie ou permission Discord).</p>"
        )

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

        {nickname_status}

        <p>
        Tu peux retourner sur Discord.
        </p>
        """

    # ========================================================
    # ALT
    # ========================================================

    if not has_main_character(
        discord_user_id
    ):

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ MAIN REQUIRED</h2>
        """, 400

    try:

        save_alt_character(
            discord_user_id,
            character_id,
            character_name,
            corporation_id,
        )

    except ValueError as error:

        if (
            "Main character cannot"
            in str(error)
        ):

            return f"""
            <h1>Freeborn Verify</h1>

            <p>
            <strong>{character_name}</strong>
            est déjà ton Main Character.
            </p>

            <h2>❌ REFUSED</h2>
            """, 400

        return """
        <h1>Freeborn Verify</h1>
        <h2>❌ CHARACTER ALREADY LINKED</h2>
        """, 400

    except Exception as error:

        print(
            "Database alt save failed:",
            repr(error),
        )

        return """
        <h1>Freeborn Verify</h1>
        <h2>⚠️ Database error</h2>
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

        return """
        <h1>Freeborn Verify</h1>
        <h2>⚠️ Alt role error</h2>
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
    a été ajouté comme Alt Character.
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
            "name":
                "verify",

            "description":
                "Vérifier ton Main EVE "
                "pour Freeborn Legacy",

            "type":
                1,
        },

        {
            "name":
                "alt",

            "description":
                "Ajouter un Alt EVE "
                "à ton compte Freeborn",

            "type":
                1,
        },

        {
            "name":
                "member-info",

            "description":
                "Afficher ton profil "
                "EVE Freeborn",

            "type":
                1,
        },

        {
            "name":
                "db-health",

            "description":
                "Afficher l'état de "
                "la base Freeborn",

            "type":
                1,
        },

        {
            "name":
                "sync-check",

            "description":
                "Contrôler les personnages "
                "Freeborn sans modifier les rôles",

            "type":
                1,
        },

        {
            "name":
                "sync-apply",

            "description":
                "Synchroniser et révoquer "
                "les anciens membres",

            "type":
                1,
        },

        {
            "name":
                "sync-test-out",

            "description":
                "Tester un départ "
                "de corporation",

            "type":
                1,
        },

        {
            "name":
                "sync-test-revoke",

            "description":
                "Simuler une révocation "
                "d'accès",

            "type":
                1,
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

        if (
            response.status_code
            == 200
        ):

            print(
                "Discord commands registered."
            )

        else:

            print(
                "Discord command registration failed:",
                response.status_code,
                response.text,
            )

    except Exception as error:

        print(
            "Discord command registration error:",
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
