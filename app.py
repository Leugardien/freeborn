import os
from urllib.parse import urlencode

import psycopg
import requests

from flask import Flask, jsonify, request
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from itsdangerous import (
    URLSafeTimedSerializer,
    TimestampSigner,
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

# Discord channels used for persistent command history
DISCORD_EVE_VERIFICATION_CHANNEL_ID = "1535497827503964190"
DISCORD_CHARACTER_MANAGEMENT_CHANNEL_ID = "1535497895929708648"

DISCORD_MEMBER_ROLE_ID = os.environ[
    "DISCORD_MEMBER_ROLE_ID"
]

DISCORD_RECRUIT_ROLE_ID = os.environ[
    "DISCORD_RECRUIT_ROLE_ID"
]

DISCORD_EVE_VERIFIED_ROLE_ID = os.environ[
    "DISCORD_EVE_VERIFIED_ROLE_ID"
]

DISCORD_MAIN_CHARACTER_ROLE_ID = os.environ[
    "DISCORD_MAIN_CHARACTER_ROLE_ID"
]

DISCORD_ALT_CHARACTER_ROLE_ID = os.environ[
    "DISCORD_ALT_CHARACTER_ROLE_ID"
]

DISCORD_FOUNDER_ROLE_ID = os.environ[
    "DISCORD_FOUNDER_ROLE_ID"
]

DISCORD_CEO_ROLE_ID = os.environ[
    "DISCORD_CEO_ROLE_ID"
]

DISCORD_DIRECTOR_ROLE_ID = os.environ[
    "DISCORD_DIRECTOR_ROLE_ID"
]

FLASK_SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]


# ============================================================
# STAFF ROLES
# ============================================================

STAFF_ROLE_IDS = {
    DISCORD_FOUNDER_ROLE_ID,
    DISCORD_CEO_ROLE_ID,
    DISCORD_DIRECTOR_ROLE_ID,
}


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

member_remove_signer = TimestampSigner(
    FLASK_SECRET_KEY,
    salt="freeborn-member-remove",
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():

    try:

        with psycopg.connect(
            DATABASE_URL
        ) as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS eve_characters (
                        character_id BIGINT PRIMARY KEY,

                        discord_user_id TEXT NOT NULL,

                        character_name TEXT NOT NULL,

                        character_type TEXT NOT NULL
                            CHECK (
                                character_type
                                IN ('main', 'alt')
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

                # One Discord account may have only one Main Character.
                # The application already enforces this rule, but this
                # partial unique index also protects the database against
                # concurrent requests or a future application bug.
                cur.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_eve_characters_one_main_per_discord
                    ON eve_characters (discord_user_id)
                    WHERE character_type = 'main';
                    """
                )

                # Most profile lookups are performed by Discord user ID.
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_eve_characters_discord_user_id
                    ON eve_characters (discord_user_id);
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


# ============================================================
# DATABASE READ FUNCTIONS
# ============================================================

def get_main_character(
    discord_user_id
):

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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


def has_main_character(
    discord_user_id
):

    return (
        get_main_character(
            discord_user_id
        )
        is not None
    )


def get_character_record(
    character_id
):

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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


def get_member_characters(
    discord_user_id
):

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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


def get_member_alts(
    discord_user_id
):

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    character_id,
                    character_name,
                    corporation_id,
                    in_corporation

                FROM eve_characters

                WHERE discord_user_id = %s
                AND character_type = 'alt'

                ORDER BY character_name;
                """,
                (
                    str(discord_user_id),
                ),
            )

            return cur.fetchall()


def get_database_stats():

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
                SELECT COUNT(
                    DISTINCT discord_user_id
                )
                FROM eve_characters;
                """
            )

            member_count = (
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

            cur.execute(
                """
                SELECT MAX(last_checked_at)
                FROM eve_characters;
                """
            )

            latest_check = (
                cur.fetchone()[0]
            )

    return {
        "characters":
            character_count,

        "members":
            member_count,

        "mains":
            main_count,

        "alts":
            alt_count,

        "outside_corporation":
            outside_count,

        "latest_check":
            latest_check,
    }


# ============================================================
# DATABASE WRITE FUNCTIONS
# ============================================================

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
                f"main character: "
                f"{existing_main_name}"
            )

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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
            ==
            "main"
        ):

            raise ValueError(
                "Main character cannot "
                "be added as alt"
            )

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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


def remove_alt_character(
    discord_user_id,
    character_id,
):

    discord_user_id = str(
        discord_user_id
    )

    character_id = int(
        character_id
    )

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

        try:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT
                        character_id,
                        character_name,
                        character_type

                    FROM eve_characters

                    WHERE character_id = %s
                    AND discord_user_id = %s

                    FOR UPDATE;
                    """,
                    (
                        character_id,
                        discord_user_id,
                    ),
                )

                character = (
                    cur.fetchone()
                )

                if not character:

                    raise ValueError(
                        "Character not linked "
                        "to this Discord account"
                    )

                character_type = (
                    character[2]
                )

                if (
                    character_type
                    !=
                    "alt"
                ):

                    raise ValueError(
                        "Main Character cannot "
                        "be removed with /alt-remove"
                    )

                character_name = (
                    character[1]
                )

                cur.execute(
                    """
                    DELETE FROM eve_characters

                    WHERE character_id = %s
                    AND discord_user_id = %s
                    AND character_type = 'alt';
                    """,
                    (
                        character_id,
                        discord_user_id,
                    ),
                )

                cur.execute(
                    """
                    SELECT COUNT(*)

                    FROM eve_characters

                    WHERE discord_user_id = %s
                    AND character_type = 'alt';
                    """,
                    (
                        discord_user_id,
                    ),
                )

                remaining_alts = int(
                    cur.fetchone()[0]
                )

            conn.commit()

            return {
                "character_id":
                    character_id,

                "character_name":
                    character_name,

                "remaining_alts":
                    remaining_alts,
            }

        except Exception:

            conn.rollback()

            raise


def remove_member_profile(
    discord_user_id
):

    discord_user_id = str(
        discord_user_id
    )

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

        try:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT
                        character_id,
                        character_name,
                        character_type

                    FROM eve_characters

                    WHERE discord_user_id = %s

                    ORDER BY
                        CASE
                            WHEN character_type = 'main'
                            THEN 0
                            ELSE 1
                        END,
                        character_name

                    FOR UPDATE;
                    """,
                    (
                        discord_user_id,
                    ),
                )

                characters = (
                    cur.fetchall()
                )

                if not characters:

                    raise ValueError(
                        "No EVE characters registered "
                        "for this Discord account"
                    )

                cur.execute(
                    """
                    DELETE FROM eve_characters
                    WHERE discord_user_id = %s;
                    """,
                    (
                        discord_user_id,
                    ),
                )

            conn.commit()

            return characters

        except Exception:

            conn.rollback()

            raise


def update_character_sync_status(
    character_id,
    corporation_id,
    in_corporation,
):

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

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
# MAIN CHANGE
# ============================================================

def change_main_character(
    discord_user_id,
    new_main_character_id,
    new_main_corporation_id,
):

    discord_user_id = str(
        discord_user_id
    )

    new_main_character_id = int(
        new_main_character_id
    )

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

        try:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT
                        character_id,
                        character_name,
                        corporation_id

                    FROM eve_characters

                    WHERE discord_user_id = %s
                    AND character_type = 'main'

                    FOR UPDATE;
                    """,
                    (
                        discord_user_id,
                    ),
                )

                old_main = (
                    cur.fetchone()
                )

                if not old_main:

                    raise ValueError(
                        "No current Main Character"
                    )

                old_main_id = int(
                    old_main[0]
                )

                old_main_name = (
                    old_main[1]
                )

                cur.execute(
                    """
                    SELECT
                        character_id,
                        character_name,
                        corporation_id

                    FROM eve_characters

                    WHERE character_id = %s
                    AND discord_user_id = %s
                    AND character_type = 'alt'

                    FOR UPDATE;
                    """,
                    (
                        new_main_character_id,
                        discord_user_id,
                    ),
                )

                new_main = (
                    cur.fetchone()
                )

                if not new_main:

                    raise ValueError(
                        "Selected character is not "
                        "a registered Alt"
                    )

                new_main_name = (
                    new_main[1]
                )

                cur.execute(
                    """
                    UPDATE eve_characters

                    SET
                        character_type = 'alt',
                        updated_at = NOW()

                    WHERE character_id = %s
                    AND discord_user_id = %s;
                    """,
                    (
                        old_main_id,
                        discord_user_id,
                    ),
                )

                cur.execute(
                    """
                    UPDATE eve_characters

                    SET
                        character_type = 'main',
                        corporation_id = %s,
                        in_corporation = TRUE,
                        last_checked_at = NOW(),
                        left_corporation_at = NULL,
                        updated_at = NOW()

                    WHERE character_id = %s
                    AND discord_user_id = %s;
                    """,
                    (
                        int(
                            new_main_corporation_id
                        ),
                        new_main_character_id,
                        discord_user_id,
                    ),
                )

            conn.commit()

            return {
                "old_main_id":
                    old_main_id,

                "old_main_name":
                    old_main_name,

                "new_main_id":
                    new_main_character_id,

                "new_main_name":
                    new_main_name,
            }

        except Exception:

            conn.rollback()

            raise


# ============================================================
# DISPLAY HELPERS
# ============================================================

def format_datetime(
    value
):

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

            f"Discord : "
            f"**{discord_display_name}**\n"

            f"Discord ID : "
            f"`{discord_user_id}`\n\n"

            "❌ Aucun personnage EVE "
            "n'est enregistré pour ce compte."
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

    if main_rows:

        main = (
            main_rows[0]
        )

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

    lines.append(
        f"### 🔹 Alt Characters "
        f"({len(alt_rows)})"
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
# MEMBER LIST
# ============================================================

def build_member_list_message():

    characters = (
        get_all_characters()
    )

    stats = (
        get_database_stats()
    )

    if not characters:

        return (
            "👥 **Freeborn Member List**\n\n"
            "ℹ️ Aucun compte EVE n'est actuellement "
            "enregistré dans Freeborn Verify.\n\n"
            "🛡️ **Mode lecture seule**\n"
            "Aucune donnée Neon n'a été modifiée.\n"
            "Aucun rôle Discord n'a été modifié."
        )

    members = {}

    for row in characters:

        (
            character_id,
            discord_user_id,
            character_name,
            character_type,
            corporation_id,
            in_corporation,
            last_checked_at,
            left_corporation_at,
        ) = row

        discord_user_id = str(
            discord_user_id
        )

        if discord_user_id not in members:

            members[discord_user_id] = {
                "main": None,
                "alts": [],
                "all_in_corporation": True,
            }

        if character_type == "main":

            members[discord_user_id]["main"] = (
                character_name
            )

        else:

            members[discord_user_id]["alts"].append(
                character_name
            )

        if not in_corporation:

            members[discord_user_id][
                "all_in_corporation"
            ] = False

    sorted_members = sorted(
        members.items(),
        key=lambda item: (
            (
                item[1]["main"]
                or "~"
            ).lower(),
            item[0],
        ),
    )

    header = [
        "👥 **Freeborn Member List**",
        "",
        (
            "Comptes enregistrés : "
            f"**{stats['members']}**"
        ),
        "",
    ]

    summary = [
        "",
        "### 📊 Résumé",
        f"👥 Comptes Discord : **{stats['members']}**",
        f"🎮 Personnages : **{stats['characters']}**",
        f"🔗 Main Characters : **{stats['mains']}**",
        f"🔹 Alt Characters : **{stats['alts']}**",
        (
            "🚪 Hors corporation : "
            f"**{stats['outside_corporation']}**"
        ),
        "",
        "🛡️ **Mode lecture seule**",
        "Aucune donnée Neon n'a été modifiée.",
        "Aucun rôle Discord n'a été modifié.",
    ]

    output_lines = list(header)
    displayed = 0
    maximum_accounts = 25
    safe_message_limit = 1900

    for index, (
        discord_user_id,
        member_data,
    ) in enumerate(
        sorted_members[:maximum_accounts],
        start=1,
    ):

        main_name = (
            member_data["main"]
            or "Aucun Main"
        )

        alt_names = sorted(
            member_data["alts"],
            key=str.lower,
        )

        if alt_names:

            visible_alts = (
                alt_names[:5]
            )

            alt_text = ", ".join(
                visible_alts
            )

            if len(alt_names) > 5:

                alt_text += (
                    f" +{len(alt_names) - 5} autre(s)"
                )

        else:

            alt_text = "Aucun"

        status_text = (
            "✅ Freeborn Legacy"
            if member_data[
                "all_in_corporation"
            ]
            else
            "❌ Statut hors corporation enregistré"
        )

        block = [
            f"**{index}.** <@{discord_user_id}>",
            f"🔗 Main : **{main_name}**",
            f"🔹 Alts : **{alt_text}**",
            f"{status_text}",
            "",
        ]

        candidate = "\n".join(
            output_lines
            + block
            + summary
        )

        if len(candidate) > safe_message_limit:

            break

        output_lines.extend(
            block
        )

        displayed += 1

    hidden_count = (
        len(sorted_members)
        - displayed
    )

    if hidden_count > 0:

        output_lines.extend([
            (
                "ℹ️ Liste limitée : "
                f"**{hidden_count}** compte(s) "
                "supplémentaire(s) non affiché(s)."
            ),
            "",
        ])

    output_lines.extend(
        summary
    )

    return "\n".join(
        output_lines
    )


# ============================================================
# DISCORD SIGNATURE
# ============================================================

def verify_discord_signature(
    req
):

    signature = req.headers.get(
        "X-Signature-Ed25519"
    )

    timestamp = req.headers.get(
        "X-Signature-Timestamp"
    )

    if (
        not signature
        or
        not timestamp
    ):

        return False

    body = req.get_data()

    try:

        verify_key = VerifyKey(
            bytes.fromhex(
                DISCORD_PUBLIC_KEY
            )
        )

        verify_key.verify(
            timestamp.encode()
            + body,

            bytes.fromhex(
                signature
            ),
        )

        return True

    except (
        BadSignatureError,
        ValueError,
    ):

        return False


# ============================================================
# STAFF ACCESS
# ============================================================

def interaction_is_staff(
    data
):

    try:

        member_roles = set(
            str(role_id)
            for role_id
            in data["member"]["roles"]
        )

    except (
        KeyError,
        TypeError,
    ):

        return False

    return bool(
        member_roles
        &
        STAFF_ROLE_IDS
    )


def interaction_response_flags(data):

    channel_id = str(
        data.get("channel_id", "")
    )

    if channel_id in {
        DISCORD_EVE_VERIFICATION_CHANNEL_ID,
        DISCORD_CHARACTER_MANAGEMENT_CHANNEL_ID,
    }:

        return 0

    return 64


def interaction_response_flags_payload(data):
    """
    Discord: for a public interaction response, omit the flags field
    entirely. For responses outside the two audit channels, explicitly
    request EPHEMERAL (64).
    """

    if interaction_response_flags(data) == 64:
        return {"flags": 64}

    return {}


def staff_access_denied(
    data=None,
):

    flags = (
        interaction_response_flags(data)
        if data
        else
        64
    )

    return jsonify({
        "type":
            4,

        "data": {
            "content":
                "⛔ **Accès refusé**\n\n"
                "Cette action est réservée "
                "aux rôles **Fondateur**, "
                "**CEO** et **Directeur**.",

            "flags":
                flags,
        },
    })



# ============================================================
# MEMBER REMOVE SECURITY TOKEN
# ============================================================

def create_member_remove_token(
    target_user_id,
    requester_user_id,
):

    payload = (
        f"{target_user_id}:"
        f"{requester_user_id}"
    )

    signed = (
        member_remove_signer.sign(
            payload.encode()
        )
    )

    return signed.decode()


def read_member_remove_token(
    token,
):

    unsigned = (
        member_remove_signer.unsign(
            token,
            max_age=300,
        )
    )

    payload = (
        unsigned.decode()
    )

    target_user_id, requester_user_id = (
        payload.split(
            ":",
            1,
        )
    )

    return (
        target_user_id,
        requester_user_id,
    )


# ============================================================
# EVE TOKEN
# ============================================================

def get_eve_identity(
    access_token
):

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

    jwks = (
        jwks_response.json()
    )

    header = (
        jwt.get_unverified_header(
            access_token
        )
    )

    algorithm = (
        header.get("alg")
    )

    key_id = (
        header.get("kid")
    )

    if algorithm != "RS256":

        raise ValueError(
            f"Unexpected JWT algorithm: "
            f"{algorithm}"
        )

    matching_keys = [
        key
        for key in jwks["keys"]
        if (
            key.get("kid")
            == key_id
            and
            key.get("alg")
            == algorithm
        )
    ]

    if not matching_keys:

        raise ValueError(
            "Unable to find matching "
            "EVE signing key"
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
            f"Invalid EVE issuer: "
            f"{issuer}"
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
# ESI CHARACTER
# ============================================================

def get_current_eve_character(
    character_id
):

    try:

        response = requests.get(
            (
                f"{ESI_BASE_URL}/characters/"
                f"{int(character_id)}/"
            ),
            timeout=15,
        )

    except Exception as error:

        print(
            "ESI character lookup error:",
            character_id,
            repr(error),
        )

        return None

    if (
        response.status_code
        !=
        200
    ):

        print(
            "ESI character lookup failed:",
            character_id,
            response.status_code,
        )

        return None

    data = (
        response.json()
    )

    if (
        "corporation_id"
        not in data
    ):

        return None

    return data


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


def remove_all_freeborn_roles(
    discord_user_id
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

        results.append({
            "role_id":
                role_id,

            "status_code":
                response.status_code,

            "success":
                response.status_code
                in
                (200, 204),
        })

    return results


# ============================================================
# REVOCATION HELPERS
# ============================================================

def revoke_main_access(
    discord_user_id
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

        not main[
            "in_corporation"
        ]
    ):

        return None

    if not alt_results:

        return None

    if any(
        item["status"]
        != "ok"

        for item
        in alt_results
    ):

        return None

    if any(
        item["in_corporation"]

        for item
        in alt_results
    ):

        return None

    response = (
        remove_discord_role(
            DISCORD_GUILD_ID,
            discord_user_id,
            DISCORD_ALT_CHARACTER_ROLE_ID,
        )
    )

    return (
        response.status_code
    )


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

            if (
                response.status_code
                !=
                200
            ):

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
                data[
                    "corporation_id"
                ]
            )

            in_corporation = (
                current_corporation_id
                ==
                FREEBORN_CORPORATION_ID
            )

            result["status"] = (
                "ok"
            )

            result[
                "in_corporation"
            ] = in_corporation

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

                if not main[
                    "in_corporation"
                ]:

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

            if (
                alt_result
                is not None
            ):

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
# SYNC MESSAGE
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
            item[
                "character_name"
            ]
        )

        character_type = (
            item[
                "character_type"
            ]
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

        elif item[
            "in_corporation"
        ]:

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
            "\n\n🛡️ Les révocations "
            "ne sont effectuées "
            "qu'après confirmation "
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
        and
        actions
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
# SYNC STATUS
# ============================================================

def build_sync_status_message():

    stats = (
        get_database_stats()
    )

    (
        sync_results,
        actions,
    ) = run_sync(
        apply_changes=False
    )

    freeborn_count = 0
    outside_count = 0
    error_count = 0

    outside_names = []
    error_names = []

    for item in sync_results:

        if (
            item["status"]
            != "ok"
        ):

            error_count += 1

            error_names.append(
                item[
                    "character_name"
                ]
            )

            continue

        if item[
            "in_corporation"
        ]:

            freeborn_count += 1

        else:

            outside_count += 1

            outside_names.append(
                item[
                    "character_name"
                ]
            )

    if (
        error_count
        ==
        0
        and
        outside_count
        ==
        0
    ):

        overall_status = (
            "✅ **OPÉRATIONNEL**"
        )

    elif (
        error_count
        >
        0
    ):

        overall_status = (
            "⚠️ **ATTENTION**"
        )

    else:

        overall_status = (
            "🚨 **ACTION REQUISE**"
        )

    lines = [
        "📡 **Freeborn Sync Status**",
        "",
        f"État général : {overall_status}",
        "",
        "### 🗄️ Base Freeborn",
        f"👥 Comptes suivis : **{stats['members']}**",
        f"🎮 Personnages : **{stats['characters']}**",
        f"🔗 Main Characters : **{stats['mains']}**",
        f"🔹 Alt Characters : **{stats['alts']}**",
        (
            "🕒 Dernière synchro enregistrée : "
            f"**{format_datetime(stats['latest_check'])}**"
        ),
        "",
        "### 🌐 Contrôle ESI en direct",
        f"✅ Freeborn : **{freeborn_count}**",
        f"❌ Hors corporation : **{outside_count}**",
        f"⚠️ Erreurs ESI : **{error_count}**",
    ]

    if outside_names:

        lines.extend([
            "",
            "### 🚪 Personnages hors corporation",
        ])

        for name in outside_names:

            lines.append(
                f"❌ **{name}**"
            )

    if error_names:

        lines.extend([
            "",
            "### ⚠️ Personnages non vérifiables",
        ])

        for name in error_names:

            lines.append(
                f"⚠️ **{name}**"
            )

    lines.extend([
        "",
        "🛡️ **Mode lecture seule**",
        "Aucune donnée Neon n'a été modifiée.",
        "Aucun rôle Discord n'a été modifié.",
    ])

    return "\n".join(
        lines
    )


# ============================================================
# AUTOCOMPLETE
# ============================================================

def handle_autocomplete(
    data
):

    command_name = (
        data[
            "data"
        ].get(
            "name"
        )
    )

    if (
        command_name
        not in {
            "main-change",
            "alt-remove",
        }
    ):

        return jsonify({
            "type":
                8,

            "data": {
                "choices":
                    []
            },
        })

    try:

        discord_user_id = str(
            data[
                "member"
            ][
                "user"
            ][
                "id"
            ]
        )

    except Exception:

        return jsonify({
            "type":
                8,

            "data": {
                "choices":
                    []
            },
        })

    search_text = ""

    options = (
        data[
            "data"
        ].get(
            "options",
            [],
        )
    )

    for option in options:

        if (
            option.get("name")
            ==
            "personnage"
        ):

            search_text = str(
                option.get(
                    "value",
                    "",
                )
            ).lower()

            break

    try:

        alts = (
            get_member_alts(
                discord_user_id
            )
        )

    except Exception as error:

        print(
            "Autocomplete database error:",
            repr(error),
        )

        alts = []

    choices = []

    for alt in alts:

        (
            character_id,
            character_name,
            corporation_id,
            in_corporation,
        ) = alt

        if (
            search_text
            and
            search_text
            not in
            character_name.lower()
        ):

            continue

        if (
            command_name
            ==
            "main-change"
        ):

            status_text = (
                "Freeborn"

                if in_corporation

                else

                "à revérifier"
            )

            display_name = (
                f"{character_name} — "
                f"{status_text}"
            )

        else:

            display_name = (
                character_name
            )

        choices.append({
            "name":
                display_name,

            "value":
                str(character_id),
        })

        if (
            len(choices)
            >= 25
        ):

            break

    return jsonify({
        "type":
            8,

        "data": {
            "choices":
                choices,
        },
    })


# ============================================================
# MESSAGE COMPONENT HANDLER
# ============================================================

def handle_message_component(
    data
):

    custom_id = (
        data[
            "data"
        ].get(
            "custom_id",
            "",
        )
    )

    # --------------------------------------------------------
    # Ignore unknown components
    # --------------------------------------------------------

    if not (
        custom_id.startswith(
            "mr_yes:"
        )
        or
        custom_id.startswith(
            "mr_no:"
        )
    ):

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⚠️ Composant inconnu.",

                "components":
                    [],
            },
        })

    try:

        actor_user_id = str(
            data[
                "member"
            ][
                "user"
            ][
                "id"
            ]
        )

    except Exception:

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⚠️ Impossible d'identifier "
                    "l'utilisateur Discord.",

                "components":
                    [],
            },
        })

    token = (
        custom_id.split(
            ":",
            1,
        )[1]
    )

    try:

        (
            target_user_id,
            requester_user_id,
        ) = read_member_remove_token(
            token
        )

    except SignatureExpired:

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⌛ **Confirmation expirée**\n\n"
                    "La suppression n'a pas été effectuée.\n\n"
                    "Relance **/member-remove** "
                    "si nécessaire.",

                "components":
                    [],
            },
        })

    except (
        BadSignature,
        ValueError,
    ):

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⛔ **Confirmation invalide**\n\n"
                    "Aucune modification n'a été effectuée.",

                "components":
                    [],
            },
        })

    # --------------------------------------------------------
    # Only the staff member who launched the command may act
    # --------------------------------------------------------

    if (
        actor_user_id
        !=
        requester_user_id
    ):

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "⛔ Cette confirmation ne "
                    "t'appartient pas.",

                "flags":
                    64,
            },
        })

    # --------------------------------------------------------
    # Staff permissions are checked again
    # --------------------------------------------------------

    if not interaction_is_staff(
        data
    ):

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⛔ **Accès refusé**\n\n"
                    "Tu ne possèdes plus un rôle "
                    "Fondateur, CEO ou Directeur.\n\n"
                    "Aucune suppression effectuée.",

                "components":
                    [],
            },
        })

    # --------------------------------------------------------
    # CANCEL
    # --------------------------------------------------------

    if custom_id.startswith(
        "mr_no:"
    ):

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "🛡️ **Suppression annulée**\n\n"
                    "Aucune donnée Neon n'a été modifiée.\n"
                    "Aucun rôle Discord n'a été modifié.",

                "components":
                    [],
            },
        })

    # --------------------------------------------------------
    # Extra protection against self-removal
    # --------------------------------------------------------

    if (
        target_user_id
        ==
        actor_user_id
    ):

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⛔ **Suppression refusée**\n\n"
                    "Un membre du staff ne peut pas "
                    "supprimer son propre profil avec "
                    "**/member-remove**.",

                "components":
                    [],
            },
        })

    # --------------------------------------------------------
    # Recheck database BEFORE destruction
    # --------------------------------------------------------

    try:

        characters_before_delete = (
            get_member_characters(
                target_user_id
            )
        )

    except Exception as error:

        print(
            "Member remove recheck failed:",
            repr(error),
        )

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⚠️ **Erreur base de données**\n\n"
                    "Le profil n'a pas été supprimé.",

                "components":
                    [],
            },
        })

    if not characters_before_delete:

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "ℹ️ **Aucun profil à supprimer**\n\n"
                    "Ce compte Discord ne possède plus "
                    "de personnage EVE enregistré.",

                "components":
                    [],
            },
        })

    # --------------------------------------------------------
    # DELETE DATABASE PROFILE
    # --------------------------------------------------------

    try:

        deleted_characters = (
            remove_member_profile(
                target_user_id
            )
        )

    except Exception as error:

        print(
            "Member remove database error:",
            repr(error),
        )

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    "⚠️ **Suppression interrompue**\n\n"
                    "Une erreur base de données "
                    "a empêché la suppression.\n\n"
                    "Aucun rôle Discord n'a été retiré.",

                "components":
                    [],
            },
        })

    # --------------------------------------------------------
    # REMOVE DISCORD ROLES
    # --------------------------------------------------------

    role_results = (
        remove_all_freeborn_roles(
            target_user_id
        )
    )

    roles_ok = all(
        item[
            "success"
        ]
        for item
        in role_results
    )

    main_names = [
        row[1]
        for row in deleted_characters
        if row[2] == "main"
    ]

    alt_names = [
        row[1]
        for row in deleted_characters
        if row[2] == "alt"
    ]

    lines = [
        "🗑️ **Freeborn Member Remove**",
        "",
        f"Compte Discord : `{target_user_id}`",
        "",
    ]

    if main_names:

        lines.append(
            "🔗 Main supprimé : "
            f"**{main_names[0]}**"
        )

    if alt_names:

        lines.append(
            "🔹 Alts supprimés : "
            f"**{', '.join(alt_names)}**"
        )

    lines.extend([
        "",
        f"🗄️ Personnages supprimés de Neon : "
        f"**{len(deleted_characters)}**",
    ])

    if roles_ok:

        lines.extend([
            "✅ Rôles Freeborn retirés.",
            "",
            "✅ **Suppression terminée.**",
        ])

    else:

        lines.extend([
            "⚠️ Le profil Neon a été supprimé,",
            "mais au moins un rôle Discord "
            "n'a pas pu être retiré.",
            "",
            "➡️ Vérifie manuellement les rôles "
            "du membre.",
        ])

    return jsonify({
        "type":
            7,

        "data": {
            "content":
                "\n".join(
                    lines
                ),

            "components":
                [],
        },
    })


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
    Freeborn Verify est opérationnel.
    </p>
    """


# ============================================================
# HEALTH
# ============================================================

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
                stats[
                    "characters"
                ],

            "mains":
                stats[
                    "mains"
                ],

            "alts":
                stats[
                    "alts"
                ],

            "outside_corporation":
                stats[
                    "outside_corporation"
                ],
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

    data = (
        request.get_json()
    )

    # ========================================================
    # PING
    # ========================================================

    if (
        data["type"]
        ==
        1
    ):

        return jsonify({
            "type":
                1
        })

    # ========================================================
    # MESSAGE COMPONENT
    # ========================================================

    if (
        data["type"]
        ==
        3
    ):

        return (
            handle_message_component(
                data
            )
        )

    # ========================================================
    # AUTOCOMPLETE
    # ========================================================

    if (
        data["type"]
        ==
        4
    ):

        return (
            handle_autocomplete(
                data
            )
        )

    # ========================================================
    # APPLICATION COMMAND
    # ========================================================

    if (
        data["type"]
        !=
        2
    ):

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "Commande inconnue.",

                **interaction_response_flags_payload(data),
            },
        })

    command_name = (
        data[
            "data"
        ][
            "name"
        ]
    )

    discord_user_id = str(
        data[
            "member"
        ][
            "user"
        ][
            "id"
        ]
    )

    guild_id = (
        data[
            "guild_id"
        ]
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
                    "réservée à "
                    "Freeborn Legacy.",

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # STAFF-ONLY COMMANDS
    # ========================================================

    STAFF_ONLY_COMMANDS = {
        "member-remove",
        "member-list",
        "db-health",
        "sync-status",
        "sync-check",
        "sync-apply",
    }

    if (
        command_name
        in STAFF_ONLY_COMMANDS

        and

        not interaction_is_staff(
            data
        )
    ):

        return (
            staff_access_denied(data)
        )

    if (
        command_name
        in STAFF_ONLY_COMMANDS

        and

        str(data.get("channel_id", ""))
        !=
        DISCORD_CHARACTER_MANAGEMENT_CHANNEL_ID
    ):

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "📍 **Commande staff réservée**\n\n"
                    "Utilise cette commande dans "
                    "<#1535497895929708648> "
                    "(**character-management**).",

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /member-remove
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "member-remove"
    ):

        options = (
            data[
                "data"
            ].get(
                "options",
                [],
            )
        )

        target_user_id = None

        for option in options:

            if (
                option.get("name")
                ==
                "membre"
            ):

                target_user_id = str(
                    option[
                        "value"
                    ]
                )

                break

        if not target_user_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun membre sélectionné.",

                    **interaction_response_flags_payload(data),
                },
            })

        # ----------------------------------------------------
        # Never allow staff to remove own profile by accident
        # ----------------------------------------------------

        if (
            target_user_id
            ==
            discord_user_id
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Suppression refusée**\n\n"
                        "Tu ne peux pas supprimer "
                        "ton propre profil avec "
                        "**/member-remove**.",

                    **interaction_response_flags_payload(data),
                },
            })

        # ----------------------------------------------------
        # Discord target information
        # ----------------------------------------------------

        resolved = (
            data[
                "data"
            ].get(
                "resolved",
                {},
            )
        )

        target_users = (
            resolved.get(
                "users",
                {},
            )
        )

        target_members = (
            resolved.get(
                "members",
                {},
            )
        )

        target_user = (
            target_users.get(
                target_user_id,
                {},
            )
        )

        target_member = (
            target_members.get(
                target_user_id,
                {},
            )
        )

        target_display_name = (
            target_member.get(
                "nick"
            )

            or

            target_user.get(
                "global_name"
            )

            or

            target_user.get(
                "username"
            )

            or

            target_user_id
        )

        # ----------------------------------------------------
        # Database preview
        # ----------------------------------------------------

        try:

            characters = (
                get_member_characters(
                    target_user_id
                )
            )

        except Exception as error:

            print(
                "Member remove preview failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible de lire "
                        "le profil de ce membre.",

                    **interaction_response_flags_payload(data),
                },
            })

        if not characters:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "ℹ️ **Aucun profil EVE enregistré**\n\n"
                        f"**{target_display_name}** "
                        "ne possède aucun personnage "
                        "dans Freeborn Verify.\n\n"
                        "Aucune modification effectuée.",

                    **interaction_response_flags_payload(data),
                },
            })

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

        preview_lines = [
            "⚠️ **CONFIRMATION — MEMBER REMOVE**",
            "",
            f"Membre : **{target_display_name}**",
            f"Discord ID : `{target_user_id}`",
            "",
        ]

        if main_rows:

            preview_lines.append(
                "🔗 Main : "
                f"**{main_rows[0][1]}**"
            )

        if alt_rows:

            preview_lines.append(
                "🔹 Alts : "
                f"**{', '.join(row[1] for row in alt_rows)}**"
            )

        preview_lines.extend([
            "",
            f"🗄️ Personnages concernés : "
            f"**{len(characters)}**",
            "",
            "Cette action supprimera :",
            "• toutes les associations EVE dans Neon ;",
            "• le rôle Membre ;",
            "• le rôle EVE Verified ;",
            "• le rôle Main Character ;",
            "• le rôle Alt Character.",
            "",
            "⚠️ **Cette action est destructive.**",
            "La confirmation expire dans 5 minutes.",
        ])

        token = (
            create_member_remove_token(
                target_user_id,
                discord_user_id,
            )
        )

        confirm_custom_id = (
            f"mr_yes:{token}"
        )

        cancel_custom_id = (
            f"mr_no:{token}"
        )

        if (
            len(confirm_custom_id)
            >
            100
            or
            len(cancel_custom_id)
            >
            100
        ):

            print(
                "Member remove custom_id too long"
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible de générer "
                        "la confirmation sécurisée.",

                    **interaction_response_flags_payload(data),
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "\n".join(
                        preview_lines
                    ),

                **interaction_response_flags_payload(data),

                "components": [
                    {
                        "type":
                            1,

                        "components": [
                            {
                                "type":
                                    2,

                                "style":
                                    4,

                                "label":
                                    "Confirmer la suppression",

                                "custom_id":
                                    confirm_custom_id,
                            },

                            {
                                "type":
                                    2,

                                "style":
                                    2,

                                "label":
                                    "Annuler",

                                "custom_id":
                                    cancel_custom_id,
                            },
                        ],
                    }
                ],
            },
        })

    # ========================================================
    # /alt-remove
    # MEMBER COMMAND
    # ========================================================

    if (
        command_name
        ==
        "alt-remove"
    ):

        options = (
            data[
                "data"
            ].get(
                "options",
                [],
            )
        )

        selected_character_id = None

        for option in options:

            if (
                option.get("name")
                ==
                "personnage"
            ):

                selected_character_id = (
                    option.get(
                        "value"
                    )
                )

                break

        if not selected_character_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun Alt Character "
                        "n'a été sélectionné.",

                    **interaction_response_flags_payload(data),
                },
            })

        try:

            alts = (
                get_member_alts(
                    discord_user_id
                )
            )

        except Exception as error:

            print(
                "Alt remove lookup failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible de lire "
                        "tes Alt Characters.",

                    **interaction_response_flags_payload(data),
                },
            })

        selected_alt = None

        for alt in alts:

            if (
                str(alt[0])
                ==
                str(selected_character_id)
            ):

                selected_alt = alt

                break

        if not selected_alt:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Ce personnage n'est pas "
                        "un Alt Character enregistré "
                        "sur ton compte.\n\n"
                        "Ton Main ne peut jamais être "
                        "supprimé avec **/alt-remove**.",

                    **interaction_response_flags_payload(data),
                },
            })

        try:

            result = (
                remove_alt_character(
                    discord_user_id,
                    selected_character_id,
                )
            )

        except ValueError as error:

            print(
                "Alt remove refused:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ **Suppression refusée**\n\n"
                        f"{str(error)}",

                    **interaction_response_flags_payload(data),
                },
            })

        except Exception as error:

            print(
                "Alt remove database error:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ **Erreur base de données**\n\n"
                        "L'Alt n'a pas été supprimé.",

                    **interaction_response_flags_payload(data),
                },
            })

        remaining_alts = (
            result[
                "remaining_alts"
            ]
        )

        if (
            remaining_alts
            ==
            0
        ):

            role_response = (
                remove_discord_role(
                    guild_id,
                    discord_user_id,
                    DISCORD_ALT_CHARACTER_ROLE_ID,
                )
            )

            role_removed = (
                role_response.status_code
                in
                (200, 204)
            )

            if role_removed:

                role_text = (
                    "🔹 Aucun Alt restant : "
                    "rôle **Alt Character** retiré."
                )

            else:

                role_text = (
                    "⚠️ Aucun Alt restant, mais "
                    "le rôle **Alt Character** "
                    "n'a pas pu être retiré."
                )

        else:

            role_text = (
                f"🔹 Alts restants : "
                f"**{remaining_alts}** — "
                "rôle **Alt Character** conservé."
            )

        current_main = (
            get_main_character(
                discord_user_id
            )
        )

        current_main_name = (
            current_main[1]

            if current_main

            else

            "Inconnu"
        )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "🗑️ **Freeborn Alt Remove**\n\n"

                    f"Alt supprimé : "
                    f"**{result['character_name']}**\n\n"

                    "✅ Le personnage a été retiré "
                    "de ton profil Freeborn.\n"

                    f"✅ Ton Main "
                    f"**{current_main_name}** "
                    "reste inchangé.\n"

                    f"{role_text}",

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /member-list
    # STAFF ONLY - READ ONLY
    # ========================================================

    if (
        command_name
        ==
        "member-list"
    ):

        try:

            message = (
                build_member_list_message()
            )

        except Exception as error:

            print(
                "Member list failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "👥 **Freeborn Member List**\n\n"
                        "⚠️ Impossible de lire "
                        "la liste des membres actuellement.\n\n"
                        "Aucune modification "
                        "n'a été effectuée.",

                    **interaction_response_flags_payload(data),
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /sync-status
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "sync-status"
    ):

        try:

            message = (
                build_sync_status_message()
            )

        except Exception as error:

            print(
                "Sync status failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "📡 **Freeborn Sync Status**\n\n"
                        "⚠️ Impossible de générer "
                        "l'état global actuellement.\n\n"
                        "Aucune modification "
                        "n'a été effectuée.",

                    **interaction_response_flags_payload(data),
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /main-change
    # MEMBER COMMAND
    # ========================================================

    if (
        command_name
        ==
        "main-change"
    ):

        try:

            current_main = (
                get_main_character(
                    discord_user_id
                )
            )

        except Exception as error:

            print(
                "Main change lookup failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible de lire "
                        "ton Main Character.",

                    **interaction_response_flags_payload(data),
                },
            })

        if not current_main:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun Main Character "
                        "n'est enregistré.\n\n"
                        "Utilise d'abord **/verify**.",

                    **interaction_response_flags_payload(data),
                },
            })

        options = (
            data[
                "data"
            ].get(
                "options",
                [],
            )
        )

        selected_character_id = None

        for option in options:

            if (
                option.get("name")
                ==
                "personnage"
            ):

                selected_character_id = (
                    option.get(
                        "value"
                    )
                )

                break

        if not selected_character_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun Alt Character "
                        "n'a été sélectionné.",

                    **interaction_response_flags_payload(data),
                },
            })

        try:

            alts = (
                get_member_alts(
                    discord_user_id
                )
            )

        except Exception as error:

            print(
                "Main change alt lookup failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible de lire "
                        "tes Alt Characters.",

                    **interaction_response_flags_payload(data),
                },
            })

        selected_alt = None

        for alt in alts:

            if (
                str(alt[0])
                ==
                str(selected_character_id)
            ):

                selected_alt = alt

                break

        if not selected_alt:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Ce personnage n'est pas "
                        "un Alt Character enregistré "
                        "sur ton compte.",

                    **interaction_response_flags_payload(data),
                },
            })

        (
            new_main_id,
            new_main_name,
            stored_corporation_id,
            stored_in_corporation,
        ) = selected_alt

        eve_data = (
            get_current_eve_character(
                new_main_id
            )
        )

        if eve_data is None:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ **Changement annulé**\n\n"
                        "EVE ESI n'a pas pu confirmer "
                        "l'état actuel du personnage.\n\n"
                        "Aucune donnée n'a été modifiée.",

                    **interaction_response_flags_payload(data),
                },
            })

        current_corporation_id = int(
            eve_data[
                "corporation_id"
            ]
        )

        if (
            current_corporation_id
            !=
            FREEBORN_CORPORATION_ID
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ **Changement refusé**\n\n"
                        f"**{new_main_name}** "
                        "n'appartient actuellement "
                        "pas à **Freeborn Legacy**.\n\n"
                        "Ton Main actuel reste inchangé.",

                    **interaction_response_flags_payload(data),
                },
            })

        try:

            result = (
                change_main_character(
                    discord_user_id,
                    new_main_id,
                    current_corporation_id,
                )
            )

        except ValueError as error:

            print(
                "Main change refused:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ **Changement impossible**\n\n"
                        f"{str(error)}",

                    **interaction_response_flags_payload(data),
                },
            })

        except Exception as error:

            print(
                "Main change database error:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ **Erreur base de données**\n\n"
                        "Le changement de Main "
                        "n'a pas été effectué.",

                    **interaction_response_flags_payload(data),
                },
            })

        add_discord_role(
            guild_id,
            discord_user_id,
            DISCORD_MEMBER_ROLE_ID,
        )

        add_discord_role(
            guild_id,
            discord_user_id,
            DISCORD_EVE_VERIFIED_ROLE_ID,
        )

        add_discord_role(
            guild_id,
            discord_user_id,
            DISCORD_MAIN_CHARACTER_ROLE_ID,
        )

        add_discord_role(
            guild_id,
            discord_user_id,
            DISCORD_ALT_CHARACTER_ROLE_ID,
        )

        nickname_response = (
            sync_discord_nickname(
                guild_id,
                discord_user_id,
                result[
                    "new_main_name"
                ],
            )
        )

        nickname_changed = (
            nickname_response.status_code
            in
            (200, 204)
        )

        nickname_text = (
            "✅ Pseudo Discord synchronisé "
            f"sur **{result['new_main_name']}**."

            if nickname_changed

            else

            "⚠️ Le changement de Main est validé, "
            "mais le pseudo Discord n'a pas pu "
            "être modifié."
        )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "🔄 **Freeborn Main Change**\n\n"

                    f"Ancien Main : "
                    f"**{result['old_main_name']}** "
                    "→ Alt Character\n"

                    f"Nouveau Main : "
                    f"**{result['new_main_name']}** "
                    "→ Main Character\n\n"

                    "✅ Changement enregistré "
                    "dans Freeborn Verify.\n"

                    f"{nickname_text}\n\n"

                    "Aucun personnage EVE "
                    "n'a été supprimé.",

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /member-info
    # ========================================================

    if (
        command_name
        ==
        "member-info"
    ):

        caller_user = (
            data[
                "member"
            ][
                "user"
            ]
        )

        caller_display_name = (
            data[
                "member"
            ].get(
                "nick"
            )

            or

            caller_user.get(
                "global_name"
            )

            or

            caller_user.get(
                "username"
            )

            or

            "Utilisateur Discord"
        )

        target_user_id = (
            discord_user_id
        )

        target_display_name = (
            caller_display_name
        )

        options = (
            data[
                "data"
            ].get(
                "options",
                [],
            )
        )

        selected_target = False

        for option in options:

            if (
                option.get("name")
                ==
                "membre"
            ):

                target_user_id = str(
                    option[
                        "value"
                    ]
                )

                selected_target = True

                break

        if (
            selected_target

            and

            target_user_id
            !=
            discord_user_id

            and

            not interaction_is_staff(
                data
            )
        ):

            return (
                staff_access_denied(data)
            )

        resolved = (
            data[
                "data"
            ].get(
                "resolved",
                {},
            )
        )

        resolved_users = (
            resolved.get(
                "users",
                {},
            )
        )

        resolved_members = (
            resolved.get(
                "members",
                {},
            )
        )

        target_user = (
            resolved_users.get(
                target_user_id,
                {},
            )
        )

        target_member = (
            resolved_members.get(
                target_user_id,
                {},
            )
        )

        if target_user:

            target_display_name = (
                target_member.get(
                    "nick"
                )

                or

                target_user.get(
                    "global_name"
                )

                or

                target_user.get(
                    "username"
                )

                or

                target_display_name
            )

        try:

            message = (
                build_member_info(
                    target_user_id,
                    target_display_name,
                )
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
                        "ce profil actuellement.",

                    **interaction_response_flags_payload(data),
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    message,

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /db-health
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "db-health"
    ):

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
                        "❌ Base de données "
                        "indisponible.",

                    **interaction_response_flags_payload(data),
                },
            })

        message = (
            "🗄️ **Freeborn Database Health**\n\n"

            "✅ Statut : **Connectée**\n"

            "📋 Table : "
            "**eve_characters**\n\n"

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

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /sync-check
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "sync-check"
    ):

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

                    **interaction_response_flags_payload(data),
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

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /sync-apply
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "sync-apply"
    ):

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

                    **interaction_response_flags_payload(data),
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

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /verify
    # MEMBER COMMAND
    # ========================================================

    if (
        command_name
        ==
        "verify"
    ):

        verification_type = (
            "main"
        )

    # ========================================================
    # /alt
    # MEMBER COMMAND
    # ========================================================

    elif (
        command_name
        ==
        "alt"
    ):

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

                    **interaction_response_flags_payload(data),
                },
            })

        if not main_exists:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Utilise d'abord "
                        "**/verify** "
                        "pour ton Main.",

                    **interaction_response_flags_payload(data),
                },
            })

    else:

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "Commande inconnue.",

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # EVE SSO LINK
    # ========================================================

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
        ==
        "main"
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

            **interaction_response_flags_payload(data),
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

    if (
        not code
        or
        not state
    ):

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
        !=
        200
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
        !=
        200
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
    # MAIN FLOW
    # ========================================================

    if (
        verification_type
        ==
        "main"
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

                <p>
                <strong>Character:</strong>
                {character_name}
                </p>

                <h2>❌ MAIN ALREADY REGISTERED</h2>

                <p>
                Ton personnage principal actuel est
                <strong>{existing_main_name}</strong>.
                </p>

                <p>
                Utilise la commande
                <strong>/main-change</strong>
                pour changer de Main Character.
                </p>
                """, 400

            return """
            <h1>Freeborn Verify</h1>

            <h2>❌ CHARACTER ALREADY LINKED</h2>

            <p>
            Ce personnage EVE est déjà associé
            à un autre compte Discord.
            </p>
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
            not in
            (200, 204)

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
            "<p>"
            "Le pseudo Discord a été "
            "synchronisé sur "
            f"<strong>{character_name}</strong>."
            "</p>"

            if nickname_changed

            else

            "<p>"
            "Le pseudo Discord n'a pas pu "
            "être modifié "
            "(hiérarchie ou permission Discord)."
            "</p>"
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
    # ALT FLOW
    # ========================================================

    if not has_main_character(
        discord_user_id
    ):

        return """
        <h1>Freeborn Verify</h1>

        <h2>❌ MAIN REQUIRED</h2>

        <p>
        Tu dois d'abord enregistrer
        ton Main avec /verify.
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

        <p>
        Ce personnage est déjà associé
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
    a été ajouté comme
    <strong>Alt Character</strong>.
    </p>

    <p>
    Tu peux retourner sur Discord.
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

        # ====================================================
        # MEMBER COMMANDS
        # ====================================================

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
                "alt-remove",

            "description":
                "Supprimer un Alt "
                "de ton profil Freeborn",

            "type":
                1,

            "options": [
                {
                    "type":
                        3,

                    "name":
                        "personnage",

                    "description":
                        "Alt Character à supprimer",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "main-change",

            "description":
                "Choisir un de tes Alts "
                "comme nouveau Main",

            "type":
                1,

            "options": [
                {
                    "type":
                        3,

                    "name":
                        "personnage",

                    "description":
                        "Alt Character "
                        "qui deviendra ton Main",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "member-info",

            "description":
                "Afficher un profil EVE Freeborn",

            "type":
                1,

            "options": [
                {
                    "type":
                        6,

                    "name":
                        "membre",

                    "description":
                        "Autre membre à consulter "
                        "(staff uniquement)",

                    "required":
                        False,
                }
            ],
        },

        # ====================================================
        # STAFF COMMANDS
        # ====================================================

        {
            "name":
                "member-remove",

            "description":
                "Supprimer complètement "
                "le profil EVE d'un membre",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites allow Founder, CEO and Director.
            "default_member_permissions":
                "0",

            "options": [
                {
                    "type":
                        6,

                    "name":
                        "membre",

                    "description":
                        "Membre Freeborn à supprimer",

                    "required":
                        True,
                }
            ],
        },

        {
            "name":
                "member-list",

            "description":
                "Afficher la liste des "
                "membres EVE enregistrés",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites allow Founder, CEO and Director.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "db-health",

            "description":
                "Afficher l'état de "
                "la base Freeborn",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites allow Founder, CEO and Director.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "sync-status",

            "description":
                "Afficher l'état global "
                "de la synchronisation",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites allow Founder, CEO and Director.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "sync-check",

            "description":
                "Contrôler les personnages "
                "Freeborn sans modifier les rôles",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites allow Founder, CEO and Director.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "sync-apply",

            "description":
                "Synchroniser et révoquer "
                "les anciens membres",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites allow Founder, CEO and Director.
            "default_member_permissions":
                "0",
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

            json=
                commands,

            timeout=
                15,
        )

        if (
            response.status_code
            ==
            200
        ):

            print(
                "Discord commands registered: "
                "/verify, /alt, /alt-remove, "
                "/main-change, /member-info, "
                "/member-remove, /member-list, "
                "/db-health, /sync-status, "
                "/sync-check, "
                "/sync-apply."
            )

        else:

            print(
                "Discord command "
                "registration failed:",

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
        host=
            "0.0.0.0",

        port=
            port,
    )
