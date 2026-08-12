import base64
import hashlib
import os
from html import escape
from urllib.parse import urlencode

import psycopg
import requests

from flask import Flask, jsonify, request, send_from_directory
from nacl.exceptions import BadSignatureError
from nacl.secret import SecretBox
from nacl.signing import VerifyKey

from itsdangerous import (
    URLSafeTimedSerializer,
    TimestampSigner,
    BadSignature,
    SignatureExpired,
)

from jose import jwt


app = Flask(__name__)


@app.get("/assets/<path:filename>")
def freeborn_assets(filename):

    return send_from_directory(
        os.path.join(
            os.path.dirname(__file__),
            "assets",
        ),
        filename,
    )


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

EVE_CLIENT_ID = os.environ["EVE_CLIENT_ID"]
EVE_CLIENT_SECRET = os.environ["EVE_CLIENT_SECRET"]
EVE_CALLBACK_URL = os.environ["EVE_CALLBACK_URL"]

PUBLIC_BASE_URL = EVE_CALLBACK_URL.rsplit(
    "/callback",
    1,
)[0].rstrip("/")

FREEBORN_CORPORATION_ID = int(
    os.environ["FREEBORN_CORPORATION_ID"]
)

DISCORD_BOT_TOKEN = os.environ["DISCORD_BOT_TOKEN"]
DISCORD_PUBLIC_KEY = os.environ["DISCORD_PUBLIC_KEY"]
DISCORD_APPLICATION_ID = os.environ["DISCORD_APPLICATION_ID"]
DISCORD_GUILD_ID = os.environ["DISCORD_GUILD_ID"]

# ============================================================
# DISCORD V3 CONFIGURATION
# ============================================================

DISCORD_RECRUITMENT_CHANNEL_ID = os.environ.get(
    "DISCORD_RECRUITMENT_CHANNEL_ID",
    "1535497827503964190",
)

DISCORD_BOT_MANAGEMENT_CHANNEL_ID = os.environ.get(
    "DISCORD_BOT_MANAGEMENT_CHANNEL_ID",
    "1535497895929708648",
)

DISCORD_LOGS_CHANNEL_ID = os.environ.get(
    "DISCORD_LOGS_CHANNEL_ID"
)


DISCORD_ORIENTATION_CHANNEL_ID = os.environ.get(
    "DISCORD_ORIENTATION_CHANNEL_ID"
)

DISCORD_CORP_RULES_CHANNEL_ID = os.environ.get(
    "DISCORD_CORP_RULES_CHANNEL_ID"
)

DISCORD_CHARTER_CHANNEL_ID = os.environ.get(
    "DISCORD_CHARTER_CHANNEL_ID"
)


# Version identifiers recorded with each acceptance.
# Increase a version when the corresponding document changes and
# members must accept the new version again.
CORP_RULES_VERSION = os.environ.get(
    "CORP_RULES_VERSION",
    "1.0",
)

FREEBORN_CHARTER_VERSION = os.environ.get(
    "FREEBORN_CHARTER_VERSION",
    "1.0",
)

DISCORD_EVE_VERIFICATION_CHANNEL_ID = (
    DISCORD_RECRUITMENT_CHANNEL_ID
)

DISCORD_CHARACTER_MANAGEMENT_CHANNEL_ID = (
    DISCORD_BOT_MANAGEMENT_CHANNEL_ID
)

DISCORD_MEMBER_ROLE_ID = os.environ[
    "DISCORD_MEMBER_ROLE_ID"
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

DISCORD_GUEST_ROLE_ID = os.environ.get(
    "DISCORD_GUEST_ROLE_ID"
)

DISCORD_CANDIDATE_ROLE_ID = (
    os.environ.get("DISCORD_CANDIDATE_ROLE_ID")
    or
    os.environ.get("DISCORD_RECRUIT_ROLE_ID")
)

DISCORD_CANDIDATE_ACCEPTED_ROLE_ID = os.environ.get(
    "DISCORD_CANDIDATE_ACCEPTED_ROLE_ID"
)

DISCORD_RECRUIT_ROLE_ID = (
    DISCORD_CANDIDATE_ROLE_ID
)

DISCORD_CEO_ROLE_ID = os.environ[
    "DISCORD_CEO_ROLE_ID"
]

DISCORD_HIGH_COUNCIL_ROLE_ID = os.environ.get(
    "DISCORD_HIGH_COUNCIL_ROLE_ID"
)

DISCORD_DIRECTION_ROLE_ID = (
    os.environ.get("DISCORD_DIRECTION_ROLE_ID")
    or
    os.environ.get("DISCORD_DIRECTOR_ROLE_ID")
)

DISCORD_HR_ROLE_ID = os.environ.get(
    "DISCORD_HR_ROLE_ID"
)

DISCORD_OFFICER_ROLE_ID = os.environ.get(
    "DISCORD_OFFICER_ROLE_ID"
)

DISCORD_FLEET_COMMANDER_ROLE_ID = os.environ.get(
    "DISCORD_FLEET_COMMANDER_ROLE_ID"
)

DISCORD_VETERAN_ROLE_ID = os.environ.get(
    "DISCORD_VETERAN_ROLE_ID"
)

DISCORD_DIRECTOR_ROLE_ID = (
    DISCORD_DIRECTION_ROLE_ID
)

FLASK_SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]


# ============================================================
# V3 ROLE ACCESS GROUPS
# ============================================================

def configured_role_ids(*role_ids):
    return {
        str(role_id)
        for role_id in role_ids
        if role_id
    }


SYSTEM_ADMIN_ROLE_IDS = configured_role_ids(
    DISCORD_CEO_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
)

RECRUITMENT_MANAGER_ROLE_IDS = configured_role_ids(
    DISCORD_CEO_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
    DISCORD_HR_ROLE_ID,
)

MODERATION_ROLE_IDS = configured_role_ids(
    DISCORD_CEO_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
    DISCORD_HR_ROLE_ID,
    DISCORD_OFFICER_ROLE_ID,
)

AUDIT_VIEWER_ROLE_IDS = configured_role_ids(
    DISCORD_CEO_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
    DISCORD_HR_ROLE_ID,
)

RECRUITMENT_REVIEWER_ROLE_IDS = configured_role_ids(
    DISCORD_CEO_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
    DISCORD_HR_ROLE_ID,
)

STAFF_ROLE_IDS = SYSTEM_ADMIN_ROLE_IDS


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

# Private ESI permissions requested only during the /freeborn
# candidate/member integration flow. Guests never use EVE SSO.
FREEBORN_EVE_SCOPES = (
    "esi-skills.read_skills.v1",
)

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

alt_remove_signer = TimestampSigner(
    FLASK_SECRET_KEY,
    salt="freeborn-alt-remove",
)

main_change_signer = TimestampSigner(
    FLASK_SECRET_KEY,
    salt="freeborn-main-change",
)


sync_apply_signer = TimestampSigner(
    FLASK_SECRET_KEY,
    salt="freeborn-sync-apply",
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


                # ====================================================
                # V3 MULTI-GUILD / RECRUITMENT FOUNDATION
                # ====================================================

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS discord_guilds (
                        guild_id TEXT PRIMARY KEY,
                        guild_name TEXT,
                        corporation_id BIGINT,
                        recruitment_channel_id TEXT,
                        bot_management_channel_id TEXT,
                        logs_channel_id TEXT,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        orientation_channel_id TEXT,
                        corp_rules_channel_id TEXT,
                        charter_channel_id TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    );
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE discord_guilds
                    ADD COLUMN IF NOT EXISTS
                    orientation_channel_id TEXT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE discord_guilds
                    ADD COLUMN IF NOT EXISTS
                    corp_rules_channel_id TEXT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE discord_guilds
                    ADD COLUMN IF NOT EXISTS
                    charter_channel_id TEXT;
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS guild_roles (
                        guild_id TEXT NOT NULL,
                        role_type TEXT NOT NULL,
                        role_id TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        PRIMARY KEY (guild_id, role_type),
                        FOREIGN KEY (guild_id)
                            REFERENCES discord_guilds (guild_id)
                            ON DELETE CASCADE
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS member_statuses (
                        guild_id TEXT NOT NULL,
                        discord_user_id TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN (
                                'guest',
                                'candidate',
                                'candidate_accepted',
                                'member'
                            )
                        ),
                        changed_by_discord_user_id TEXT,
                        changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        PRIMARY KEY (guild_id, discord_user_id),
                        FOREIGN KEY (guild_id)
                            REFERENCES discord_guilds (guild_id)
                            ON DELETE CASCADE
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policy_documents (
                        guild_id TEXT NOT NULL,
                        document_type TEXT NOT NULL,
                        document_version TEXT NOT NULL,
                        message_id TEXT,
                        channel_id TEXT,
                        is_active BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        PRIMARY KEY (
                            guild_id,
                            document_type,
                            document_version
                        ),
                        FOREIGN KEY (guild_id)
                            REFERENCES discord_guilds (guild_id)
                            ON DELETE CASCADE
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS policy_acceptances (
                        guild_id TEXT NOT NULL,
                        discord_user_id TEXT NOT NULL,
                        document_type TEXT NOT NULL,
                        document_version TEXT NOT NULL,
                        accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        message_id TEXT,
                        channel_id TEXT,
                        PRIMARY KEY (
                            guild_id,
                            discord_user_id,
                            document_type,
                            document_version
                        ),
                        FOREIGN KEY (
                            guild_id,
                            document_type,
                            document_version
                        )
                            REFERENCES policy_documents (
                                guild_id,
                                document_type,
                                document_version
                            )
                            ON DELETE CASCADE
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_log (
                        event_id BIGSERIAL PRIMARY KEY,
                        guild_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        target_discord_user_id TEXT,
                        actor_discord_user_id TEXT,
                        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        FOREIGN KEY (guild_id)
                            REFERENCES discord_guilds (guild_id)
                            ON DELETE CASCADE
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS guild_eve_characters (
                        guild_id TEXT NOT NULL,
                        character_id BIGINT NOT NULL,
                        discord_user_id TEXT NOT NULL,
                        character_name TEXT NOT NULL,
                        character_type TEXT NOT NULL CHECK (
                            character_type IN ('main', 'alt')
                        ),
                        corporation_id BIGINT NOT NULL,
                        in_corporation BOOLEAN NOT NULL DEFAULT TRUE,
                        verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        last_checked_at TIMESTAMPTZ,
                        left_corporation_at TIMESTAMPTZ,
                        PRIMARY KEY (guild_id, character_id),
                        FOREIGN KEY (guild_id)
                            REFERENCES discord_guilds (guild_id)
                            ON DELETE CASCADE
                    );
                    """
                )

                # Authenticated ESI data kept with the guild-scoped Main.
                # The refresh token is encrypted before it reaches Neon.
                cur.execute(
                    """
                    ALTER TABLE guild_eve_characters
                    ADD COLUMN IF NOT EXISTS
                    eve_refresh_token_encrypted TEXT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE guild_eve_characters
                    ADD COLUMN IF NOT EXISTS
                    eve_scopes TEXT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE guild_eve_characters
                    ADD COLUMN IF NOT EXISTS
                    total_skill_points BIGINT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE guild_eve_characters
                    ADD COLUMN IF NOT EXISTS
                    skills_updated_at TIMESTAMPTZ;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE guild_eve_characters
                    ADD COLUMN IF NOT EXISTS
                    sso_authorized_at TIMESTAMPTZ;
                    """
                )

                cur.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                    uq_guild_eve_one_main_per_discord
                    ON guild_eve_characters (
                        guild_id,
                        discord_user_id
                    )
                    WHERE character_type = 'main';
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_guild_eve_discord_user
                    ON guild_eve_characters (
                        guild_id,
                        discord_user_id
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_member_statuses_status
                    ON member_statuses (guild_id, status);
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_policy_acceptances_user
                    ON policy_acceptances (
                        guild_id,
                        discord_user_id,
                        accepted_at
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                    idx_audit_log_guild_created_at
                    ON audit_log (guild_id, created_at DESC);
                    """
                )

                cur.execute(
                    """
                    INSERT INTO discord_guilds (
                        guild_id,
                        corporation_id,
                        recruitment_channel_id,
                        bot_management_channel_id,
                        logs_channel_id,
                        orientation_channel_id,
                        corp_rules_channel_id,
                        charter_channel_id,
                        updated_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, NOW()
                    )
                    ON CONFLICT (guild_id)
                    DO UPDATE SET
                        corporation_id = EXCLUDED.corporation_id,
                        recruitment_channel_id =
                            EXCLUDED.recruitment_channel_id,
                        bot_management_channel_id =
                            EXCLUDED.bot_management_channel_id,
                        logs_channel_id = COALESCE(
                            EXCLUDED.logs_channel_id,
                            discord_guilds.logs_channel_id
                        ),
                        orientation_channel_id = COALESCE(
                            EXCLUDED.orientation_channel_id,
                            discord_guilds.orientation_channel_id
                        ),
                        corp_rules_channel_id = COALESCE(
                            EXCLUDED.corp_rules_channel_id,
                            discord_guilds.corp_rules_channel_id
                        ),
                        charter_channel_id = COALESCE(
                            EXCLUDED.charter_channel_id,
                            discord_guilds.charter_channel_id
                        ),
                        updated_at = NOW();
                    """,
                    (
                        str(DISCORD_GUILD_ID),
                        int(FREEBORN_CORPORATION_ID),
                        str(DISCORD_RECRUITMENT_CHANNEL_ID),
                        str(DISCORD_BOT_MANAGEMENT_CHANNEL_ID),
                        (
                            str(DISCORD_LOGS_CHANNEL_ID)
                            if DISCORD_LOGS_CHANNEL_ID
                            else None
                        ),
                        (
                            str(DISCORD_ORIENTATION_CHANNEL_ID)
                            if DISCORD_ORIENTATION_CHANNEL_ID
                            else None
                        ),
                        (
                            str(DISCORD_CORP_RULES_CHANNEL_ID)
                            if DISCORD_CORP_RULES_CHANNEL_ID
                            else None
                        ),
                        (
                            str(DISCORD_CHARTER_CHANNEL_ID)
                            if DISCORD_CHARTER_CHANNEL_ID
                            else None
                        ),
                    ),
                )

                cur.execute(
                    """
                    INSERT INTO guild_eve_characters (
                        guild_id,
                        character_id,
                        discord_user_id,
                        character_name,
                        character_type,
                        corporation_id,
                        in_corporation,
                        verified_at,
                        updated_at,
                        last_checked_at,
                        left_corporation_at
                    )
                    SELECT
                        %s,
                        character_id,
                        discord_user_id,
                        character_name,
                        character_type,
                        corporation_id,
                        in_corporation,
                        verified_at,
                        updated_at,
                        last_checked_at,
                        left_corporation_at
                    FROM eve_characters
                    ON CONFLICT (guild_id, character_id)
                    DO NOTHING;
                    """,
                    (
                        str(DISCORD_GUILD_ID),
                    ),
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
# V3 MULTI-GUILD HELPERS
# ============================================================

VALID_MEMBER_STATUSES = {
    "guest",
    "candidate",
    "candidate_accepted",
    "member",
}


def get_guild_config(guild_id):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    guild_id,
                    guild_name,
                    corporation_id,
                    recruitment_channel_id,
                    bot_management_channel_id,
                    logs_channel_id,
                    is_active,
                    orientation_channel_id,
                    corp_rules_channel_id,
                    charter_channel_id
                FROM discord_guilds
                WHERE guild_id = %s
                LIMIT 1;
                """,
                (
                    str(guild_id),
                ),
            )

            return cur.fetchone()


def get_guild_role_id(
    guild_id,
    role_type,
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT role_id
                FROM guild_roles
                WHERE guild_id = %s
                AND role_type = %s
                LIMIT 1;
                """,
                (
                    str(guild_id),
                    str(role_type),
                ),
            )

            row = cur.fetchone()

            return row[0] if row else None


def set_guild_role_id(
    guild_id,
    role_type,
    role_id,
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO guild_roles (
                    guild_id,
                    role_type,
                    role_id,
                    updated_at
                )
                VALUES (%s, %s, %s, NOW())
                ON CONFLICT (guild_id, role_type)
                DO UPDATE SET
                    role_id = EXCLUDED.role_id,
                    updated_at = NOW();
                """,
                (
                    str(guild_id),
                    str(role_type),
                    str(role_id),
                ),
            )

        conn.commit()


def resolve_guild_role_id(
    guild_id,
    role_type,
):
    """
    Resolve a V3 role for one guild.

    Priority:
    1. guild_roles table (true multi-guild configuration)
    2. current Freeborn environment variables as bootstrap fallback
    """

    role_id = get_guild_role_id(
        guild_id,
        role_type,
    )

    if role_id:

        return str(role_id)

    if str(guild_id) != str(DISCORD_GUILD_ID):

        return None

    bootstrap_roles = {
        "guest":
            DISCORD_GUEST_ROLE_ID,

        "candidate":
            DISCORD_CANDIDATE_ROLE_ID,

        "candidate_accepted":
            DISCORD_CANDIDATE_ACCEPTED_ROLE_ID,

        "member":
            DISCORD_MEMBER_ROLE_ID,

        "ceo":
            DISCORD_CEO_ROLE_ID,

        "high_council":
            DISCORD_HIGH_COUNCIL_ROLE_ID,

        "direction":
            DISCORD_DIRECTION_ROLE_ID,

        "hr":
            DISCORD_HR_ROLE_ID,

        "officer":
            DISCORD_OFFICER_ROLE_ID,

        "fleet_commander":
            DISCORD_FLEET_COMMANDER_ROLE_ID,

        "veteran":
            DISCORD_VETERAN_ROLE_ID,

        "eve_verified":
            DISCORD_EVE_VERIFIED_ROLE_ID,

        "main_character":
            DISCORD_MAIN_CHARACTER_ROLE_ID,

        "alt_character":
            DISCORD_ALT_CHARACTER_ROLE_ID,
    }

    role_id = bootstrap_roles.get(
        str(role_type)
    )

    return (
        str(role_id)
        if role_id
        else None
    )


def interaction_member_role_ids(data):

    try:

        return {
            str(role_id)
            for role_id
            in data["member"]["roles"]
        }

    except (
        KeyError,
        TypeError,
    ):

        return set()


def apply_recruitment_status_role(
    guild_id,
    discord_user_id,
    new_status,
):
    """
    Apply only the recruitment/status roles involved in a V3 transition.

    This helper deliberately does not touch EVE identity roles
    (EVE Verified / Main / Alt).
    """

    if new_status not in VALID_MEMBER_STATUSES:

        raise ValueError(
            f"Invalid V3 member status: {new_status}"
        )

    target_role_id = resolve_guild_role_id(
        guild_id,
        new_status,
    )

    if not target_role_id:

        raise ValueError(
            f"Discord role not configured for status: {new_status}"
        )

    transition_role_types = (
        "guest",
        "candidate",
        "candidate_accepted",
        "member",
    )

    removal_results = []

    for role_type in transition_role_types:

        role_id = resolve_guild_role_id(
            guild_id,
            role_type,
        )

        if (
            not role_id
            or
            role_id == target_role_id
        ):

            continue

        response = remove_discord_role(
            guild_id,
            discord_user_id,
            role_id,
        )

        removal_results.append({
            "role_type":
                role_type,

            "role_id":
                role_id,

            "status_code":
                response.status_code,
        })

    add_response = add_discord_role(
        guild_id,
        discord_user_id,
        target_role_id,
    )

    return {
        "target_role_id":
            target_role_id,

        "add_status_code":
            add_response.status_code,

        "removals":
            removal_results,
    }


def get_member_status_v3(
    guild_id,
    discord_user_id,
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    status,
                    changed_by_discord_user_id,
                    changed_at,
                    updated_at
                FROM member_statuses
                WHERE guild_id = %s
                AND discord_user_id = %s
                LIMIT 1;
                """,
                (
                    str(guild_id),
                    str(discord_user_id),
                ),
            )

            return cur.fetchone()


def set_member_status_v3(
    guild_id,
    discord_user_id,
    status,
    changed_by_discord_user_id=None,
):

    if status not in VALID_MEMBER_STATUSES:

        raise ValueError(
            f"Invalid V3 member status: {status}"
        )

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO member_statuses (
                    guild_id,
                    discord_user_id,
                    status,
                    changed_by_discord_user_id,
                    changed_at,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (
                    guild_id,
                    discord_user_id
                )
                DO UPDATE SET
                    status = EXCLUDED.status,
                    changed_by_discord_user_id =
                        EXCLUDED.changed_by_discord_user_id,
                    changed_at = NOW(),
                    updated_at = NOW();
                """,
                (
                    str(guild_id),
                    str(discord_user_id),
                    str(status),
                    (
                        str(changed_by_discord_user_id)
                        if changed_by_discord_user_id
                        else None
                    ),
                ),
            )

        conn.commit()


def add_audit_event_v3(
    guild_id,
    event_type,
    target_discord_user_id=None,
    actor_discord_user_id=None,
    metadata_json="{}",
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO audit_log (
                    guild_id,
                    event_type,
                    target_discord_user_id,
                    actor_discord_user_id,
                    metadata
                )
                VALUES (%s, %s, %s, %s, %s::jsonb);
                """,
                (
                    str(guild_id),
                    str(event_type),
                    (
                        str(target_discord_user_id)
                        if target_discord_user_id
                        else None
                    ),
                    (
                        str(actor_discord_user_id)
                        if actor_discord_user_id
                        else None
                    ),
                    str(metadata_json),
                ),
            )

        conn.commit()


def has_policy_acceptance_v3(
    guild_id,
    discord_user_id,
    document_type,
    document_version,
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT accepted_at
                FROM policy_acceptances
                WHERE guild_id = %s
                AND discord_user_id = %s
                AND document_type = %s
                AND document_version = %s
                LIMIT 1;
                """,
                (
                    str(guild_id),
                    str(discord_user_id),
                    str(document_type),
                    str(document_version),
                ),
            )

            return cur.fetchone()


def has_required_policy_acceptances_v3(
    guild_id,
    discord_user_id,
):

    corp_rules = has_policy_acceptance_v3(
        guild_id,
        discord_user_id,
        "corp_rules",
        CORP_RULES_VERSION,
    )

    charter = has_policy_acceptance_v3(
        guild_id,
        discord_user_id,
        "freeborn_charter",
        FREEBORN_CHARTER_VERSION,
    )

    return {
        "corp_rules":
            corp_rules,

        "charter":
            charter,

        "complete":
            bool(
                corp_rules
                and
                charter
            ),
    }


def get_guild_main_character_v3(
    guild_id,
    discord_user_id,
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    character_id,
                    character_name,
                    corporation_id,
                    in_corporation,
                    verified_at,
                    last_checked_at,
                    left_corporation_at,
                    total_skill_points,
                    skills_updated_at
                FROM guild_eve_characters
                WHERE guild_id = %s
                AND discord_user_id = %s
                AND character_type = 'main'
                LIMIT 1;
                """,
                (
                    str(guild_id),
                    str(discord_user_id),
                ),
            )

            return cur.fetchone()


def save_main_character_v3(
    guild_id,
    discord_user_id,
    character_id,
    character_name,
    corporation_id,
    refresh_token=None,
    granted_scopes=None,
    total_skill_points=None,
):

    guild_id = str(guild_id)
    discord_user_id = str(discord_user_id)
    character_id = int(character_id)
    corporation_id = int(corporation_id)

    encrypted_refresh_token = (
        encrypt_eve_refresh_token(refresh_token)
        if refresh_token
        else None
    )

    scopes_text = (
        " ".join(sorted(set(granted_scopes or [])))
        if granted_scopes
        else None
    )

    with psycopg.connect(DATABASE_URL) as conn:

        try:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT
                        character_id,
                        character_name
                    FROM guild_eve_characters
                    WHERE guild_id = %s
                    AND discord_user_id = %s
                    AND character_type = 'main'
                    FOR UPDATE;
                    """,
                    (
                        guild_id,
                        discord_user_id,
                    ),
                )

                existing_main = cur.fetchone()

                if (
                    existing_main
                    and
                    int(existing_main[0]) != character_id
                ):

                    raise ValueError(
                        "Discord account already has main character"
                    )

                cur.execute(
                    """
                    SELECT discord_user_id
                    FROM guild_eve_characters
                    WHERE guild_id = %s
                    AND character_id = %s
                    FOR UPDATE;
                    """,
                    (
                        guild_id,
                        character_id,
                    ),
                )

                linked = cur.fetchone()

                if (
                    linked
                    and
                    str(linked[0]) != discord_user_id
                ):

                    raise ValueError(
                        "Character already linked to another Discord account"
                    )

                cur.execute(
                    """
                    INSERT INTO guild_eve_characters (
                        guild_id,
                        character_id,
                        discord_user_id,
                        character_name,
                        character_type,
                        corporation_id,
                        in_corporation,
                        verified_at,
                        updated_at,
                        last_checked_at,
                        left_corporation_at,
                        eve_refresh_token_encrypted,
                        eve_scopes,
                        total_skill_points,
                        skills_updated_at,
                        sso_authorized_at
                    )
                    VALUES (
                        %s, %s, %s, %s, 'main',
                        %s, TRUE, NOW(), NOW(), NOW(), NULL,
                        %s, %s, %s,
                        CASE WHEN %s IS NULL THEN NULL ELSE NOW() END,
                        CASE WHEN %s IS NULL THEN NULL ELSE NOW() END
                    )
                    ON CONFLICT (guild_id, character_id)
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
                        updated_at =
                            NOW(),
                        last_checked_at =
                            NOW(),
                        left_corporation_at =
                            NULL,
                        eve_refresh_token_encrypted = COALESCE(
                            EXCLUDED.eve_refresh_token_encrypted,
                            guild_eve_characters.eve_refresh_token_encrypted
                        ),
                        eve_scopes = COALESCE(
                            EXCLUDED.eve_scopes,
                            guild_eve_characters.eve_scopes
                        ),
                        total_skill_points = COALESCE(
                            EXCLUDED.total_skill_points,
                            guild_eve_characters.total_skill_points
                        ),
                        skills_updated_at = COALESCE(
                            EXCLUDED.skills_updated_at,
                            guild_eve_characters.skills_updated_at
                        ),
                        sso_authorized_at = COALESCE(
                            EXCLUDED.sso_authorized_at,
                            guild_eve_characters.sso_authorized_at
                        );
                    """,
                    (
                        guild_id,
                        character_id,
                        discord_user_id,
                        str(character_name),
                        corporation_id,
                        encrypted_refresh_token,
                        scopes_text,
                        (
                            int(total_skill_points)
                            if total_skill_points is not None
                            else None
                        ),
                        (
                            int(total_skill_points)
                            if total_skill_points is not None
                            else None
                        ),
                        encrypted_refresh_token,
                    ),
                )

            conn.commit()

        except Exception:

            conn.rollback()
            raise


def save_alt_character_v3(
    guild_id,
    discord_user_id,
    character_id,
    character_name,
    corporation_id,
):

    guild_id = str(guild_id)
    discord_user_id = str(discord_user_id)
    character_id = int(character_id)
    corporation_id = int(corporation_id)

    with psycopg.connect(DATABASE_URL) as conn:

        try:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    SELECT
                        discord_user_id,
                        character_type
                    FROM guild_eve_characters
                    WHERE guild_id = %s
                    AND character_id = %s
                    FOR UPDATE;
                    """,
                    (
                        guild_id,
                        character_id,
                    ),
                )

                linked = cur.fetchone()

                if linked:

                    if str(linked[0]) != discord_user_id:

                        raise ValueError(
                            "Character already linked to another Discord account"
                        )

                    if linked[1] == "main":

                        raise ValueError(
                            "Main character cannot be registered as alt"
                        )

                cur.execute(
                    """
                    INSERT INTO guild_eve_characters (
                        guild_id,
                        character_id,
                        discord_user_id,
                        character_name,
                        character_type,
                        corporation_id,
                        in_corporation,
                        verified_at,
                        updated_at,
                        last_checked_at,
                        left_corporation_at
                    )
                    VALUES (
                        %s, %s, %s, %s, 'alt',
                        %s, TRUE, NOW(), NOW(), NOW(), NULL
                    )
                    ON CONFLICT (guild_id, character_id)
                    DO UPDATE SET
                        discord_user_id =
                            EXCLUDED.discord_user_id,
                        character_name =
                            EXCLUDED.character_name,
                        corporation_id =
                            EXCLUDED.corporation_id,
                        in_corporation =
                            TRUE,
                        updated_at =
                            NOW(),
                        last_checked_at =
                            NOW(),
                        left_corporation_at =
                            NULL;
                    """,
                    (
                        guild_id,
                        character_id,
                        discord_user_id,
                        str(character_name),
                        corporation_id,
                    ),
                )

            conn.commit()

        except Exception:

            conn.rollback()
            raise


def has_verified_main_v3(
    guild_id,
    discord_user_id,
):
    """
    Read the guild-scoped V3 table first.

    During the Freeborn migration, fall back to the legacy
    eve_characters table for the bootstrap guild because /verification
    still writes there until its dedicated V3 conversion step.
    """

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT 1
                FROM guild_eve_characters
                WHERE guild_id = %s
                AND discord_user_id = %s
                AND character_type = 'main'
                AND in_corporation = TRUE
                LIMIT 1;
                """,
                (
                    str(guild_id),
                    str(discord_user_id),
                ),
            )

            if cur.fetchone():

                return True

    if str(guild_id) == str(DISCORD_GUILD_ID):

        return has_main_character(
            discord_user_id
        )

    return False


def save_policy_acceptance_v3(
    guild_id,
    discord_user_id,
    document_type,
    document_version,
    message_id=None,
    channel_id=None,
):

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO policy_documents (
                    guild_id,
                    document_type,
                    document_version,
                    message_id,
                    channel_id,
                    is_active,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (
                    guild_id,
                    document_type,
                    document_version
                )
                DO UPDATE SET
                    message_id = COALESCE(
                        EXCLUDED.message_id,
                        policy_documents.message_id
                    ),
                    channel_id = COALESCE(
                        EXCLUDED.channel_id,
                        policy_documents.channel_id
                    ),
                    updated_at = NOW();
                """,
                (
                    str(guild_id),
                    str(document_type),
                    str(document_version),
                    (
                        str(message_id)
                        if message_id
                        else None
                    ),
                    (
                        str(channel_id)
                        if channel_id
                        else None
                    ),
                ),
            )

            cur.execute(
                """
                INSERT INTO policy_acceptances (
                    guild_id,
                    discord_user_id,
                    document_type,
                    document_version,
                    accepted_at,
                    message_id,
                    channel_id
                )
                VALUES (%s, %s, %s, %s, NOW(), %s, %s)
                ON CONFLICT (
                    guild_id,
                    discord_user_id,
                    document_type,
                    document_version
                )
                DO NOTHING;
                """,
                (
                    str(guild_id),
                    str(discord_user_id),
                    str(document_type),
                    str(document_version),
                    (
                        str(message_id)
                        if message_id
                        else None
                    ),
                    (
                        str(channel_id)
                        if channel_id
                        else None
                    ),
                ),
            )

        conn.commit()


# ============================================================
# AUTHENTICATED ESI STORAGE
# ============================================================

def _eve_token_box():
    """Build the symmetric box used to encrypt EVE refresh tokens at rest."""

    key = hashlib.sha256(
        FLASK_SECRET_KEY.encode("utf-8")
    ).digest()

    return SecretBox(key)


def encrypt_eve_refresh_token(refresh_token):
    """Encrypt an EVE refresh token before saving it to Neon."""

    encrypted = _eve_token_box().encrypt(
        str(refresh_token).encode("utf-8")
    )

    return base64.urlsafe_b64encode(
        bytes(encrypted)
    ).decode("ascii")


def decrypt_eve_refresh_token(encrypted_refresh_token):
    """Decrypt a stored EVE refresh token for a future token refresh."""

    raw = base64.urlsafe_b64decode(
        str(encrypted_refresh_token).encode("ascii")
    )

    return _eve_token_box().decrypt(
        raw
    ).decode("utf-8")


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
                        "Le personnage principal ne peut pas "
                        "être supprimé avec /alt-supprimer"
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
            "👤 **Profil membre Freeborn**\n\n"

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
        "👤 **Profil membre Freeborn**",
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
            "### 🔗 Personnage principal",
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
            "### 🔗 Personnage principal",
            "❌ Aucun Main enregistré",
            "",
        ])

    lines.append(
        f"### 🔹 Personnages secondaires "
        f"({len(alt_rows)})"
    )

    if not alt_rows:

        lines.append(
            "Aucun personnage secondaire enregistré."
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
            "👥 **Liste des membres Freeborn**\n\n"
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
        "👥 **Liste des membres Freeborn**",
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
        f"🔗 Personnages principaux : **{stats['mains']}**",
        f"🔹 Personnages secondaires : **{stats['alts']}**",
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

def interaction_has_any_role(
    data,
    allowed_role_ids,
):

    member_roles = interaction_member_role_ids(
        data
    )

    return bool(
        member_roles
        &
        set(
            str(role_id)
            for role_id
            in allowed_role_ids
            if role_id
        )
    )


def interaction_is_recruitment_manager(
    data
):

    return interaction_has_any_role(
        data,
        RECRUITMENT_MANAGER_ROLE_IDS,
    )



def interaction_is_recruitment_reviewer(
    data
):

    return interaction_has_any_role(
        data,
        RECRUITMENT_REVIEWER_ROLE_IDS,
    )


def interaction_is_audit_viewer(
    data
):

    return interaction_has_any_role(
        data,
        AUDIT_VIEWER_ROLE_IDS,
    )


def recruitment_access_denied():

    return jsonify({
        "type":
            4,

        "data": {
            "content":
                "⛔ **Accès refusé**\n\n"
                "Cette action est réservée aux rôles "
                "**CEO**, **Haut Conseil**, **Direction** "
                "et **Ressources Humaines**.",

            "flags":
                64,
        },
    })


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


def guild_dedicated_channel_id(
    guild_config,
    channel_type,
):

    if not guild_config:

        return None

    indexes = {
        "orientation":
            7,

        "corp_rules":
            8,

        "charter":
            9,
    }

    index = indexes.get(
        str(channel_type)
    )

    if index is None:

        return None

    try:

        channel_id = guild_config[index]

    except IndexError:

        return None

    return (
        str(channel_id)
        if channel_id
        else None
    )


def dedicated_channel_error(
    expected_channel_id,
    label,
):

    channel_text = (
        f"<#{expected_channel_id}>"
        if expected_channel_id
        else
        f"le salon **{label}** configuré"
    )

    return jsonify({
        "type":
            4,

        "data": {
            "content":
                "📍 **Mauvais salon**\n\n"
                f"Cette action doit être utilisée dans "
                f"{channel_text}.",

            "flags":
                64,
        },
    })


def interaction_response_flags(data):

    command_name = str(
        ((data.get("data") or {}).get("name") or "")
    ).lower()

    # /freeborn contains the personal EVE SSO link and must always
    # remain private to the member who launched the command, even
    # when it is used in the public recruitment channel.
    if command_name == "freeborn":

        return 64

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
                "aux rôles **CEO**, "
                "**Haut Conseil** et **Direction**.",

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
# MEMBER SELF-SERVICE CONFIRMATION TOKENS
# ============================================================

def create_alt_remove_token(character_id, requester_user_id):

    payload = f"{character_id}:{requester_user_id}"
    return alt_remove_signer.sign(payload.encode()).decode()


def read_alt_remove_token(token):

    payload = alt_remove_signer.unsign(
        token,
        max_age=300,
    ).decode()

    character_id, requester_user_id = payload.split(":", 1)
    return character_id, requester_user_id


def create_main_change_token(character_id, requester_user_id):

    payload = f"{character_id}:{requester_user_id}"
    return main_change_signer.sign(payload.encode()).decode()


def read_main_change_token(token):

    payload = main_change_signer.unsign(
        token,
        max_age=300,
    ).decode()

    character_id, requester_user_id = payload.split(":", 1)
    return character_id, requester_user_id



def create_sync_apply_token(requester_user_id):

    payload = str(requester_user_id)
    return sync_apply_signer.sign(payload.encode()).decode()


def read_sync_apply_token(token):

    return sync_apply_signer.unsign(
        token,
        max_age=300,
    ).decode()


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

    granted_scopes = payload.get(
        "scp",
        [],
    )

    if isinstance(granted_scopes, str):
        granted_scopes = [
            granted_scopes
        ]

    granted_scopes = {
        str(scope)
        for scope in granted_scopes
    }

    return (
        character_id,
        character_name,
        granted_scopes,
    )


def get_eve_character_skills(
    character_id,
    access_token,
):
    """Read the authenticated character skill summary from ESI."""

    response = requests.get(
        (
            f"{ESI_BASE_URL}/characters/"
            f"{int(character_id)}/skills/"
        ),
        headers={
            "Authorization":
                f"Bearer {access_token}",
        },
        timeout=15,
    )

    response.raise_for_status()

    data = response.json()

    if "total_sp" not in data:
        raise ValueError(
            "ESI skills response does not contain total_sp"
        )

    return {
        "total_sp":
            int(data["total_sp"]),

        "unallocated_sp":
            int(data.get("unallocated_sp", 0) or 0),

        "trained_skills":
            len(data.get("skills", [])),
    }


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


def get_discord_member(
    guild_id,
    user_id,
):

    response = requests.get(
        f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}",
        headers={
            "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        },
        timeout=15,
    )

    if response.status_code != 200:
        return None

    return response.json()


def send_discord_channel_message(
    channel_id,
    content,
):

    if not channel_id:
        return None

    return requests.post(
        f"{DISCORD_API}/channels/{channel_id}/messages",
        headers={
            "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
            "Content-Type": "application/json",
        },
        json={"content": content},
        timeout=15,
    )


def log_v3_event_to_discord(
    guild_config,
    content,
):
    """Best-effort visible audit log. Database audit remains authoritative."""

    try:
        logs_channel_id = (
            str(guild_config[5])
            if guild_config and guild_config[5]
            else None
        )

        if not logs_channel_id:
            return

        response = send_discord_channel_message(
            logs_channel_id,
            content,
        )

        if response is not None and response.status_code not in (200, 201):
            print(
                "Discord V3 log failed:",
                response.status_code,
                response.text[:300],
            )

    except Exception as error:
        print("Discord V3 log error:", repr(error))


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
            "⚙️ **Application de la synchronisation Freeborn**"
        )

        footer = (
            "\n\n🛡️ Les révocations "
            "ne sont effectuées "
            "qu'après confirmation "
            "ESI valide."
        )

    else:

        title = (
            "🔎 **Contrôle de synchronisation Freeborn**"
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
        "📡 **État de la synchronisation Freeborn**",
        "",
        f"État général : {overall_status}",
        "",
        "### 🗄️ Base Freeborn",
        f"👥 Comptes suivis : **{stats['members']}**",
        f"🎮 Personnages : **{stats['characters']}**",
        f"🔗 Personnages principaux : **{stats['mains']}**",
        f"🔹 Personnages secondaires : **{stats['alts']}**",
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
            "main-changer",
            "alt-supprimer",
            "verification",
            "candidat-accepter",
            "membre-supprimer",
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

    # /membre-supprimer lists only human Discord accounts that actually
    # own at least one EVE profile in Freeborn Verify.
    if command_name == "membre-supprimer":

        guild_id = str(data.get("guild_id", ""))
        search_text = ""

        for option in data["data"].get("options", []):
            if option.get("name") == "membre":
                search_text = str(option.get("value", "")).lower()
                break

        try:
            with psycopg.connect(DATABASE_URL) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT DISTINCT discord_user_id
                        FROM eve_characters
                        ORDER BY discord_user_id;
                        """
                    )
                    profile_rows = cur.fetchall()
        except Exception as error:
            print("Member remove autocomplete database error:", repr(error))
            profile_rows = []

        choices = []

        for (target_user_id,) in profile_rows:
            target_user_id = str(target_user_id)
            member_payload = get_discord_member(guild_id, target_user_id)

            if not member_payload:
                continue

            user_payload = member_payload.get("user", {})

            if user_payload.get("bot", False):
                continue

            display_name = (
                member_payload.get("nick")
                or user_payload.get("global_name")
                or user_payload.get("username")
                or target_user_id
            )

            if search_text and search_text not in display_name.lower():
                continue

            choices.append({
                "name": display_name,
                "value": target_user_id,
            })

            if len(choices) >= 25:
                break

        return jsonify({
            "type": 8,
            "data": {"choices": choices},
        })

    # Staff recruitment commands use a controlled autocomplete list
    # sourced from the V3 member_statuses table. This avoids Discord's
    # generic USER picker proposing bots while hiding valid candidates.
    if (
        command_name
        in {
            "verification",
            "candidat-accepter",
        }
    ):

        guild_id = str(
            data.get(
                "guild_id",
                "",
            )
        )

        search_text = ""

        for option in (
            data[
                "data"
            ].get(
                "options",
                [],
            )
        ):

            if (
                option.get("name")
                ==
                "membre"
            ):

                search_text = str(
                    option.get(
                        "value",
                        "",
                    )
                ).lower()

                break

        try:

            with psycopg.connect(
                DATABASE_URL
            ) as conn:

                with conn.cursor() as cur:

                    cur.execute(
                        """
                        SELECT
                            discord_user_id,
                            status
                        FROM member_statuses
                        WHERE guild_id = %s
                        AND status = %s
                        ORDER BY updated_at DESC;
                        """,
                        (
                            guild_id,
                            "candidate",
                        ),
                    )

                    candidate_rows = (
                        cur.fetchall()
                    )

        except Exception as error:

            print(
                "Recruitment autocomplete "
                "database error:",
                repr(error),
            )

            candidate_rows = []

        choices = []

        for (
            candidate_user_id,
            candidate_status,
        ) in candidate_rows:

            candidate_user_id = str(
                candidate_user_id
            )

            try:

                member_response = (
                    requests.get(
                        f"{DISCORD_API}/guilds/"
                        f"{guild_id}/members/"
                        f"{candidate_user_id}",
                        headers={
                            "Authorization":
                                f"Bot {DISCORD_BOT_TOKEN}",
                        },
                        timeout=10,
                    )
                )

                if (
                    member_response.status_code
                    !=
                    200
                ):

                    continue

                member_payload = (
                    member_response.json()
                )

                user_payload = (
                    member_payload.get(
                        "user",
                        {},
                    )
                )

                if user_payload.get(
                    "bot",
                    False,
                ):

                    continue

                display_name = (
                    member_payload.get(
                        "nick"
                    )
                    or
                    user_payload.get(
                        "global_name"
                    )
                    or
                    user_payload.get(
                        "username"
                    )
                    or
                    candidate_user_id
                )

            except Exception as error:

                print(
                    "Recruitment autocomplete "
                    "Discord error:",
                    repr(error),
                )

                continue

            if (
                search_text
                and
                search_text
                not in
                display_name.lower()
            ):

                continue

            choices.append({
                "name":
                    display_name,

                "value":
                    candidate_user_id,
            })

            if len(choices) >= 25:

                break

        return jsonify({
            "type":
                8,

            "data": {
                "choices":
                    choices,
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
            "main-changer"
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

    # ========================================================
    # V3 ORIENTATION
    # ========================================================

    if custom_id in {
        "v3_orientation_guest",
        "v3_orientation_candidate",
    }:

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

            guild_id = str(
                data[
                    "guild_id"
                ]
            )

        except Exception:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible d'identifier "
                        "ton compte ou le serveur Discord.",

                    "flags":
                        64,
                },
            })

        guild_config = get_guild_config(
            guild_id
        )

        if (
            not guild_config
            or
            not guild_config[6]
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ Ce serveur n'est pas "
                        "configuré pour Freeborn Verify V3.",

                    "flags":
                        64,
                },
            })

        orientation_channel_id = (
            guild_dedicated_channel_id(
                guild_config,
                "orientation",
            )
        )

        if (
            not orientation_channel_id
            or
            str(data.get("channel_id", ""))
            !=
            orientation_channel_id
        ):

            return dedicated_channel_error(
                orientation_channel_id,
                "orientation",
            )

        member_roles = (
            interaction_member_role_ids(
                data
            )
        )

        protected_role_ids = {
            role_id
            for role_id
            in {
                resolve_guild_role_id(
                    guild_id,
                    "candidate_accepted",
                ),
                resolve_guild_role_id(
                    guild_id,
                    "member",
                ),
            }
            if role_id
        }

        if (
            member_roles
            &
            protected_role_ids
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "ℹ️ Ton statut est déjà "
                        "plus avancé que l'Orientation. "
                        "Aucune modification effectuée.",

                    "flags":
                        64,
                },
            })

        new_status = (
            "guest"

            if custom_id
            ==
            "v3_orientation_guest"

            else

            "candidate"
        )

        try:

            role_result = (
                apply_recruitment_status_role(
                    guild_id,
                    actor_user_id,
                    new_status,
                )
            )

            if (
                role_result[
                    "add_status_code"
                ]
                not in
                (200, 204)
            ):

                raise RuntimeError(
                    "Discord role assignment failed: "
                    f"{role_result['add_status_code']}"
                )

            set_member_status_v3(
                guild_id,
                actor_user_id,
                new_status,
                actor_user_id,
            )

            add_audit_event_v3(
                guild_id,
                (
                    "orientation_guest"
                    if new_status == "guest"
                    else
                    "orientation_candidate"
                ),
                target_discord_user_id=
                    actor_user_id,
                actor_discord_user_id=
                    actor_user_id,
            )

        except Exception as error:

            print(
                "V3 orientation failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ L'Orientation n'a pas pu "
                        "être enregistrée. "
                        "Un administrateur peut vérifier "
                        "la configuration du bot.",

                    "flags":
                        64,
                },
            })

        if new_status == "guest":

            confirmation = (
                "✅ **Orientation enregistrée : Invité**\n\n"
                "Le rôle **Invité** t'a été attribué."
            )

        else:

            confirmation = (
                "✅ **Orientation enregistrée : Candidat**\n\n"
                "Le rôle **Candidat** t'a été attribué. "
                "Tu peux maintenant poursuivre le recrutement."
            )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    confirmation,

                "flags":
                    64,
            },
        })

    # ========================================================
    # V3 POLICY ACCEPTANCE
    # ========================================================

    if custom_id in {
        "v3_accept_corp_rules",
        "v3_accept_charter",
    }:

        try:

            actor_user_id = str(
                data["member"]["user"]["id"]
            )

            guild_id = str(
                data["guild_id"]
            )

            channel_id = str(
                data.get("channel_id", "")
            )

            message_id = str(
                data.get("message", {}).get(
                    "id",
                    "",
                )
            )

        except Exception:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Impossible d'identifier "
                        "ton compte ou ce message.",

                    "flags":
                        64,
                },
            })

        guild_config = get_guild_config(
            guild_id
        )

        if (
            not guild_config
            or
            not guild_config[6]
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ Ce serveur n'est pas "
                        "configuré pour Freeborn Verify V3.",

                    "flags":
                        64,
                },
            })

        current_status = get_member_status_v3(
            guild_id,
            actor_user_id,
        )

        allowed_statuses = {
            "candidate",
            "candidate_accepted",
            "member",
        }

        if (
            not current_status
            or
            current_status[0]
            not in allowed_statuses
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "ℹ️ Cette acceptation est réservée "
                        "aux **Candidats** et aux membres "
                        "du parcours Freeborn.",

                    "flags":
                        64,
                },
            })

        if custom_id == "v3_accept_corp_rules":

            document_type = "corp_rules"
            document_version = CORP_RULES_VERSION
            document_label = "Règlement Corp"
            audit_event = "policy_accept_corp_rules"
            dedicated_channel_type = "corp_rules"
            dedicated_channel_label = "règlement-corp"

        else:

            document_type = "freeborn_charter"
            document_version = FREEBORN_CHARTER_VERSION
            document_label = "Charte Freeborn Legacy"
            audit_event = "policy_accept_charter"
            dedicated_channel_type = "charter"
            dedicated_channel_label = "charte-freeborn"

        expected_policy_channel_id = (
            guild_dedicated_channel_id(
                guild_config,
                dedicated_channel_type,
            )
        )

        if (
            not expected_policy_channel_id
            or
            channel_id
            !=
            expected_policy_channel_id
        ):

            return dedicated_channel_error(
                expected_policy_channel_id,
                dedicated_channel_label,
            )

        existing_acceptance = (
            has_policy_acceptance_v3(
                guild_id,
                actor_user_id,
                document_type,
                document_version,
            )
        )

        if existing_acceptance:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        f"✅ Tu as déjà accepté "
                        f"**{document_label}** "
                        f"(version `{document_version}`).\n"
                        f"Acceptation enregistrée le "
                        f"**{format_datetime(existing_acceptance[0])}**.",

                    "flags":
                        64,
                },
            })

        try:

            save_policy_acceptance_v3(
                guild_id,
                actor_user_id,
                document_type,
                document_version,
                message_id=message_id,
                channel_id=channel_id,
            )

            add_audit_event_v3(
                guild_id,
                audit_event,
                target_discord_user_id=
                    actor_user_id,
                actor_discord_user_id=
                    actor_user_id,
            )

            recorded_acceptance = (
                has_policy_acceptance_v3(
                    guild_id,
                    actor_user_id,
                    document_type,
                    document_version,
                )
            )

            main_row = get_guild_main_character_v3(
                guild_id,
                actor_user_id,
            )

            accepted_at_text = (
                format_datetime(recorded_acceptance[0])
                if recorded_acceptance
                else "Horodatage indisponible"
            )

            eve_identity_text = (
                (
                    f"**{main_row[1]}** "
                    f"(`{main_row[0]}`)"
                )
                if main_row
                else
                "Non encore liée — validation EVE à venir"
            )

            log_title = (
                "📕 **RÈGLEMENT CORPORATION ACCEPTÉ**"
                if document_type == "corp_rules"
                else
                "📜 **CHARTE FREEBORN LEGACY ACCEPTÉE**"
            )

            policy_progress = (
                has_required_policy_acceptances_v3(
                    guild_id,
                    actor_user_id,
                )
            )

            documentation_complete = bool(
                policy_progress["complete"]
            )

            documentation_status_text = (
                "✅ **COMPLET — Règlement + Charte acceptés**"
                if documentation_complete
                else
                "⏳ **EN COURS — un document reste à accepter**"
            )

            log_v3_event_to_discord(
                guild_config,
                f"{log_title}\n"
                f"Discord : <@{actor_user_id}> (`{actor_user_id}`)\n"
                f"Main EVE : {eve_identity_text}\n"
                f"Document : **{document_label}**\n"
                f"Version : `{document_version}`\n"
                f"Accepté le : **{accepted_at_text}**\n"
                f"Canal : <#{channel_id}>\n"
                f"Parcours documentaire : {documentation_status_text}",
            )

            if documentation_complete:
                add_audit_event_v3(
                    guild_id,
                    "policy_documents_complete",
                    target_discord_user_id=
                        actor_user_id,
                    actor_discord_user_id=
                        actor_user_id,
                )

        except Exception as error:

            print(
                "V3 policy acceptance failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ L'acceptation n'a pas pu "
                        "être enregistrée. "
                        "Aucune validation n'a été confirmée.",

                    "flags":
                        64,
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    f"✅ **{document_label} accepté**\n\n"
                    f"Version : `{document_version}`\n"
                    "Ta preuve d'acceptation horodatée "
                    "a été enregistrée par Freeborn Verify.\n\n"
                    + (
                        (
                            "✅ **Parcours documentaire terminé.**\n"
                            "Le Règlement Corporation et la Charte "
                            "Freeborn Legacy sont maintenant validés."
                        )
                        if documentation_complete
                        else
                        (
                            "➡️ Tu peux maintenant poursuivre avec "
                            "la **Charte Freeborn Legacy**."
                            if document_type == "corp_rules"
                            else
                            "➡️ Le **Règlement Corporation** doit encore "
                            "être accepté pour terminer cette étape."
                        )
                    ),

                "flags":
                    64,
            },
        })

    # ========================================================
    # ALT REMOVE CONFIRMATION
    # ========================================================

    if custom_id.startswith("ar_yes:") or custom_id.startswith("ar_no:"):

        try:
            actor_user_id = str(data["member"]["user"]["id"])
            token = custom_id.split(":", 1)[1]
            character_id, requester_user_id = read_alt_remove_token(token)
        except SignatureExpired:
            return jsonify({"type": 7, "data": {"content": "⌛ **Confirmation expirée**\n\nAucune suppression effectuée.", "components": []}})
        except (BadSignature, ValueError, KeyError):
            return jsonify({"type": 7, "data": {"content": "⛔ **Confirmation invalide**\n\nAucune modification effectuée.", "components": []}})

        if actor_user_id != requester_user_id:
            return jsonify({"type": 4, "data": {"content": "⛔ Cette confirmation ne t'appartient pas.", "flags": 64}})

        if custom_id.startswith("ar_no:"):
            return jsonify({"type": 7, "data": {"content": "🛡️ **Suppression annulée**\n\nTon profil Freeborn reste inchangé.", "components": []}})

        try:
            result = remove_alt_character(actor_user_id, character_id)
        except ValueError as error:
            return jsonify({"type": 7, "data": {"content": f"❌ **Suppression refusée**\n\n{str(error)}", "components": []}})
        except Exception as error:
            print("Alt remove confirmation failed:", repr(error))
            return jsonify({"type": 7, "data": {"content": "⚠️ **Erreur base de données**\n\nL'Alt n'a pas été supprimé.", "components": []}})

        if result["remaining_alts"] == 0:
            role_response = remove_discord_role(
                str(data.get("guild_id", DISCORD_GUILD_ID)),
                actor_user_id,
                DISCORD_ALT_CHARACTER_ROLE_ID,
            )
            role_text = (
                "🔹 Aucun Alt restant : rôle **Alt Character** retiré."
                if role_response.status_code in (200, 204)
                else
                "⚠️ Aucun Alt restant, mais le rôle **Alt Character** n'a pas pu être retiré."
            )
        else:
            role_text = f"🔹 Alts restants : **{result['remaining_alts']}** — rôle **Alt Character** conservé."

        current_main = get_main_character(actor_user_id)
        current_main_name = current_main[1] if current_main else "Inconnu"

        return jsonify({"type": 7, "data": {
            "content":
                "🗑️ **Suppression du personnage secondaire**\n\n"
                f"Alt supprimé : **{result['character_name']}**\n\n"
                "✅ Le personnage a été retiré de ton profil Freeborn.\n"
                f"✅ Ton Main **{current_main_name}** reste inchangé.\n"
                f"{role_text}",
            "components": [],
        }})

    # ========================================================
    # MAIN CHANGE CONFIRMATION
    # ========================================================

    if custom_id.startswith("mc_yes:") or custom_id.startswith("mc_no:"):

        try:
            actor_user_id = str(data["member"]["user"]["id"])
            guild_id = str(data["guild_id"])
            token = custom_id.split(":", 1)[1]
            character_id, requester_user_id = read_main_change_token(token)
        except SignatureExpired:
            return jsonify({"type": 7, "data": {"content": "⌛ **Confirmation expirée**\n\nAucun changement effectué.", "components": []}})
        except (BadSignature, ValueError, KeyError):
            return jsonify({"type": 7, "data": {"content": "⛔ **Confirmation invalide**\n\nAucune modification effectuée.", "components": []}})

        if actor_user_id != requester_user_id:
            return jsonify({"type": 4, "data": {"content": "⛔ Cette confirmation ne t'appartient pas.", "flags": 64}})

        if custom_id.startswith("mc_no:"):
            return jsonify({"type": 7, "data": {"content": "🛡️ **Changement annulé**\n\nTon Main reste inchangé.", "components": []}})

        alts = get_member_alts(actor_user_id)
        selected_alt = next((alt for alt in alts if str(alt[0]) == str(character_id)), None)

        if not selected_alt:
            return jsonify({"type": 7, "data": {"content": "❌ Ce personnage n'est plus un Alt Character enregistré sur ton compte.", "components": []}})

        new_main_id, new_main_name, _, _ = selected_alt
        eve_data = get_current_eve_character(new_main_id)

        if eve_data is None:
            return jsonify({"type": 7, "data": {"content": "⚠️ **Changement annulé**\n\nEVE ESI n'a pas pu confirmer l'état actuel du personnage.", "components": []}})

        current_corporation_id = int(eve_data["corporation_id"])

        if current_corporation_id != FREEBORN_CORPORATION_ID:
            return jsonify({"type": 7, "data": {"content": f"❌ **Changement refusé**\n\n**{new_main_name}** n'appartient actuellement pas à **Freeborn Legacy**.", "components": []}})

        try:
            result = change_main_character(
                actor_user_id,
                new_main_id,
                current_corporation_id,
            )
        except Exception as error:
            print("Main change confirmation failed:", repr(error))
            return jsonify({"type": 7, "data": {"content": "⚠️ **Changement impossible**\n\nAucune donnée n'a été modifiée.", "components": []}})

        for role_id in (
            DISCORD_MEMBER_ROLE_ID,
            DISCORD_EVE_VERIFIED_ROLE_ID,
            DISCORD_MAIN_CHARACTER_ROLE_ID,
            DISCORD_ALT_CHARACTER_ROLE_ID,
        ):
            add_discord_role(guild_id, actor_user_id, role_id)

        nickname_response = sync_discord_nickname(
            guild_id,
            actor_user_id,
            result["new_main_name"],
        )

        nickname_text = (
            f"✅ Pseudo Discord synchronisé sur **{result['new_main_name']}**."
            if nickname_response.status_code in (200, 204)
            else
            "⚠️ Le changement de Main est validé, mais le pseudo Discord n'a pas pu être modifié (propriétaire du serveur ou hiérarchie Discord)."
        )

        return jsonify({"type": 7, "data": {
            "content":
                "🔄 **Changement de personnage principal**\n\n"
                f"Ancien Main : **{result['old_main_name']}** → Personnage secondaire\n"
                f"Nouveau personnage principal : **{result['new_main_name']}** → Personnage principal\n\n"
                "✅ Changement enregistré dans Freeborn Verify.\n"
                f"{nickname_text}\n\n"
                "Aucun personnage EVE n'a été supprimé.",
            "components": [],
        }})

    # ========================================================
    # SYNC APPLY CONFIRMATION
    # ========================================================

    if custom_id.startswith("sa_yes:") or custom_id.startswith("sa_no:"):

        try:

            actor_user_id = str(
                data["member"]["user"]["id"]
            )

            guild_id = str(
                data["guild_id"]
            )

            token = custom_id.split(
                ":",
                1,
            )[1]

            requester_user_id = (
                read_sync_apply_token(
                    token
                )
            )

        except SignatureExpired:

            return jsonify({
                "type":
                    7,

                "data": {
                    "content":
                        "⌛ **Confirmation expirée**\n\n"
                        "Aucune synchronisation n'a été appliquée.\n\n"
                        "Relance **/synchro-appliquer** si nécessaire.",

                    "components":
                        [],
                },
            })

        except (
            BadSignature,
            ValueError,
            KeyError,
        ):

            return jsonify({
                "type":
                    7,

                "data": {
                    "content":
                        "⛔ **Confirmation invalide**\n\n"
                        "Aucune synchronisation n'a été appliquée.",

                    "components":
                        [],
                },
            })

        if actor_user_id != requester_user_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ Cette confirmation ne t'appartient pas.",

                    "flags":
                        64,
                },
            })

        if not interaction_is_staff(
            data
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ Tu n'as plus les permissions nécessaires "
                        "pour appliquer cette synchronisation.",

                    "flags":
                        64,
                },
            })

        guild_config = get_guild_config(
            guild_id
        )

        expected_channel_id = (
            str(guild_config[4])
            if guild_config
            and guild_config[4]
            else None
        )

        if (
            not expected_channel_id
            or
            str(data.get("channel_id", ""))
            != expected_channel_id
        ):

            return dedicated_channel_error(
                expected_channel_id,
                "commandes-bot",
            )

        if custom_id.startswith("sa_no:"):

            return jsonify({
                "type":
                    7,

                "data": {
                    "content":
                        "🛡️ **Synchronisation annulée**\n\n"
                        "Aucune donnée Neon et aucun rôle Discord "
                        "n'ont été modifiés.",

                    "components":
                        [],
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
                "Sync apply confirmation failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    7,

                "data": {
                    "content":
                        "⚠️ **Synchronisation impossible**\n\n"
                        "La vérification ESI ou l'application des "
                        "changements a rencontré une erreur.",

                    "components":
                        [],
                },
            })

        return jsonify({
            "type":
                7,

            "data": {
                "content":
                    build_sync_message(
                        sync_results,
                        actions=actions,
                        applied=True,
                    ),

                "components":
                    [],
            },
        })

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
        or custom_id.startswith("ar_yes:")
        or custom_id.startswith("ar_no:")
        or custom_id.startswith("mc_yes:")
        or custom_id.startswith("mc_no:")
        or custom_id.startswith("sa_yes:")
        or custom_id.startswith("sa_no:")
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
                    "Relance **/membre-supprimer** "
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
                    "**/membre-supprimer**.",

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
        "🗑️ **Suppression du profil membre Freeborn**",
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

    return freeborn_web_page(
        "Service opérationnel",
        "Freeborn Verify V3 assure la vérification EVE Online et le parcours d'intégration de Freeborn Legacy.",
        status="success",
    )


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


@app.route("/base-statut")
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

    # Load the V3 guild configuration once for all command handlers
    # that need dedicated channels / per-guild settings.
    guild_config = get_guild_config(
        guild_id
    )

    if (
        not guild_config
        or
        not guild_config[6]
    ):

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "⛔ Ce serveur n'est pas "
                    "configuré pour Freeborn Verify V3.",

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # STAFF-ONLY COMMANDS
    # ========================================================

    STAFF_ONLY_COMMANDS = {
        "bienvenue-panneau",
        "orientation-panneau",
        "reglement-discord-panneau",
        "reglement-corp-panneau",
        "charte-panneau",
        "membre-supprimer",
        "synchro-appliquer",
    }

    AUDIT_VIEWER_COMMANDS = {
        "membre-liste",
        "base-statut",
        "synchro-statut",
        "synchro-verifier",
    }

    TECHNICAL_CHANNEL_COMMANDS = {
        "membre-supprimer",
        "membre-liste",
        "base-statut",
        "synchro-statut",
        "synchro-verifier",
        "synchro-appliquer",
    }

    RECRUITMENT_MANAGER_COMMANDS = {
        "candidat-accepter",
        "membre-promouvoir",
    }

    RECRUITMENT_REVIEWER_COMMANDS = {
        "verification",
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
        in AUDIT_VIEWER_COMMANDS

        and

        not interaction_is_audit_viewer(
            data
        )
    ):

        return jsonify({
            "type": 4,
            "data": {
                "content":
                    "⛔ **Accès refusé**\n\n"
                    "Cette commande de consultation est réservée aux rôles "
                    "**CEO**, **Haut Conseil**, **Direction** et "
                    "**Ressources Humaines**.",
                "flags": 64,
            },
        })


    if (
        command_name
        in RECRUITMENT_MANAGER_COMMANDS

        and

        not interaction_is_recruitment_manager(
            data
        )
    ):

        return recruitment_access_denied()


    if (
        command_name
        in RECRUITMENT_REVIEWER_COMMANDS

        and

        not interaction_is_recruitment_reviewer(
            data
        )
    ):

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "⛔ **Accès refusé**\n\n"
                    "La commande **/verification** est réservée aux rôles "
                    "**CEO**, **Haut Conseil**, **Direction** et "
                    "**Ressources Humaines**.",

                "flags":
                    64,
            },
        })

    if (
        command_name
        in TECHNICAL_CHANNEL_COMMANDS
    ):

        staff_channel_id = (
            str(guild_config[4])
            if guild_config and guild_config[4]
            else None
        )

        if (
            not staff_channel_id
            or
            str(data.get("channel_id", ""))
            !=
            staff_channel_id
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "📍 **Commande staff réservée**\n\n"
                        "Utilise cette commande dans "
                        + (
                            f"<#{staff_channel_id}>."
                            if staff_channel_id
                            else
                            "le salon de gestion du bot configuré pour ce serveur."
                        ),

                    **interaction_response_flags_payload(data),
                },
            })

    # ========================================================
    # /reglement-discord-panneau
    # V3 STAFF SETUP — informational panel only
    # The official acceptance remains managed natively by Discord.
    # ========================================================

    if (
        command_name
        ==
        "reglement-discord-panneau"
    ):

        rules_image_url = (
            f"{PUBLIC_BASE_URL}"
            "/assets/reglement-discord.png"
        )

        return jsonify({
            "type":
                4,

            "data": {
                "embeds": [
                    {
                        "image": {
                            "url":
                                rules_image_url
                        },

                        "color":
                            0x2F81F7,
                    },

                    {
                        "title":
                            "🛡️ RÈGLEMENT DISCORD — FREEBORN LEGACY",

                        "description":
                            "📜 L'acceptation du règlement est gérée "
                            "directement par **Discord** lors de l'arrivée "
                            "sur le serveur.\n\n"
                            "Le visuel ci-dessus en présente les principes "
                            "essentiels. **Son respect reste obligatoire "
                            "pendant toute ta présence sur Freeborn Legacy.**",

                        "color":
                            0x2F81F7,

                        "fields": [
                            {
                                "name":
                                    "📌 Informations",

                                "value":
                                    "• Acceptation : **système natif Discord**\n"
                                    "• Version : **11 août 2026**\n"
                                    "• Application : membres, candidats, "
                                    "invités et partenaires",

                                "inline":
                                    False,
                            },
                        ],

                        "footer": {
                            "text":
                                "Freeborn Legacy • Règlement Discord"
                        },
                    },
                ],
            },
        })


    # ========================================================
    # /bienvenue-panneau
    # V3 STAFF SETUP — visual onboarding panel
    # ========================================================

    if (
        command_name
        ==
        "bienvenue-panneau"
    ):

        welcome_image_url = (
            f"{PUBLIC_BASE_URL}"
            "/assets/bienvenue-v2.png"
        )

        return jsonify({
            "type":
                4,

            "data": {
                "embeds": [
                    {
                        "image": {
                            "url":
                                welcome_image_url
                        },

                        "color":
                            0x2F81F7,
                    },

                    {
                        "title":
                            "🧭 PROCHAINE ÉTAPE : ORIENTATION",

                        "description":
                            "Rends-toi dans le salon **Orientation** "
                            "pour choisir ton parcours.\n\n"
                            "🔵 **Invité** → accès aux espaces diplomatiques "
                            "et communautaires prévus pour les visiteurs.\n"
                            "🟢 **Candidat** → accès au parcours de "
                            "recrutement Freeborn Legacy.\n\n"
                            "📌 **Suis les étapes dans l'ordre : "
                            "Freeborn Verify s'occupe automatiquement "
                            "de la suite.**",

                        "color":
                            0x2F81F7,

                        "footer": {
                            "text":
                                "Freeborn Legacy • Bienvenue • "
                                "Orientation → Invité ou Candidat"
                        },
                    },
                ],
            },
        })


    # ========================================================
    # /orientation-panneau
    # V3 STAFF SETUP
    # ========================================================

    if (
        command_name
        ==
        "orientation-panneau"
    ):

        orientation_channel_id = (
            guild_dedicated_channel_id(
                guild_config,
                "orientation",
            )
        )

        if (
            not orientation_channel_id
            or
            str(data.get("channel_id", ""))
            !=
            orientation_channel_id
        ):

            return dedicated_channel_error(
                orientation_channel_id,
                "orientation",
            )

        guest_role_id = (
            resolve_guild_role_id(
                guild_id,
                "guest",
            )
        )

        candidate_role_id = (
            resolve_guild_role_id(
                guild_id,
                "candidate",
            )
        )

        if (
            not guest_role_id
            or
            not candidate_role_id
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ **Orientation non configurée**\n\n"
                        "Les rôles **Invité** et **Candidat** "
                        "doivent être configurés avant de "
                        "publier le panneau.",

                    "flags":
                        64,
                },
            })

        orientation_image_url = (
            f"{PUBLIC_BASE_URL}"
            "/assets/orientation-v2.png"
        )

        return jsonify({
            "type":
                4,

            "data": {
                "embeds": [
                    {
                        "image": {
                            "url":
                                orientation_image_url
                        },

                        "color":
                            0x2F81F7,
                    },

                    {
                        "title":
                            "🧭 CHOISIS TON ORIENTATION",

                        "description":
                            "Sélectionne le parcours correspondant à "
                            "ta présence sur Freeborn Legacy.\n\n"
                            "🔵 **Invité** → accès aux espaces "
                            "diplomatiques et communautaires prévus "
                            "pour les visiteurs.\n"
                            "🟢 **Candidat** → commencer le parcours "
                            "de recrutement Freeborn Legacy.\n\n"
                            "📌 **Ton choix est enregistré par "
                            "Freeborn Verify et le serveur adapte "
                            "automatiquement tes accès.**",

                        "color":
                            0x2F81F7,

                        "footer": {
                            "text":
                                "Freeborn Legacy • Orientation • "
                                "Invité ou Candidat"
                        },
                    },
                ],

                "components": [
                    {
                        "type":
                            1,

                        "components": [
                            {
                                "type":
                                    2,

                                "style":
                                    1,

                                "label":
                                    "Invité",

                                "custom_id":
                                    "v3_orientation_guest",
                            },

                            {
                                "type":
                                    2,

                                "style":
                                    3,

                                "label":
                                    "Candidat",

                                "custom_id":
                                    "v3_orientation_candidate",
                            },
                        ],
                    }
                ],
            },
        })

    # ========================================================
    # /reglement-corp-panneau
    # V3 STAFF SETUP — official 3-part visual publication
    # ========================================================

    if (
        command_name
        ==
        "reglement-corp-panneau"
    ):

        corp_rules_channel_id = (
            guild_dedicated_channel_id(
                guild_config,
                "corp_rules",
            )
        )

        if (
            not corp_rules_channel_id
            or
            str(data.get("channel_id", ""))
            !=
            corp_rules_channel_id
        ):

            return dedicated_channel_error(
                corp_rules_channel_id,
                "règlement-corp",
            )

        corp_rules_image_urls = [
            (
                f"{PUBLIC_BASE_URL}"
                "/assets/reglement-corp-part1.png"
            ),
            (
                f"{PUBLIC_BASE_URL}"
                "/assets/reglement-corp-part2.png"
            ),
            (
                f"{PUBLIC_BASE_URL}"
                "/assets/reglement-corp-part3.png"
            ),
        ]

        return jsonify({
            "type":
                4,

            "data": {
                "embeds": [
                    {
                        "image": {
                            "url":
                                corp_rules_image_urls[0]
                        },
                        "color":
                            0x0A84FF,
                    },
                    {
                        "image": {
                            "url":
                                corp_rules_image_urls[1]
                        },
                        "color":
                            0x0A84FF,
                    },
                    {
                        "image": {
                            "url":
                                corp_rules_image_urls[2]
                        },
                        "color":
                            0x0A84FF,
                    },
                    {
                        "title":
                            "📕 RÈGLEMENT CORPORATION — FREEBORN LEGACY",

                        "description":
                            "Lis attentivement les **3 parties** du "
                            "Règlement Corporation ci-dessus.\n\n"
                            "En validant, tu confirmes avoir lu et "
                            "accepté **l'intégralité du règlement**. "
                            "Freeborn Verify enregistre une preuve "
                            "horodatée de ton acceptation.",

                        "color":
                            0x0A84FF,

                        "fields": [
                            {
                                "name":
                                    "📌 Version en vigueur",

                                "value":
                                    f"`{CORP_RULES_VERSION}` "
                                    "— 11 août 2026",

                                "inline":
                                    False,
                            },
                            {
                                "name":
                                    "➡️ Étape suivante",

                                "value":
                                    "Après le Règlement Corporation, "
                                    "poursuis avec la **Charte Freeborn**.",

                                "inline":
                                    False,
                            },
                        ],

                        "footer": {
                            "text":
                                "Freeborn Legacy • Règlement Corporation"
                        },
                    },
                ],

                "components": [
                    {
                        "type":
                            1,

                        "components": [
                            {
                                "type":
                                    2,

                                "style":
                                    3,

                                "label":
                                    "J'accepte le Règlement Corporation",

                                "custom_id":
                                    "v3_accept_corp_rules",
                            }
                        ],
                    }
                ],
            },
        })

    # ========================================================
    # /charte-panneau
    # V3 STAFF SETUP — official 3-part visual publication
    # ========================================================

    if (
        command_name
        ==
        "charte-panneau"
    ):

        charter_channel_id = (
            guild_dedicated_channel_id(
                guild_config,
                "charter",
            )
        )

        if (
            not charter_channel_id
            or
            str(data.get("channel_id", ""))
            !=
            charter_channel_id
        ):

            return dedicated_channel_error(
                charter_channel_id,
                "charte-freeborn",
            )

        charter_image_urls = [
            (
                f"{PUBLIC_BASE_URL}"
                "/assets/charte-corp-part1.png"
            ),
            (
                f"{PUBLIC_BASE_URL}"
                "/assets/charte-corp-part2.png"
            ),
            (
                f"{PUBLIC_BASE_URL}"
                "/assets/charte-corp-part3.png"
            ),
        ]

        return jsonify({
            "type":
                4,

            "data": {
                "embeds": [
                    {
                        "image": {
                            "url":
                                charter_image_urls[0]
                        },
                        "color":
                            0x0A84FF,
                    },
                    {
                        "image": {
                            "url":
                                charter_image_urls[1]
                        },
                        "color":
                            0x0A84FF,
                    },
                    {
                        "image": {
                            "url":
                                charter_image_urls[2]
                        },
                        "color":
                            0x0A84FF,
                    },
                    {
                        "title":
                            "📜 CHARTE DE FREEBORN LEGACY",

                        "description":
                            "Lis attentivement les **3 parties** de "
                            "la Charte Freeborn Legacy ci-dessus.\n\n"
                            "En validant, tu confirmes avoir lu et "
                            "accepté **l'intégralité de la Charte**. "
                            "Freeborn Verify enregistre une preuve "
                            "horodatée de ton acceptation.",

                        "color":
                            0x0A84FF,

                        "fields": [
                            {
                                "name":
                                    "📌 Version en vigueur",

                                "value":
                                    f"`{FREEBORN_CHARTER_VERSION}` "
                                    "— 11 août 2026",

                                "inline":
                                    False,
                            },
                            {
                                "name":
                                    "✅ Validation documentaire",

                                "value":
                                    "Le parcours documentaire n'est "
                                    "considéré comme terminé que lorsque "
                                    "le **Règlement Corporation** et la "
                                    "**Charte Freeborn Legacy** sont tous "
                                    "les deux acceptés.",

                                "inline":
                                    False,
                            },
                        ],

                        "footer": {
                            "text":
                                "Freeborn Legacy • Charte Corporation"
                        },
                    },
                ],

                "components": [
                    {
                        "type":
                            1,

                        "components": [
                            {
                                "type":
                                    2,

                                "style":
                                    3,

                                "label":
                                    "J'accepte la Charte Freeborn Legacy",

                                "custom_id":
                                    "v3_accept_charter",
                            }
                        ],
                    }
                ],
            },
        })

    # ========================================================
    # /candidat-accepter
    # V3 RECRUITMENT MANAGEMENT
    # ========================================================

    if (
        command_name
        ==
        "candidat-accepter"
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

            if option.get("name") == "membre":

                target_user_id = str(
                    option["value"]
                )

                break

        if not target_user_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun candidat sélectionné.",

                    "flags":
                        64,
                },
            })

        current_status = get_member_status_v3(
            guild_id,
            target_user_id,
        )

        if (
            not current_status
            or
            current_status[0]
            !=
            "candidate"
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "ℹ️ Cette personne n'a pas "
                        "le statut V3 **Candidat**. "
                        "Aucune modification effectuée.",

                    "flags":
                        64,
                },
            })

        policy_state = (
            has_required_policy_acceptances_v3(
                guild_id,
                target_user_id,
            )
        )

        if not policy_state["complete"]:

            missing_documents = []

            if not policy_state["corp_rules"]:

                missing_documents.append(
                    "Règlement Corp"
                )

            if not policy_state["charter"]:

                missing_documents.append(
                    "Charte Freeborn"
                )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Validation impossible**\n\n"
                        "Le candidat doit encore accepter : "
                        + ", ".join(missing_documents)
                        + ".",

                    "flags":
                        64,
                },
            })

        try:

            role_result = (
                apply_recruitment_status_role(
                    guild_id,
                    target_user_id,
                    "candidate_accepted",
                )
            )

            if (
                role_result["add_status_code"]
                not in
                (200, 204)
            ):

                raise RuntimeError(
                    "Candidate Accepted role assignment failed: "
                    f"{role_result['add_status_code']}"
                )

            set_member_status_v3(
                guild_id,
                target_user_id,
                "candidate_accepted",
                discord_user_id,
            )

            add_audit_event_v3(
                guild_id,
                "candidate_accepted",
                target_discord_user_id=
                    target_user_id,
                actor_discord_user_id=
                    discord_user_id,
            )

        except Exception as error:

            print(
                "V3 candidate acceptance failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Le passage vers "
                        "**Candidat Accepté** a échoué. "
                        "Aucune validation n'est confirmée.",

                    "flags":
                        64,
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "✅ **Candidat validé**\n\n"
                    f"<@{target_user_id}> est maintenant "
                    "**Candidat Accepté**.\n"
                    "Les anciens rôles transitoires ont été "
                    "retirés automatiquement.",

                "flags":
                    64,
            },
        })

    # ========================================================
    # /membre-promouvoir
    # V3 RECRUITMENT MANAGEMENT
    # ========================================================

    if (
        command_name
        ==
        "membre-promouvoir"
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

            if option.get("name") == "membre":

                target_user_id = str(
                    option["value"]
                )

                break

        if not target_user_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun candidat accepté sélectionné.",

                    "flags":
                        64,
                },
            })

        current_status = get_member_status_v3(
            guild_id,
            target_user_id,
        )

        if (
            not current_status
            or
            current_status[0]
            !=
            "candidate_accepted"
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "ℹ️ Cette personne n'a pas "
                        "le statut **Candidat Accepté**. "
                        "Aucune modification effectuée.",

                    "flags":
                        64,
                },
            })

        policy_state = (
            has_required_policy_acceptances_v3(
                guild_id,
                target_user_id,
            )
        )

        if not policy_state["complete"]:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Promotion impossible**\n\n"
                        "Les deux acceptations actuelles "
                        "(Règlement Corp et Charte Freeborn) "
                        "sont obligatoires.",

                    "flags":
                        64,
                },
            })

        if not has_verified_main_v3(
            guild_id,
            target_user_id,
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Promotion impossible**\n\n"
                        "Aucun Main EVE valide n'est enregistré "
                        "pour ce candidat. Le candidat doit d'abord "
                        "finaliser son intégration avec **/freeborn**.",

                    "flags":
                        64,
                },
            })

        try:

            role_result = (
                apply_recruitment_status_role(
                    guild_id,
                    target_user_id,
                    "member",
                )
            )

            if (
                role_result["add_status_code"]
                not in
                (200, 204)
            ):

                raise RuntimeError(
                    "Member role assignment failed: "
                    f"{role_result['add_status_code']}"
                )

            set_member_status_v3(
                guild_id,
                target_user_id,
                "member",
                discord_user_id,
            )

            add_audit_event_v3(
                guild_id,
                "member_promoted",
                target_discord_user_id=
                    target_user_id,
                actor_discord_user_id=
                    discord_user_id,
            )

        except Exception as error:

            print(
                "V3 member promotion failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Le passage vers **Membre** "
                        "a échoué. Aucune promotion "
                        "n'est confirmée.",

                    "flags":
                        64,
                },
            })

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "✅ **Recrutement terminé**\n\n"
                    f"<@{target_user_id}> est maintenant "
                    "**Membre**.\n"
                    "Les rôles transitoires précédents ont "
                    "été retirés automatiquement.",

                "flags":
                    64,
            },
        })

    # ========================================================
    # /membre-supprimer
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "membre-supprimer"
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
                        "**/membre-supprimer**.",

                    **interaction_response_flags_payload(data),
                },
            })

        # ----------------------------------------------------
        # Discord target information
        # ----------------------------------------------------

        target_member = get_discord_member(
            guild_id,
            target_user_id,
        ) or {}

        target_user = target_member.get(
            "user",
            {},
        )

        if target_user.get("bot", False):
            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "⛔ **Suppression refusée**\n\n"
                        "Un bot Discord ne peut pas être sélectionné "
                        "comme profil Freeborn à supprimer.",
                    **interaction_response_flags_payload(data),
                },
            })

        target_display_name = (
            target_member.get("nick")
            or target_user.get("global_name")
            or target_user.get("username")
            or target_user_id
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
            "⚠️ **CONFIRMATION — SUPPRESSION DU PROFIL**",
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
    # /alt-supprimer
    # MEMBER COMMAND - CONFIRMATION REQUIRED
    # ========================================================

    if command_name == "alt-supprimer":

        selected_character_id = None

        for option in data["data"].get("options", []):
            if option.get("name") == "personnage":
                selected_character_id = option.get("value")
                break

        if not selected_character_id:
            return jsonify({
                "type": 4,
                "data": {
                    "content": "❌ Aucun personnage secondaire n'a été sélectionné.",
                    **interaction_response_flags_payload(data),
                },
            })

        try:
            alts = get_member_alts(discord_user_id)
        except Exception as error:
            print("Alt remove lookup failed:", repr(error))
            return jsonify({
                "type": 4,
                "data": {
                    "content": "⚠️ Impossible de lire tes personnages secondaires.",
                    **interaction_response_flags_payload(data),
                },
            })

        selected_alt = next(
            (alt for alt in alts if str(alt[0]) == str(selected_character_id)),
            None,
        )

        if not selected_alt:
            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "❌ Ce personnage n'est pas un personnage secondaire enregistré "
                        "sur ton compte. Ton Main ne peut jamais être supprimé "
                        "avec **/alt-supprimer**.",
                    **interaction_response_flags_payload(data),
                },
            })

        token = create_alt_remove_token(
            selected_character_id,
            discord_user_id,
        )

        return jsonify({
            "type": 4,
            "data": {
                "content":
                    "⚠️ **Confirmer la suppression de l'Alt ?**\n\n"
                    f"Personnage : **{selected_alt[1]}**\n"
                    "Cette action retirera ce personnage de ton profil Freeborn.\n"
                    "Ton Main restera inchangé.\n\n"
                    "La confirmation expire dans 5 minutes.",
                **interaction_response_flags_payload(data),
                "components": [{
                    "type": 1,
                    "components": [
                        {
                            "type": 2,
                            "style": 4,
                            "label": "Confirmer la suppression",
                            "custom_id": f"ar_yes:{token}",
                        },
                        {
                            "type": 2,
                            "style": 2,
                            "label": "Annuler",
                            "custom_id": f"ar_no:{token}",
                        },
                    ],
                }],
            },
        })

    # ========================================================
    # /membre-liste
    # STAFF ONLY - READ ONLY
    # ========================================================

    if (
        command_name
        ==
        "membre-liste"
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
                        "👥 **Liste des membres Freeborn**\n\n"
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
    # /synchro-statut
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "synchro-statut"
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
                        "📡 **État de la synchronisation Freeborn**\n\n"
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
    # /main-changer
    # MEMBER COMMAND - CONFIRMATION REQUIRED
    # ========================================================

    if command_name == "main-changer":

        current_main = get_main_character(discord_user_id)

        if not current_main:
            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "❌ Aucun personnage principal n'est enregistré. "
                        "Finalise d'abord ton identité EVE avec **/freeborn**.",
                    **interaction_response_flags_payload(data),
                },
            })

        selected_character_id = None

        for option in data["data"].get("options", []):
            if option.get("name") == "personnage":
                selected_character_id = option.get("value")
                break

        if not selected_character_id:
            return jsonify({
                "type": 4,
                "data": {
                    "content": "❌ Aucun personnage secondaire n'a été sélectionné.",
                    **interaction_response_flags_payload(data),
                },
            })

        try:
            alts = get_member_alts(discord_user_id)
        except Exception as error:
            print("Main change alt lookup failed:", repr(error))
            return jsonify({
                "type": 4,
                "data": {
                    "content": "⚠️ Impossible de lire tes personnages secondaires.",
                    **interaction_response_flags_payload(data),
                },
            })

        selected_alt = next(
            (alt for alt in alts if str(alt[0]) == str(selected_character_id)),
            None,
        )

        if not selected_alt:
            return jsonify({
                "type": 4,
                "data": {
                    "content":
                        "❌ Ce personnage n'est pas un personnage secondaire enregistré "
                        "sur ton compte.",
                    **interaction_response_flags_payload(data),
                },
            })

        token = create_main_change_token(
            selected_character_id,
            discord_user_id,
        )

        return jsonify({
            "type": 4,
            "data": {
                "content":
                    "🔄 **Confirmer le changement de Main ?**\n\n"
                    f"Personnage principal actuel : **{current_main[1]}**\n"
                    f"Nouveau personnage principal : **{selected_alt[1]}**\n\n"
                    "L'ancien personnage principal deviendra automatiquement un personnage secondaire. "
                    "Aucun personnage ne sera supprimé.\n\n"
                    "La confirmation expire dans 5 minutes.",
                **interaction_response_flags_payload(data),
                "components": [{
                    "type": 1,
                    "components": [
                        {
                            "type": 2,
                            "style": 3,
                            "label": "Confirmer le changement",
                            "custom_id": f"mc_yes:{token}",
                        },
                        {
                            "type": 2,
                            "style": 2,
                            "label": "Annuler",
                            "custom_id": f"mc_no:{token}",
                        },
                    ],
                }],
            },
        })

    # ========================================================
    # /membre-info
    # ========================================================

    if (
        command_name
        ==
        "membre-info"
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
                        "👤 **Profil membre Freeborn**\n\n"
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
    # /base-statut
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "base-statut"
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
                        "🗄️ **Base de données Freeborn**\n\n"
                        "❌ Base de données "
                        "indisponible.",

                    **interaction_response_flags_payload(data),
                },
            })

        message = (
            "🗄️ **État de la base de données Freeborn**\n\n"

            "✅ Statut : **Connectée**\n"

            "📋 Table : "
            "**eve_characters**\n\n"

            f"👥 Personnages : "
            f"**{stats['characters']}**\n"

            f"🔗 Personnages principaux : "
            f"**{stats['mains']}**\n"

            f"🔹 Personnages secondaires : "
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
    # /synchro-verifier
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "synchro-verifier"
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
    # /synchro-appliquer
    # STAFF ONLY
    # ========================================================

    if (
        command_name
        ==
        "synchro-appliquer"
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
                "Sync apply preview failed:",
                repr(error),
            )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⚠️ Le contrôle préalable "
                        "à la synchronisation a rencontré une erreur.",

                    **interaction_response_flags_payload(data),
                },
            })

        confirmation_token = (
            create_sync_apply_token(
                discord_user_id
            )
        )

        preview_message = (
            build_sync_message(
                sync_results,
                applied=False,
            )
            +
            "\n\n⚠️ **Confirmation requise**\n"
            "Aucun changement n'a encore été appliqué.\n"
            "En confirmant, Freeborn Verify relancera un contrôle ESI "
            "à jour avant toute modification.\n\n"
            "Cette confirmation expire après **5 minutes**."
        )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    preview_message,

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
                                    "Confirmer la synchronisation",

                                "custom_id":
                                    f"sa_yes:{confirmation_token}",
                            },

                            {
                                "type":
                                    2,

                                "style":
                                    2,

                                "label":
                                    "Annuler",

                                "custom_id":
                                    f"sa_no:{confirmation_token}",
                            },
                        ],
                    }
                ],

                **interaction_response_flags_payload(data),
            },
        })

    # ========================================================
    # /verification
    # MEMBER COMMAND
    # ========================================================

    if (
        command_name
        ==
        "verification"
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

            if option.get("name") == "membre":

                target_user_id = str(
                    option["value"]
                )

                break

        if not target_user_id:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "❌ Aucun candidat sélectionné.",

                    "flags":
                        64,
                },
            })

        status_row = get_member_status_v3(
            guild_id,
            target_user_id,
        )

        status_value = (
            status_row[0]
            if status_row
            else None
        )

        status_labels = {
            "guest":
                "Invité",

            "candidate":
                "Candidat",

            "candidate_accepted":
                "Candidat Accepté",

            "member":
                "Membre",
        }

        policy_state = (
            has_required_policy_acceptances_v3(
                guild_id,
                target_user_id,
            )
        )

        main_row = get_guild_main_character_v3(
            guild_id,
            target_user_id,
        )

        if not main_row and str(guild_id) == str(DISCORD_GUILD_ID):

            legacy_main = get_main_character(
                target_user_id
            )

            if legacy_main:

                main_name = legacy_main[1]
                main_text = (
                    f"✅ **{main_name}** "
                    "(ancien profil Freeborn)"
                )

            else:

                main_text = "❌ Aucun Main EVE enregistré"

        elif main_row:

            (
                main_character_id,
                main_name,
                main_corporation_id,
                main_in_corporation,
                main_verified_at,
                main_last_checked_at,
                main_left_at,
                main_total_skill_points,
                main_skills_updated_at,
            ) = main_row

            main_text = (
                f"✅ **{main_name}** "
                f"(`{main_character_id}`)"
            )

            if main_total_skill_points is not None:
                main_text += (
                    "\n🎓 Skill Points : "
                    f"**{int(main_total_skill_points):,} SP**"
                )

        else:

            main_text = "❌ Aucun Main EVE enregistré"

        lines = [
            "🔎 **Vérification recrutement Freeborn**",
            "",
            f"Candidat : <@{target_user_id}>",
            (
                "Statut Discord : "
                f"**{status_labels.get(status_value, 'Non défini')}**"
            ),
            "",
            "### Documents",
            (
                "✅ Règlement Corp"
                if policy_state["corp_rules"]
                else
                "❌ Règlement Corp"
            ),
            (
                "✅ Charte Freeborn"
                if policy_state["charter"]
                else
                "❌ Charte Freeborn"
            ),
            "",
            "### Identité EVE",
            main_text,
            "",
        ]

        if status_value == "candidate_accepted":

            lines.append(
                "✅ **Recrutement validé par la Direction/RH.**"
            )

        elif status_value == "candidate":

            lines.append(
                "🕒 **Candidature encore en cours.**"
            )

        elif status_value == "member":

            lines.append(
                "✅ Cette personne est déjà **Membre**."
            )

        else:

            lines.append(
                "⚠️ Le parcours Candidat n'est pas actif."
            )

        return jsonify({
            "type":
                4,

            "data": {
                "content":
                    "\n".join(lines),

                "flags":
                    64,
            },
        })

    # ========================================================
    # /freeborn
    # FINAL MEMBER INTEGRATION
    # ========================================================

    elif (
        command_name
        ==
        "freeborn"
    ):

        current_status = get_member_status_v3(
            guild_id,
            discord_user_id,
        )

        if (
            not current_status
            or
            current_status[0]
            not in {
                "candidate",
                "candidate_accepted",
            }
        ):

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Parcours Freeborn incomplet**\n\n"
                        "Tu dois d'abord passer par "
                        "**Orientation → Candidat**.",

                    **interaction_response_flags_payload(data),
                },
            })

        policy_state = (
            has_required_policy_acceptances_v3(
                guild_id,
                discord_user_id,
            )
        )

        if not policy_state["complete"]:

            missing_documents = []

            if not policy_state["corp_rules"]:

                missing_documents.append(
                    "Règlement Corp"
                )

            if not policy_state["charter"]:

                missing_documents.append(
                    "Charte Freeborn"
                )

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "⛔ **Parcours Freeborn incomplet**\n\n"
                        "Il te reste à accepter : "
                        + ", ".join(missing_documents)
                        + ".",

                    **interaction_response_flags_payload(data),
                },
            })

        verification_type = (
            "freeborn"
        )

    # ========================================================
    # /alt-ajouter
    # MEMBER COMMAND
    # ========================================================

    elif (
        command_name
        ==
        "alt-ajouter"
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
                        "ton personnage principal.",

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
                        "**/freeborn** "
                        "pour enregistrer ton Main EVE.",

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

    # Only candidates finalising /freeborn grant the private ESI scope.
    # Guests never authenticate to EVE, and legacy Main/Alt actions do not
    # request private character data.
    if verification_type == "freeborn":
        params["scope"] = " ".join(
            FREEBORN_EVE_SCOPES
        )

    login_url = (
        f"{EVE_AUTHORIZE_URL}?"
        f"{urlencode(params)}"
    )

    if (
        verification_type
        ==
        "freeborn"
    ):

        message = (
            "🛡️ **Intégration Freeborn**\n\n"
            "Connecte ton **Main EVE**. "
            "Freeborn Verify contrôlera que ce personnage "
            "appartient bien à la corporation EVE configurée "
            "pour ce serveur.\n\n"
            f"[Finaliser mon intégration Freeborn]"
            f"({login_url})"
        )

    elif (
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
            "🔗 **Vérification du personnage secondaire**\n\n"

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
# WEB UI - FREEBORN LEGACY V3
# ============================================================

def freeborn_web_page(
    title,
    message,
    status="info",
    character_name=None,
):

    status_map = {
        "success": ("✓", "VALIDATION CONFIRMÉE", "#22C55E"),
        "pending": ("⌛", "SYNCHRONISATION ESI", "#FFB300"),
        "warning": ("i", "INFORMATIONS", "#0A84FF"),
        "error": ("×", "ERREUR", "#FF3B30"),
        "info": ("i", "INFORMATIONS", "#00E5FF"),
    }

    icon, badge, accent = status_map.get(
        status,
        status_map["info"],
    )

    safe_title = escape(str(title))
    safe_message = escape(str(message)).replace("\n", "<br>")
    safe_character = (
        escape(str(character_name))
        if character_name
        else None
    )

    character_html = (
        f"""
        <div class="character">
            <span>Personnage EVE</span>
            <strong>{safe_character}</strong>
        </div>
        """
        if safe_character
        else ""
    )

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#02070d">
<link rel="icon" type="image/png" href="/assets/favicon.png">
<title>Freeborn Legacy — {safe_title}</title>
<style>
:root {{
    color-scheme: dark;
    --accent:{accent};
    --cyan:#00E5FF;
    --blue:#0A84FF;
    --green:#22C55E;
    --orange:#FFB300;
    --red:#FF3B30;
    --text:#F5F8FC;
    --muted:#B9C8D5;
}}
* {{ box-sizing:border-box; }}
html,body {{ min-height:100%; }}
body {{
    margin:0;
    min-height:100vh;
    display:grid;
    place-items:center;
    padding:18px;
    color:var(--text);
    font-family:"Segoe UI",Arial,sans-serif;
    background:
        linear-gradient(rgba(0,4,9,.38),rgba(0,4,9,.58)),
        url("/assets/bg-space.jpg") center/cover fixed no-repeat,
        #01050a;
}}
.page {{
    width:min(860px,100%);
}}
.frame {{
    position:relative;
    padding:2px;
    background:linear-gradient(135deg,var(--cyan),var(--blue) 28%,transparent 45%,var(--blue) 72%,var(--cyan));
    clip-path:polygon(0 28px,28px 0,calc(100% - 28px) 0,100% 28px,100% calc(100% - 28px),calc(100% - 28px) 100%,28px 100%,0 calc(100% - 28px));
    filter:drop-shadow(0 0 14px rgba(0,132,255,.38));
}}
.card {{
    position:relative;
    min-height:0;
    padding:20px 48px 24px;
    text-align:center;
    background:
        linear-gradient(rgba(1,8,15,.91),rgba(1,7,13,.96)),
        url("/assets/bg-panel.jpg") center/cover;
    clip-path:inherit;
    overflow:hidden;
}}
.card::before,
.card::after {{
    content:"";
    position:absolute;
    top:62px;
    width:22%;
    height:1px;
    background:linear-gradient(90deg,transparent,var(--cyan));
    box-shadow:0 0 9px var(--blue);
}}
.card::before {{ left:3%; }}
.card::after {{ right:3%; transform:scaleX(-1); }}
.logo {{
    display:block;
    width:min(210px,48vw);
    height:auto;
    margin:0 auto 10px;
    object-fit:contain;
}}
.status-icon {{
    width:54px;
    height:54px;
    margin:0 auto 10px;
    display:grid;
    place-items:center;
    transform:rotate(45deg);
    border:2px solid var(--accent);
    border-radius:8px;
    color:var(--accent);
    font-size:27px;
    font-weight:900;
    background:color-mix(in srgb,var(--accent) 10%,#02070d);
    box-shadow:0 0 20px color-mix(in srgb,var(--accent) 52%,transparent);
}}
.status-icon span {{ transform:rotate(-45deg); }}
.badge {{
    margin:0 0 6px;
    color:var(--accent);
    font-size:13px;
    font-weight:800;
    letter-spacing:.16em;
}}
h1 {{
    margin:4px 0 12px;
    font-size:clamp(28px,4.4vw,40px);
    line-height:1.05;
    text-transform:uppercase;
    letter-spacing:.025em;
    color:var(--accent);
    text-shadow:0 0 22px color-mix(in srgb,var(--accent) 24%,transparent);
}}
.message {{
    max-width:720px;
    margin:0 auto;
    color:#F2F6FA;
    font-size:16px;
    line-height:1.5;
}}
.character {{
    max-width:650px;
    margin:18px auto 0;
    padding:12px 18px;
    display:flex;
    justify-content:center;
    gap:18px;
    align-items:center;
    border:1px solid color-mix(in srgb,var(--accent) 78%,transparent);
    background:rgba(0,7,14,.78);
    box-shadow:inset 0 0 22px rgba(0,0,0,.45);
}}
.character span {{ color:#E9F0F6; }}
.character span::after {{ content:" :"; }}
.character strong {{ color:var(--accent); }}
.footer {{
    margin:18px auto 0;
    padding-top:13px;
    max-width:720px;
    border-top:1px solid rgba(0,229,255,.28);
    color:var(--muted);
    font-size:14px;
}}
.brandline {{
    margin-top:14px;
    color:#48B9FF;
    font-size:11px;
    letter-spacing:.22em;
    text-transform:uppercase;
}}
@media (max-width:640px) {{
    body {{ padding:12px; }}
    .card {{ min-height:0; padding:24px 20px 28px; }}
    .card::before,.card::after {{ top:64px; width:14%; }}
    .logo {{ margin-bottom:18px; }}
    .status-icon {{ width:54px; height:54px; font-size:27px; }}
    .message {{ font-size:16px; }}
    .character {{ flex-direction:column; gap:5px; }}
}}
</style>
</head>
<body>
<div class="page">
    <div class="frame">
        <main class="card">
            <img class="logo" src="/assets/logo-freeborn-legacy.png" alt="Freeborn Legacy">
            <div class="status-icon"><span>{icon}</span></div>
            <div class="badge">{badge}</div>
            <h1>{safe_title}</h1>
            <div class="message">{safe_message}</div>
            {character_html}
            <div class="footer">Tu peux fermer cette fenêtre et retourner sur Discord.</div>
            <div class="brandline">Freeborn Legacy · Freeborn Verify V3</div>
        </main>
    </div>
</div>
</body>
</html>"""


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

        return freeborn_web_page(
            "Authentification impossible",
            "La demande EVE est incomplète. Relance la commande depuis Discord.",
            status="error",
        ), 400

    try:

        state_data = (
            state_serializer.loads(
                state,
                max_age=600,
            )
        )

    except SignatureExpired:

        return freeborn_web_page(
            "Lien expiré",
            "Le lien de vérification a expiré. Relance la commande depuis Discord.",
            status="error",
        ), 400

    except BadSignature:

        return freeborn_web_page(
            "Demande invalide",
            "La demande de vérification n'est pas valide. Relance la commande depuis Discord.",
            status="error",
        ), 400

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

    guild_config = get_guild_config(
        guild_id
    )

    if (
        not guild_config
        or
        not guild_config[6]
    ):

        return freeborn_web_page(
            "Serveur Discord invalide",
            "Ce serveur n'est pas configuré ou n'est plus actif dans Freeborn Verify V3.",
            status="error",
        ), 400

    expected_corporation_id = (
        guild_config[2]
    )

    if not expected_corporation_id:

        return freeborn_web_page(
            "Configuration EVE incomplète",
            "Aucune corporation EVE n'est configurée pour ce serveur Discord.",
            status="warning",
        ), 500

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

        return freeborn_web_page(
            "Connexion EVE refusée",
            "Freeborn Verify n'a pas pu obtenir l'autorisation EVE. Relance l'intégration depuis Discord.",
            status="error",
        ), 400

    token_data = token_response.json()

    access_token = token_data[
        "access_token"
    ]

    refresh_token = token_data.get(
        "refresh_token"
    )

    try:

        (
            character_id,
            character_name,
            granted_scopes,
        ) = get_eve_identity(
            access_token
        )

    except Exception as error:

        print(
            "EVE identity verification failed:",
            repr(error),
        )

        return freeborn_web_page(
            "Identité EVE non validée",
            "L'identité du personnage EVE n'a pas pu être vérifiée.",
            status="error",
        ), 400

    skill_summary = None

    if verification_type == "freeborn":

        missing_scopes = (
            set(FREEBORN_EVE_SCOPES)
            -
            set(granted_scopes)
        )

        if missing_scopes:

            return freeborn_web_page(
                "Autorisation ESI incomplète",
                "Le scope ESI nécessaire aux compétences n'a pas été accordé. Relance /freeborn et accepte l'autorisation EVE demandée.",
                status="error",
                character_name=character_name,
            ), 403

        if not refresh_token:

            return freeborn_web_page(
                "Autorisation EVE incomplète",
                "EVE n'a pas fourni de refresh token. Relance /freeborn afin que Freeborn puisse conserver l'autorisation sans te redemander de te connecter.",
                status="error",
                character_name=character_name,
            ), 400

        try:

            skill_summary = get_eve_character_skills(
                character_id,
                access_token,
            )

        except Exception as error:

            print(
                "EVE skills lookup failed:",
                repr(error),
            )

            return freeborn_web_page(
                "Compétences EVE indisponibles",
                "Freeborn Verify n'a pas pu récupérer les Skill Points du personnage. Aucune intégration n'a été enregistrée ; relance /freeborn dans quelques instants.",
                status="warning",
                character_name=character_name,
            ), 502

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

        return freeborn_web_page(
            "Personnage EVE indisponible",
            "Les informations du personnage n'ont pas pu être récupérées auprès d'EVE Online.",
            status="error",
        ), 400

    character_data = (
        character_response.json()
    )

    corporation_id = (
        character_data[
            "corporation_id"
        ]
    )

    # ========================================================
    # TEMPORARY ESI CORPORATION DIAGNOSTIC
    # Safe diagnostic only: no token, code, state or secret logged.
    # ========================================================

    esi_date = character_response.headers.get(
        "Date",
        "",
    )

    esi_expires = character_response.headers.get(
        "Expires",
        "",
    )

    esi_age = character_response.headers.get(
        "Age",
        "",
    )

    esi_etag = character_response.headers.get(
        "ETag",
        "",
    )

    corporation_match = (
        int(corporation_id)
        ==
        int(expected_corporation_id)
    )

    print(
        "[FREEBORN ESI DEBUG] "
        f"character={character_name!r} "
        f"character_id={character_id} "
        f"corporation_id_esi={corporation_id} "
        f"corporation_id_expected={expected_corporation_id} "
        f"match={corporation_match} "
        f"verification_type={verification_type!r} "
        f"guild_id={guild_id} "
        f"esi_date={esi_date!r} "
        f"esi_expires={esi_expires!r} "
        f"esi_age={esi_age!r} "
        f"esi_etag={esi_etag!r}",
        flush=True,
    )

    if (
        int(corporation_id)
        !=
        int(expected_corporation_id)
    ):

        return freeborn_web_page(
            "Intégration en attente",
            (
                "Freeborn Verify ne peut pas encore confirmer ton appartenance "
                "à Freeborn Legacy auprès de l’ESI EVE Online.\n\n"
                "Après une entrée récente dans la corporation, la synchronisation "
                "des données ESI peut nécessiter un certain délai. Un délai pouvant "
                "aller jusqu’à 24 heures peut être nécessaire.\n\n"
                "Réessaie simplement /freeborn un peu plus tard. Si la situation "
                "persiste au-delà de ce délai, contacte le staff."
            ),
            status="pending",
            character_name=character_name,
        ), 409

    # ========================================================
    # FREEBORN FINAL INTEGRATION FLOW
    # ========================================================

    if (
        verification_type
        ==
        "freeborn"
    ):

        current_status = get_member_status_v3(
            guild_id,
            discord_user_id,
        )

        if (
            not current_status
            or
            current_status[0]
            not in {
                "candidate",
                "candidate_accepted",
            }
        ):

            return freeborn_web_page(
                "Parcours Discord incomplet",
                "Le parcours Orientation → Candidat doit être effectué avant /freeborn.",
                status="error",
            ), 400

        policy_state = (
            has_required_policy_acceptances_v3(
                guild_id,
                discord_user_id,
            )
        )

        if not policy_state["complete"]:

            return freeborn_web_page(
                "Documents non acceptés",
                "Le Règlement Corp et la Charte Freeborn doivent être lus et acceptés avant /freeborn.",
                status="error",
            ), 400

        try:

            save_main_character_v3(
                guild_id,
                discord_user_id,
                character_id,
                character_name,
                corporation_id,
                refresh_token=refresh_token,
                granted_scopes=granted_scopes,
                total_skill_points=skill_summary["total_sp"],
            )

            if str(guild_id) == str(DISCORD_GUILD_ID):

                try:

                    save_main_character(
                        discord_user_id,
                        character_id,
                        character_name,
                        corporation_id,
                    )

                except ValueError as legacy_error:

                    if (
                        "already has main character"
                        not in str(legacy_error)
                        and
                        "already linked"
                        not in str(legacy_error).lower()
                    ):

                        raise

        except ValueError as error:

            error_text = str(error)
            if "another Discord account" in error_text:
                error_text = "Ce personnage EVE est déjà lié à un autre compte Discord."
            elif "already has main character" in error_text:
                error_text = "Ce compte Discord possède déjà un Main EVE enregistré."

            return freeborn_web_page(
                "Conflit d'identité EVE",
                error_text,
                status="error",
                character_name=character_name,
            ), 409

        except Exception as error:

            print(
                "V3 /freeborn main save failed:",
                repr(error),
            )

            return freeborn_web_page(
                "Erreur de base de données",
                "L'identité EVE n'a pas pu être enregistrée. Aucune validation n'a été confirmée.",
                status="warning",
                character_name=character_name,
            ), 500

        eve_verified_role_id = resolve_guild_role_id(
            guild_id,
            "eve_verified",
        )

        main_character_role_id = resolve_guild_role_id(
            guild_id,
            "main_character",
        )

        if (
            not eve_verified_role_id
            or
            not main_character_role_id
        ):

            return freeborn_web_page(
                "Rôles Discord non configurés",
                "Les rôles EVE Verified / Main Character ne sont pas correctement configurés pour ce serveur.",
                status="warning",
            ), 500

        identity_role_responses = [
            add_discord_role(
                guild_id,
                discord_user_id,
                eve_verified_role_id,
            ),

            add_discord_role(
                guild_id,
                discord_user_id,
                main_character_role_id,
            ),
        ]

        if any(
            response.status_code
            not in
            (200, 204)

            for response
            in identity_role_responses
        ):

            return freeborn_web_page(
                "Attribution des rôles impossible",
                "L'identité EVE est enregistrée mais les rôles Discord n'ont pas pu être attribués. Contacte un administrateur.",
                status="warning",
                character_name=character_name,
            ), 500

        add_audit_event_v3(
            guild_id,
            "freeborn_eve_identity_verified",
            target_discord_user_id=
                discord_user_id,
            actor_discord_user_id=
                discord_user_id,
        )

        log_v3_event_to_discord(
            guild_config,
            "🛡️ **Identité EVE vérifiée**\n"
            f"Membre : <@{discord_user_id}> (`{discord_user_id}`)\n"
            f"Main EVE : **{character_name}**\n"
            f"Skill Points : **{skill_summary['total_sp']:,} SP**\n"
            "Étape suivante : contrôle staff puis promotion en Membre.",
        )

        nickname_response = sync_discord_nickname(
            guild_id,
            discord_user_id,
            character_name,
        )

        nickname_changed = (
            nickname_response.status_code
            in
            (200, 204)
        )

        nickname_status = (
            "<p>"
            "Le pseudo Discord a été synchronisé sur "
            f"<strong>{character_name}</strong>."
            "</p>"

            if nickname_changed

            else

            "<p>"
            "Le personnage est validé, mais le pseudo Discord "
            "n'a pas pu être modifié."
            "</p>"
        )

        next_step = (
            "Ton identité EVE est validée. Le staff peut maintenant contrôler "
            "ton dossier et finaliser ton passage en Membre."
            if current_status[0] == "candidate_accepted"
            else
            "Ton identité EVE est validée. Le staff peut maintenant contrôler "
            "ton dossier puis valider ta candidature."
        )

        return freeborn_web_page(
            "Identité EVE validée",
            next_step + (
                " Le pseudo Discord a également été synchronisé."
                if nickname_changed
                else
                " Le pseudo Discord n'a pas pu être modifié automatiquement."
            ),
            status="success",
            character_name=character_name,
        )

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

                return freeborn_web_page(
                    "Main déjà enregistré",
                    f"Ton Main actuel est {existing_main_name}. Utilise /main-changer pour changer de Main.",
                    status="error",
                    character_name=character_name,
                ), 400

            return freeborn_web_page(
                "Personnage déjà lié",
                "Ce personnage EVE est déjà associé à un autre compte Discord.",
                status="error",
                character_name=character_name,
            ), 409

        except Exception as error:

            print(
                "Database main save failed:",
                repr(error),
            )

            return freeborn_web_page(
                "Erreur de base de données",
                "Le Main EVE n'a pas pu être enregistré. Aucune validation n'a été confirmée.",
                status="warning",
                character_name=character_name,
            ), 500

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

            return freeborn_web_page(
                "Attribution des rôles impossible",
                "Le personnage est enregistré mais les rôles Discord n'ont pas pu être appliqués. Contacte un administrateur.",
                status="warning",
                character_name=character_name,
            ), 500

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

        return freeborn_web_page(
            "Main EVE vérifié",
            (
                f"{character_name} est enregistré comme personnage principal. "
                + (
                    "Le pseudo Discord a été synchronisé."
                    if nickname_changed
                    else
                    "Le pseudo Discord n'a pas pu être modifié automatiquement."
                )
            ),
            status="success",
            character_name=character_name,
        )

    # ========================================================
    # ALT FLOW
    # ========================================================

    if not has_main_character(
        discord_user_id
    ):

        return freeborn_web_page(
            "Main EVE requis",
            "Tu dois d'abord enregistrer ton Main EVE avant d'ajouter un Alt.",
            status="error",
        ), 400

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

            return freeborn_web_page(
                "Ajout d'Alt refusé",
                "Ce personnage est déjà ton personnage principal.",
                status="error",
                character_name=character_name,
            ), 400

        return freeborn_web_page(
            "Personnage déjà lié",
            "Ce personnage EVE est déjà associé à un autre compte Discord.",
            status="error",
            character_name=character_name,
        ), 409

    except Exception as error:

        print(
            "Database alt save failed:",
            repr(error),
        )

        return freeborn_web_page(
            "Erreur de base de données",
            "L'Alt EVE n'a pas pu être enregistré.",
            status="warning",
            character_name=character_name,
        ), 500

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

        return freeborn_web_page(
            "Attribution du rôle Alt impossible",
            "L'Alt est enregistré mais le rôle Discord Alt Character n'a pas pu être attribué.",
            status="warning",
            character_name=character_name,
        ), 500

    return freeborn_web_page(
        "Alt EVE vérifié",
        f"{character_name} a été ajouté comme personnage secondaire.",
        status="success",
        character_name=character_name,
    )


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
                "freeborn",

            "description":
                "Finaliser ton intégration Freeborn",

            "type":
                1,
        },

        {
            "name":
                "verification",

            "description":
                "Contrôler le dossier d'un candidat",

            "type":
                1,

            "default_member_permissions":
                "0",

            "options": [
                {
                    "type":
                        3,

                    "name":
                        "membre",

                    "description":
                        "Candidat à contrôler",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "alt-ajouter",

            "description":
                "Ajouter un personnage secondaire EVE "
                "à ton profil Freeborn",

            "type":
                1,
        },

        {
            "name":
                "alt-supprimer",

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
                        "Personnage secondaire à supprimer",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "main-changer",

            "description":
                "Choisir un personnage secondaire "
                "comme nouveau personnage principal",

            "type":
                1,

            "options": [
                {
                    "type":
                        3,

                    "name":
                        "personnage",

                    "description":
                        "Personnage secondaire qui deviendra "
                        "ton personnage principal",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "membre-info",

            "description":
                "Afficher le profil EVE d'un membre Freeborn",

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
                "reglement-discord-panneau",

            "description":
                "Publier le règlement Discord officiel Freeborn Legacy",

            "type":
                1,

            "default_member_permissions":
                "0",
        },

        {
            "name":
                "bienvenue-panneau",

            "description":
                "Publier le panneau officiel de bienvenue Freeborn Legacy",

            "type":
                1,

            "default_member_permissions":
                "0",
        },

        {
            "name":
                "orientation-panneau",

            "description":
                "Publier le panneau d'orientation V3",

            "type":
                1,

            "default_member_permissions":
                "0",
        },

        {
            "name":
                "reglement-corp-panneau",

            "description":
                "Publier le bouton d'acceptation du Règlement Corp",

            "type":
                1,

            "default_member_permissions":
                "0",
        },

        {
            "name":
                "charte-panneau",

            "description":
                "Publier le bouton d'acceptation de la Charte Freeborn",

            "type":
                1,

            "default_member_permissions":
                "0",
        },

        {
            "name":
                "candidat-accepter",

            "description":
                "Valider un candidat en Candidat Accepté",

            "type":
                1,

            "default_member_permissions":
                "0",

            "options": [
                {
                    "type":
                        3,

                    "name":
                        "membre",

                    "description":
                        "Candidat à valider",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "membre-promouvoir",

            "description":
                "Promouvoir un Candidat Accepté en Membre",

            "type":
                1,

            "default_member_permissions":
                "0",

            "options": [
                {
                    "type":
                        6,

                    "name":
                        "membre",

                    "description":
                        "Candidat Accepté à promouvoir",

                    "required":
                        True,
                }
            ],
        },

        {
            "name":
                "membre-supprimer",

            "description":
                "Supprimer complètement "
                "le profil EVE d'un membre",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites are managed according to the V3 staff hierarchy.
            "default_member_permissions":
                "0",

            "options": [
                {
                    "type":
                        3,

                    "name":
                        "membre",

                    "description":
                        "Membre Freeborn à supprimer",

                    "required":
                        True,

                    "autocomplete":
                        True,
                }
            ],
        },

        {
            "name":
                "membre-liste",

            "description":
                "Afficher la liste des membres EVE enregistrés",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites are managed according to the V3 staff hierarchy.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "base-statut",

            "description":
                "Afficher l'état de la base de données Freeborn",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites are managed according to the V3 staff hierarchy.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "synchro-statut",

            "description":
                "Afficher l'état global "
                "de la synchronisation",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites are managed according to the V3 staff hierarchy.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "synchro-verifier",

            "description":
                "Contrôler les personnages "
                "Freeborn sans modifier les rôles",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites are managed according to the V3 staff hierarchy.
            "default_member_permissions":
                "0",
        },

        {
            "name":
                "synchro-appliquer",

            "description":
                "Appliquer la synchronisation et les révocations confirmées",

            "type":
                1,

            # Hidden/disabled by default. Explicit Discord role
            # overwrites are managed according to the V3 staff hierarchy.
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
                "Commandes Discord enregistrées : "
                "/freeborn, /verification, "
                "/alt-ajouter, /alt-supprimer, /main-changer, "
                "/membre-info, /membre-liste, "
                "/membre-promouvoir, /membre-supprimer, "
                "/candidat-accepter, "
                "/reglement-discord-panneau, "
                "/bienvenue-panneau, "
                "/orientation-panneau, "
                "/reglement-corp-panneau, /charte-panneau, "
                "/base-statut, /synchro-statut, "
                "/synchro-verifier, /synchro-appliquer."
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
