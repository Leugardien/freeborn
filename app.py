import base64
import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape
from urllib.parse import urlencode

import psycopg
import requests

from flask import Flask, jsonify, redirect, request, send_from_directory
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
# FREEBORN FITTINGS — ACCESS
# ============================================================

FITTING_CREATOR_ROLE_IDS = configured_role_ids(
    DISCORD_MEMBER_ROLE_ID,
    DISCORD_VETERAN_ROLE_ID,
    DISCORD_FLEET_COMMANDER_ROLE_ID,
    DISCORD_OFFICER_ROLE_ID,
    DISCORD_HR_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_CEO_ROLE_ID,
)

FITTING_MANAGER_ROLE_IDS = configured_role_ids(
    DISCORD_FLEET_COMMANDER_ROLE_ID,
    DISCORD_OFFICER_ROLE_ID,
    DISCORD_HR_ROLE_ID,
    DISCORD_DIRECTION_ROLE_ID,
    DISCORD_HIGH_COUNCIL_ROLE_ID,
    DISCORD_CEO_ROLE_ID,
)


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

fit_delete_signer = TimestampSigner(
    FLASK_SECRET_KEY,
    salt="freeborn-fit-delete",
)

fit_web_serializer = URLSafeTimedSerializer(
    FLASK_SECRET_KEY,
    salt="freeborn-fit-web",
)


fit_pilot_serializer = URLSafeTimedSerializer(
    FLASK_SECRET_KEY,
    salt="freeborn-fit-pilot",
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

                # ====================================================
                # FREEBORN FITTINGS — PHASE 1
                # ====================================================

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS fits (
                        fit_id BIGSERIAL PRIMARY KEY,
                        guild_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        ship_name TEXT NOT NULL,
                        usage TEXT NOT NULL,
                        eft_text TEXT NOT NULL,
                        notes TEXT,
                        status TEXT NOT NULL DEFAULT 'proposed'
                            CHECK (status IN ('proposed', 'testing', 'approved')),
                        created_by_discord_user_id TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        FOREIGN KEY (guild_id)
                            REFERENCES discord_guilds (guild_id)
                            ON DELETE CASCADE
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_fits_guild_ship
                    ON fits (guild_id, ship_name);
                    """
                )

                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_fits_guild_status
                    ON fits (guild_id, status);
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE fits
                    ADD COLUMN IF NOT EXISTS ship_type_id BIGINT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE fits
                    ADD COLUMN IF NOT EXISTS technical_snapshot JSONB;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE fits
                    ADD COLUMN IF NOT EXISTS technical_snapshot_version TEXT;
                    """
                )

                cur.execute(
                    """
                    ALTER TABLE fits
                    ADD COLUMN IF NOT EXISTS technical_snapshot_updated_at TIMESTAMPTZ;
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
                    skills_snapshot JSONB;
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



def infer_recruitment_status_from_interaction_roles(
    data,
    guild_id,
):
    """
    Infer the current V3 recruitment status from the live Discord
    member roles included in an interaction payload.

    The database remains the normal source of truth. This helper is
    only used to recover from a missing/stale member_statuses row,
    for example after a manual role adjustment by staff.
    """

    live_role_ids = interaction_member_role_ids(
        data
    )

    role_priority = (
        "member",
        "candidate_accepted",
        "candidate",
    )

    for status in role_priority:

        role_id = resolve_guild_role_id(
            guild_id,
            status,
        )

        if (
            role_id
            and
            str(role_id) in live_role_ids
        ):

            return status

    return None


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


def get_guild_main_by_character_id_v3(
    guild_id,
    character_id,
):
    """Return one verified guild Main from its EVE character ID."""

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    discord_user_id,
                    character_id,
                    character_name,
                    corporation_id,
                    in_corporation,
                    total_skill_points,
                    skills_updated_at,
                    skills_snapshot
                FROM guild_eve_characters
                WHERE guild_id = %s
                AND character_id = %s
                AND character_type = 'main'
                LIMIT 1;
                """,
                (
                    str(guild_id),
                    int(character_id),
                ),
            )

            row = cur.fetchone()

    if not row:
        return None

    return {
        "discord_user_id": str(row[0]),
        "character_id": int(row[1]),
        "character_name": row[2],
        "corporation_id": int(row[3]),
        "in_corporation": bool(row[4]),
        "total_skill_points": (
            int(row[5])
            if row[5] is not None
            else None
        ),
        "skills_updated_at": row[6],
        "skills_snapshot": row[7],
    }


def update_guild_main_skills_snapshot_v3(
    guild_id,
    character_id,
    skill_summary,
):
    """Refresh the stored skills snapshot after a voluntary pilot test."""

    snapshot = skill_summary.get("skills", []) or []

    with psycopg.connect(DATABASE_URL) as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                UPDATE guild_eve_characters
                SET
                    total_skill_points = %s,
                    skills_snapshot = %s::jsonb,
                    skills_updated_at = NOW(),
                    updated_at = NOW()
                WHERE guild_id = %s
                AND character_id = %s
                AND character_type = 'main';
                """,
                (
                    int(skill_summary.get("total_sp", 0) or 0),
                    json.dumps(
                        snapshot,
                        separators=(",", ":"),
                    ),
                    str(guild_id),
                    int(character_id),
                ),
            )

        conn.commit()


def save_main_character_v3(
    guild_id,
    discord_user_id,
    character_id,
    character_name,
    corporation_id,
    refresh_token=None,
    granted_scopes=None,
    total_skill_points=None,
    skills_snapshot=None,
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

    skills_snapshot_json = (
        json.dumps(
            skills_snapshot,
            separators=(",", ":"),
        )
        if skills_snapshot is not None
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
                        skills_snapshot,
                        sso_authorized_at
                    )
                    VALUES (
                        %s, %s, %s, %s, 'main',
                        %s, TRUE, NOW(), NOW(), NOW(), NULL,
                        %s, %s, %s,
                        CASE WHEN %s::BIGINT IS NULL THEN NULL ELSE NOW() END,
                        %s::jsonb,
                        CASE WHEN %s::TEXT IS NULL THEN NULL ELSE NOW() END
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
                        skills_snapshot = COALESCE(
                            EXCLUDED.skills_snapshot,
                            guild_eve_characters.skills_snapshot
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
                        skills_snapshot_json,
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
# FREEBORN FITTINGS — PHASE 2
# ============================================================

def parse_eft_header(eft_text):
    """Extract ship and optional fit name from the first EFT header line."""

    normalized = str(eft_text or "").strip()

    if not normalized:
        raise ValueError("Le champ EFT est vide.")

    first_line = normalized.splitlines()[0].strip()

    if not (first_line.startswith("[") and first_line.endswith("]")):
        raise ValueError(
            "Le format EFT doit commencer par une ligne du type "
            "[Vaisseau, Nom du fit]."
        )

    header = first_line[1:-1].strip()

    if not header:
        raise ValueError("Le nom du vaisseau est introuvable dans l'EFT.")

    parts = [part.strip() for part in header.split(",", 1)]
    ship_name = parts[0]
    eft_fit_name = parts[1] if len(parts) > 1 else ""

    if not ship_name:
        raise ValueError("Le nom du vaisseau est introuvable dans l'EFT.")

    return {
        "ship_name": ship_name,
        "eft_fit_name": eft_fit_name,
        "normalized_eft": normalized,
    }


_eve_inventory_single_id_cache = {}


def resolve_eve_inventory_type_id(type_name):
    """Resolve an exact EVE inventory type name with process caching."""

    clean_name = str(type_name or "").strip()

    if not clean_name:
        return None

    key = clean_name.casefold()

    if key in _eve_inventory_single_id_cache:
        return _eve_inventory_single_id_cache[key]

    try:
        response = requests.post(
            f"{ESI_BASE_URL}/universe/ids/",
            json=[clean_name],
            headers={
                "User-Agent": "Freeborn/3.0 Freeborn-Legacy-Discord-Bot",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()

        for item in payload.get("inventory_types", []):
            if str(item.get("name", "")).casefold() == key:
                type_id = int(item["id"])
                _eve_inventory_single_id_cache[key] = type_id
                return type_id

    except Exception as error:
        print("Freeborn Fittings ESI type resolution failed:", repr(error))

    _eve_inventory_single_id_cache[key] = None
    return None


def eve_type_render_url(type_id, size=512):
    if not type_id:
        return None

    return (
        f"https://images.evetech.net/types/{int(type_id)}/render"
        f"?size={int(size)}&tenant=tranquility"
    )


def save_fit_phase1(
    guild_id,
    discord_user_id,
    fit_name,
    usage,
    eft_text,
    notes=None,
):
    parsed = parse_eft_header(eft_text)

    clean_name = str(fit_name or "").strip() or parsed["eft_fit_name"]
    clean_usage = str(usage or "").strip()
    clean_notes = str(notes or "").strip() or None

    if not clean_name:
        raise ValueError("Le nom du fit est obligatoire.")

    if not clean_usage:
        raise ValueError("L'usage du fit est obligatoire.")

    ship_type_id = resolve_eve_inventory_type_id(parsed["ship_name"])

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fits (
                    guild_id,
                    name,
                    ship_name,
                    ship_type_id,
                    usage,
                    eft_text,
                    notes,
                    status,
                    created_by_discord_user_id,
                    created_at,
                    updated_at,
                    technical_snapshot,
                    technical_snapshot_version,
                    technical_snapshot_updated_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    'proposed', %s, NOW(), NOW()
                )
                RETURNING fit_id;
                """,
                (
                    str(guild_id),
                    clean_name,
                    parsed["ship_name"],
                    ship_type_id,
                    clean_usage,
                    parsed["normalized_eft"],
                    clean_notes,
                    str(discord_user_id),
                ),
            )

            fit_id = cur.fetchone()[0]

        conn.commit()

    return {
        "fit_id": int(fit_id),
        "name": clean_name,
        "ship_name": parsed["ship_name"],
        "ship_type_id": ship_type_id,
        "usage": clean_usage,
        "notes": clean_notes,
        "status": "proposed",
    }


def parse_fit_reference(value):
    """Accept 1, "1", "FREE-0001", "free0001" or "FREE 0001"."""

    text = str(value or "").strip().upper()

    if not text:
        raise ValueError("Identifiant de fit manquant.")

    compact = text.replace("-", "").replace(" ", "")

    if compact.startswith("FREE"):
        compact = compact[4:]

    if not compact.isdigit():
        raise ValueError("Identifiant de fit invalide. Utilise par exemple FREE-0001.")

    fit_id = int(compact)

    if fit_id < 1:
        raise ValueError("Identifiant de fit invalide.")

    return fit_id


def format_fit_reference(fit_id):
    return f"FREE-{int(fit_id):04d}"


def get_fit(guild_id, fit_id):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    fit_id,
                    guild_id,
                    name,
                    ship_name,
                    ship_type_id,
                    usage,
                    eft_text,
                    notes,
                    status,
                    created_by_discord_user_id,
                    created_at,
                    updated_at
                FROM fits
                WHERE guild_id = %s
                AND fit_id = %s
                LIMIT 1;
                """,
                (str(guild_id), int(fit_id)),
            )
            row = cur.fetchone()

    if not row:
        return None

    keys = (
        "fit_id", "guild_id", "name", "ship_name", "ship_type_id",
        "usage", "eft_text", "notes", "status",
        "created_by_discord_user_id", "created_at", "updated_at",
        "technical_snapshot", "technical_snapshot_version",
        "technical_snapshot_updated_at",
    )
    return dict(zip(keys, row))


def list_fits(guild_id, limit=50):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    fit_id,
                    name,
                    ship_name,
                    usage,
                    status,
                    created_by_discord_user_id,
                    created_at
                FROM fits
                WHERE guild_id = %s
                ORDER BY fit_id DESC
                LIMIT %s;
                """,
                (str(guild_id), int(limit)),
            )
            rows = cur.fetchall()

    return [
        {
            "fit_id": row[0],
            "name": row[1],
            "ship_name": row[2],
            "usage": row[3],
            "status": row[4],
            "created_by_discord_user_id": row[5],
            "created_at": row[6],
        }
        for row in rows
    ]


def ensure_fit_ship_type_id(fit):
    if not fit or fit.get("ship_type_id"):
        return fit

    type_id = resolve_eve_inventory_type_id(fit.get("ship_name"))

    if not type_id:
        return fit

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE fits
                SET ship_type_id = %s,
                    updated_at = NOW()
                WHERE guild_id = %s
                AND fit_id = %s;
                """,
                (int(type_id), str(fit["guild_id"]), int(fit["fit_id"])),
            )
        conn.commit()

    fit["ship_type_id"] = int(type_id)
    return fit


def fit_status_label(status):
    labels = {
        "proposed": "⚪ PROPOSÉ",
        "approved": "🟢 FREEBORN APPROVED",
        "rejected": "🔴 REFUSÉ",
        "archived": "⚫ ARCHIVÉ",
    }
    return labels.get(str(status or "").lower(), str(status or "INCONNU").upper())


def fit_embed_color(status):
    colors = {
        "proposed": 0xD6A84B,
        "approved": 0x78C94A,
        "rejected": 0xC94A4A,
        "archived": 0x666666,
    }
    return colors.get(str(status or "").lower(), 0x149CFF)


def build_fit_embed(fit):
    fit = ensure_fit_ship_type_id(fit)
    notes = str(fit.get("notes") or "Aucune note particulière.")[:1024]

    embed = {
        "title": f"🛡️ FREEBORN FITTINGS — {format_fit_reference(fit['fit_id'])}",
        "description": (
            f"## {fit['ship_name']}\n"
            f"**{fit['name']}**\n\n"
            f"Usage : **{fit['usage']}**"
        ),
        "color": fit_embed_color(fit.get("status")),
        "fields": [
            {
                "name": "Statut",
                "value": fit_status_label(fit.get("status")),
                "inline": True,
            },
            {
                "name": "Créateur",
                "value": f"<@{fit['created_by_discord_user_id']}>",
                "inline": True,
            },
            {
                "name": "Notes du créateur",
                "value": notes,
                "inline": False,
            },
        ],
        "footer": {
            "text": "Freeborn Legacy • Fittings • EFT conservé dans Freeborn",
        },
    }

    render_url = eve_type_render_url(fit.get("ship_type_id"), 512)
    if render_url:
        embed["thumbnail"] = {"url": render_url}

    return embed


def create_fit_web_token(guild_id, fit_id):
    return fit_web_serializer.dumps({
        "guild_id": str(guild_id),
        "fit_id": int(fit_id),
    })


def read_fit_web_token(token):
    payload = fit_web_serializer.loads(str(token or ""))
    return str(payload["guild_id"]), int(payload["fit_id"])


def build_fit_web_url(guild_id, fit_id):
    fit_ref = format_fit_reference(fit_id)
    token = create_fit_web_token(guild_id, fit_id)
    return f"{PUBLIC_BASE_URL}/fittings/{fit_ref}?token={token}"


def build_fit_components(fit_id, guild_id=None):
    components = [
        {
            "type": 2,
            "style": 2,
            "label": "Voir / copier l'EFT",
            "emoji": {"name": "📋"},
            "custom_id": f"fit_eft:{int(fit_id)}",
        },
    ]

    if guild_id:
        components.append({
            "type": 2,
            "style": 5,
            "label": "Fiche Web Freeborn",
            "emoji": {"name": "🌐"},
            "url": build_fit_web_url(guild_id, fit_id),
        })

    return [
        {
            "type": 1,
            "components": components,
        },
    ]


def build_fit_list_message(guild_id):
    fits = list_fits(guild_id, limit=50)

    if not fits:
        return (
            "🛡️ **FREEBORN FITTINGS**\n\n"
            "Aucun fitting n'est encore enregistré.\n"
            "Utilise **/fit-creer** pour proposer le premier fit."
        )

    lines = [
        "🛡️ **FREEBORN FITTINGS — Bibliothèque corporation**",
        "",
        f"Fittings enregistrés : **{len(fits)}**",
        "",
    ]

    for fit in fits:
        lines.append(
            f"**{format_fit_reference(fit['fit_id'])}** • **{fit['ship_name']}** "
            f"— {fit['name']} • `{fit['usage']}` • "
            f"{fit_status_label(fit['status'])}"
        )

    lines.extend([
        "",
        "Utilise **/fit-afficher ref:FREE-0001** pour ouvrir une fiche.",
    ])

    return "\n".join(lines)[:1900]


def create_fit_delete_token(fit_id, requester_user_id):
    payload = f"{int(fit_id)}:{requester_user_id}"
    return fit_delete_signer.sign(payload.encode()).decode()


def read_fit_delete_token(token):
    payload = fit_delete_signer.unsign(token, max_age=300).decode()
    fit_id, requester_user_id = payload.split(":", 1)
    return int(fit_id), requester_user_id


def can_delete_fit(data, fit):
    try:
        actor_user_id = str(data["member"]["user"]["id"])
    except (KeyError, TypeError):
        return False

    if actor_user_id == str(fit.get("created_by_discord_user_id")):
        return True

    return interaction_has_any_role(data, FITTING_MANAGER_ROLE_IDS)


def set_fit_status(guild_id, fit_id, status):
    allowed_statuses = {"proposed", "approved", "rejected", "archived"}
    clean_status = str(status or "").lower()

    if clean_status not in allowed_statuses:
        raise ValueError("Statut de fitting invalide.")

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE fits
                SET status = %s,
                    updated_at = NOW()
                WHERE guild_id = %s
                AND fit_id = %s
                RETURNING fit_id, name, ship_name, status;
                """,
                (clean_status, str(guild_id), int(fit_id)),
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        return None

    return {
        "fit_id": int(row[0]),
        "name": row[1],
        "ship_name": row[2],
        "status": row[3],
    }


def delete_fit(guild_id, fit_id):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM fits
                WHERE guild_id = %s
                AND fit_id = %s
                RETURNING fit_id, name, ship_name;
                """,
                (str(guild_id), int(fit_id)),
            )
            deleted = cur.fetchone()
        conn.commit()

    if not deleted:
        return None

    return {
        "fit_id": int(deleted[0]),
        "name": deleted[1],
        "ship_name": deleted[2],
    }


def modal_values(data):
    """Flatten Discord modal action rows into {custom_id: value}."""

    values = {}

    for row in (data.get("data") or {}).get("components", []):
        for component in row.get("components", []):
            custom_id = component.get("custom_id")

            if custom_id:
                values[str(custom_id)] = component.get("value", "")

    return values


def handle_fit_modal_submit(data):
    custom_id = str((data.get("data") or {}).get("custom_id") or "")

    if custom_id != "freeborn_fit_create_v1":
        return jsonify({
            "type": 4,
            "data": {
                "content": "❌ Formulaire Freeborn inconnu.",
                "flags": 64,
            },
        })

    try:
        discord_user_id = str(data["member"]["user"]["id"])
        guild_id = str(data["guild_id"])
    except (KeyError, TypeError):
        return jsonify({
            "type": 4,
            "data": {
                "content": "❌ Impossible d'identifier le membre ou le serveur.",
                "flags": 64,
            },
        })

    if guild_id != str(DISCORD_GUILD_ID):
        return jsonify({
            "type": 4,
            "data": {
                "content": "❌ Cette action est réservée à Freeborn Legacy.",
                "flags": 64,
            },
        })

    if not interaction_has_any_role(data, FITTING_CREATOR_ROLE_IDS):
        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    "⛔ **Accès refusé**\n\n"
                    "La création de fittings est réservée aux membres Freeborn."
                ),
                "flags": 64,
            },
        })

    values = modal_values(data)

    try:
        saved = save_fit_phase1(
            guild_id,
            discord_user_id,
            values.get("fit_name"),
            values.get("fit_usage"),
            values.get("fit_eft"),
            values.get("fit_notes"),
        )
    except ValueError as error:
        return jsonify({
            "type": 4,
            "data": {
                "content": f"❌ **Fit non enregistré**\n\n{error}",
                "flags": 64,
            },
        })
    except Exception as error:
        print("Freeborn Fittings save failed:", repr(error))
        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    "⚠️ **Erreur d'enregistrement**\n\n"
                    "Le fit n'a pas pu être enregistré dans la base."
                ),
                "flags": 64,
            },
        })

    fit = get_fit(guild_id, saved["fit_id"])

    return jsonify({
        "type": 4,
        "data": {
            "content": (
                f"✅ **{format_fit_reference(saved['fit_id'])} enregistré dans Freeborn.**\n"
                "La fiche ci-dessous peut maintenant être partagée avec la corporation."
            ),
            "embeds": [build_fit_embed(fit)],
            "components": build_fit_components(saved["fit_id"], guild_id),
            "flags": 64,
        },
    })


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

    normalized_skills = []

    for skill in data.get("skills", []) or []:

        try:

            normalized_skills.append({
                "skill_id":
                    int(skill["skill_id"]),

                "active_skill_level":
                    int(skill.get("active_skill_level", 0) or 0),

                "trained_skill_level":
                    int(skill.get("trained_skill_level", 0) or 0),

                "skillpoints_in_skill":
                    int(skill.get("skillpoints_in_skill", 0) or 0),
            })

        except (
            KeyError,
            TypeError,
            ValueError,
        ):

            continue

    return {
        "total_sp":
            int(data["total_sp"]),

        "unallocated_sp":
            int(data.get("unallocated_sp", 0) or 0),

        "trained_skills":
            len(normalized_skills),

        # Phase 4K foundation:
        # keep the individual skill levels so Freeborn Fittings can later
        # compare the corporate ALL-V reference with the real pilot.
        "skills":
            normalized_skills,
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


def get_eve_character_affiliation(
    character_id
):
    """Return ESI affiliation data for one character, or None on failure.

    The dedicated affiliation route is preferred for corporation membership
    checks because it is specifically intended to expose corporation/alliance
    affiliation. The caller keeps the regular character endpoint as fallback.
    """

    try:

        response = requests.post(
            f"{ESI_BASE_URL}/characters/affiliation/",
            json=[
                int(character_id),
            ],
            timeout=15,
        )

    except Exception as error:

        print(
            "ESI affiliation lookup error:",
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
            "ESI affiliation lookup failed:",
            character_id,
            response.status_code,
            response.text[:500],
        )

        return None

    try:

        data = response.json()

    except Exception as error:

        print(
            "ESI affiliation JSON decode failed:",
            character_id,
            repr(error),
        )

        return None

    if (
        not isinstance(data, list)
        or
        not data
    ):

        return None

    affiliation = data[0]

    if (
        str(affiliation.get("character_id"))
        !=
        str(int(character_id))
        or
        "corporation_id"
        not in affiliation
    ):

        return None

    return {
        "data":
            affiliation,

        "response":
            response,
    }


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


_discord_member_read_cache = {}
DISCORD_MEMBER_CACHE_TTL_SECONDS = 300


def get_discord_member(
    guild_id,
    user_id,
):
    """
    Read one Discord member with a short in-process cache.

    Fitting pages only need the creator display name. Re-querying Discord on
    every page refresh adds avoidable latency and does not need real-time
    precision.
    """
    guild_id = str(guild_id or "")
    user_id = str(user_id or "")

    if not guild_id or not user_id:
        return None

    key = (guild_id, user_id)
    now = time.monotonic()

    cached = _discord_member_read_cache.get(key)

    if cached:
        cached_at, payload = cached

        if (
            now - cached_at
            <= DISCORD_MEMBER_CACHE_TTL_SECONDS
        ):
            return payload

    response = requests.get(
        f"{DISCORD_API}/guilds/{guild_id}/members/{user_id}",
        headers={
            "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        },
        timeout=15,
    )

    if response.status_code != 200:
        return None

    payload = response.json()

    _discord_member_read_cache[key] = (
        now,
        payload,
    )

    return payload


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

        current_status_name = (
            str(current_status[0])
            if current_status
            else None
        )

        if current_status_name not in allowed_statuses:

            live_status = (
                infer_recruitment_status_from_interaction_roles(
                    data,
                    guild_id,
                )
            )

            if live_status in allowed_statuses:

                try:

                    set_member_status_v3(
                        guild_id,
                        actor_user_id,
                        live_status,
                        changed_by_discord_user_id=
                            actor_user_id,
                    )

                    current_status_name = live_status

                    add_audit_event_v3(
                        guild_id,
                        "member_status_reconciled_from_discord_roles",
                        target_discord_user_id=
                            actor_user_id,
                        actor_discord_user_id=
                            actor_user_id,
                    )

                except Exception as error:

                    print(
                        "Policy role/status reconciliation error:",
                        repr(error),
                    )

        if current_status_name not in allowed_statuses:

            return jsonify({
                "type":
                    4,

                "data": {
                    "content":
                        "ℹ️ Cette acceptation est réservée "
                        "aux **Candidats**, **Candidats Acceptés** "
                        "et **Membres** du parcours Freeborn.",

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

    # ========================================================
    # FREEBORN FITTINGS — COMPONENTS
    # ========================================================

    if custom_id.startswith("fit_eft:"):
        try:
            fit_id = int(custom_id.split(":", 1)[1])
            guild_id = str(data["guild_id"])
        except (ValueError, KeyError, TypeError):
            return jsonify({"type": 4, "data": {"content": "❌ Fit invalide.", "flags": 64}})

        fit = get_fit(guild_id, fit_id)
        if not fit:
            return jsonify({"type": 4, "data": {"content": "❌ Ce fit n'existe plus dans Freeborn.", "flags": 64}})

        if not interaction_has_any_role(data, FITTING_CREATOR_ROLE_IDS):
            return jsonify({"type": 4, "data": {"content": "⛔ Accès réservé aux membres Freeborn.", "flags": 64}})

        eft_text = str(fit.get("eft_text") or "")
        safe_eft = eft_text[:1800]
        suffix = "\n… *(EFT tronqué pour Discord)*" if len(eft_text) > 1800 else ""

        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    f"📋 **EFT — {format_fit_reference(fit_id)} • {fit['ship_name']}**\n"
                    f"```\n{safe_eft}\n```{suffix}"
                ),
                "flags": 64,
            },
        })

    if custom_id.startswith("fit_del_yes:") or custom_id.startswith("fit_del_no:"):
        try:
            actor_user_id = str(data["member"]["user"]["id"])
            guild_id = str(data["guild_id"])
            token = custom_id.split(":", 1)[1]
            fit_id, requester_user_id = read_fit_delete_token(token)
        except SignatureExpired:
            return jsonify({"type": 7, "data": {"content": "⌛ **Confirmation expirée**\n\nAucun fit n'a été supprimé.", "components": []}})
        except (BadSignature, ValueError, KeyError, TypeError):
            return jsonify({"type": 7, "data": {"content": "⛔ **Confirmation invalide**\n\nAucun fit n'a été supprimé.", "components": []}})

        if actor_user_id != requester_user_id:
            return jsonify({"type": 4, "data": {"content": "⛔ Cette confirmation ne t'appartient pas.", "flags": 64}})

        fit = get_fit(guild_id, fit_id)
        if not fit:
            return jsonify({"type": 7, "data": {"content": "ℹ️ Ce fit n'existe déjà plus dans Freeborn.", "components": []}})

        if not can_delete_fit(data, fit):
            return jsonify({"type": 4, "data": {"content": "⛔ Tu n'as plus la permission de supprimer ce fit.", "flags": 64}})

        if custom_id.startswith("fit_del_no:"):
            return jsonify({"type": 7, "data": {"content": "🛡️ **Suppression annulée**\n\nLe fit reste enregistré dans Freeborn.", "components": []}})

        deleted = delete_fit(guild_id, fit_id)
        if not deleted:
            return jsonify({"type": 7, "data": {"content": "ℹ️ Ce fit n'existe déjà plus dans Freeborn.", "components": []}})

        return jsonify({
            "type": 7,
            "data": {
                "content": (
                    f"🗑️ **{format_fit_reference(fit_id)} supprimé définitivement**\n\n"
                    f"**{deleted['ship_name']} — {deleted['name']}** a été retiré de Neon.\n"
                    "Les éventuels anciens messages Discord déjà publiés ne constituent pas la base de données."
                ),
                "components": [],
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
# FREEBORN FITTINGS — WEB CARD PHASE 4A
# ============================================================

def parse_eft_web_sections(eft_text):
    """Parse standard EFT block order for the corporate Web card."""
    text = str(eft_text or "").replace("\r\n", "\n").strip()
    if not text:
        return {"low": [], "mid": [], "high": [], "rigs": [], "extras": []}
    lines = text.split("\n")
    if lines and lines[0].strip().startswith("["):
        lines = lines[1:]
    blocks, current = [], []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        blocks.append(current)
    sections = {"low": [], "mid": [], "high": [], "rigs": [], "extras": []}
    ordered = ["low", "mid", "high", "rigs"]
    for index, block in enumerate(blocks):
        if index < len(ordered):
            sections[ordered[index]] = block
        else:
            sections["extras"].extend(block)
    return sections


def parse_eft_display_quantity(line):
    """
    Split the standard EFT trailing quantity suffix.

    Example:
        "Legion Mjolnir Auto-Targeting Cruise Missile x2000"
        -> ("Legion Mjolnir Auto-Targeting Cruise Missile", 2000)
    """
    clean = str(line or "").strip()

    if not clean:
        return "", 0

    match = re.match(
        r"^(.*?)\s+x(\d+)\s*$",
        clean,
        flags=re.IGNORECASE,
    )

    if not match:
        return clean, 1

    return match.group(1).strip(), int(match.group(2))


def normalize_eft_item_name(line):
    """Return the inventory type name represented by one EFT line."""
    clean = str(line or "").strip()
    if not clean:
        return ""

    # Fitted charges/scripts follow the module after a comma. The icon we
    # want for the slot row is the fitted module itself.
    clean = clean.split(",", 1)[0].strip()

    # Cargo/drone EFT exports may append quantities as `x1234`.
    clean = re.sub(r"\s+x\d+$", "", clean, flags=re.IGNORECASE).strip()
    return clean


_eve_inventory_batch_id_cache = {}
_eve_inventory_name_id_cache = {}


def resolve_eve_inventory_type_ids(type_names):
    """
    Resolve exact EVE inventory names, requesting only names not cached yet.
    """
    names = []
    seen = set()

    for value in type_names:
        clean = normalize_eft_item_name(value)
        key = clean.casefold()

        if clean and key not in seen:
            names.append(clean)
            seen.add(key)

    if not names:
        return {}

    result = {}
    unresolved = []

    for name in names:
        key = name.casefold()

        if key in _eve_inventory_name_id_cache:
            cached = _eve_inventory_name_id_cache[key]
            if cached is not None:
                result[key] = int(cached)
        else:
            unresolved.append(name)

    if not unresolved:
        return result

    cache_key = tuple(
        sorted(
            value.casefold()
            for value in unresolved
        )
    )

    cached_batch = _eve_inventory_batch_id_cache.get(
        cache_key
    )

    if cached_batch is not None:
        result.update(cached_batch)
        return dict(result)

    try:
        response = requests.post(
            f"{ESI_BASE_URL}/universe/ids/",
            json=unresolved,
            headers={
                "User-Agent": "Freeborn/3.0 Freeborn-Legacy-Discord-Bot",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()

        resolved = {
            str(item.get("name", "")).casefold(): int(item["id"])
            for item in payload.get("inventory_types", [])
            if item.get("name") and item.get("id")
        }

        for name in unresolved:
            key = name.casefold()
            value = resolved.get(key)
            _eve_inventory_name_id_cache[key] = value

        _eve_inventory_batch_id_cache[
            cache_key
        ] = dict(resolved)

        result.update(resolved)
        return dict(result)

    except Exception as error:
        print(
            "Freeborn Fittings ESI batch type resolution failed:",
            repr(error),
        )
        return dict(result)


def eve_type_icon_url(type_id, size=64):
    if not type_id:
        return None
    return (
        f"https://images.evetech.net/types/{int(type_id)}/icon"
        f"?size={int(size)}&tenant=tranquility"
    )


# ============================================================
# FREEBORN FITTINGS — PHASE 4J DOGMA TELEMETRY
# ============================================================

# Core Dogma attribute IDs used by EVE fitting calculations.
# These four values are stable legacy Dogma identifiers:
#   11 = powerOutput
#   30 = power (module powergrid requirement)
#   48 = cpuOutput
#   50 = cpu (module CPU requirement)
DOGMA_POWER_OUTPUT = 11
DOGMA_POWER_NEED = 30
DOGMA_CPU_OUTPUT = 48
DOGMA_CPU_NEED = 50
# Ship capacitor telemetry (Dogma): 482 = capacitorCapacity, 55 = rechargeRate (ms).
DOGMA_CAPACITOR_CAPACITY = 482
DOGMA_CAPACITOR_RECHARGE_TIME = 55
# Active module capacitor telemetry.
# 6 = capacitorNeed (GJ per activation)
# 73 = duration (milliseconds per activation cycle)
DOGMA_CAPACITOR_NEED = 6
DOGMA_DURATION = 73

_eve_type_dogma_cache = {}
_eve_dogma_attribute_metadata_cache = {}
_eve_dogma_named_lookup_cache = {}

_eve_type_category_cache = {}
_eve_group_category_cache = {}
_eve_type_metadata_cache = {}
_eve_group_metadata_cache = {}

# EVE inventory category 18 = Drone.
EVE_CATEGORY_DRONE = 18


def get_eve_type_metadata(type_id):
    """
    Return the public ESI metadata for one inventory type.

    Cached in-process because the same type is commonly used several times
    while one fitting page is rendered.
    """
    if not type_id:
        return {}

    type_id = int(type_id)

    if type_id in _eve_type_metadata_cache:
        return _eve_type_metadata_cache[type_id]

    try:
        response = requests.get(
            f"{ESI_BASE_URL}/universe/types/{type_id}/",
            params={"datasource": "tranquility"},
            headers={
                "User-Agent": "Freeborn/3.0 Freeborn-Legacy-Discord-Bot",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json() or {}
        _eve_type_metadata_cache[type_id] = payload

        dogma = {}
        for row in payload.get(
            "dogma_attributes",
            [],
        ) or []:
            attribute_id = row.get(
                "attribute_id"
            )
            value = row.get(
                "value"
            )

            if (
                attribute_id is None
                or value is None
            ):
                continue

            try:
                dogma[
                    int(attribute_id)
                ] = float(value)
            except (TypeError, ValueError):
                continue

        if dogma:
            _eve_type_dogma_cache[
                type_id
            ] = dogma

        return payload

    except Exception as error:
        print(
            "Freeborn Fittings ESI type metadata lookup failed:",
            type_id,
            repr(error),
        )
        return {}


def get_eve_group_metadata(group_id):
    """Return one EVE inventory group metadata payload with process caching."""
    if not group_id:
        return {}

    group_id = int(group_id)

    if group_id in _eve_group_metadata_cache:
        return _eve_group_metadata_cache[group_id]

    try:
        response = requests.get(
            f"{ESI_BASE_URL}/universe/groups/{group_id}/",
            params={"datasource": "tranquility"},
            headers={
                "User-Agent": "Freeborn/3.0 Freeborn-Legacy-Discord-Bot",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json() or {}
        _eve_group_metadata_cache[group_id] = payload
        return payload

    except Exception as error:
        print(
            "Freeborn Fittings ESI group metadata lookup failed:",
            group_id,
            repr(error),
        )
        return {}


def prefetch_eve_static_type_data(
    type_ids,
    *,
    max_workers=8,
):
    """
    Warm EVE static type/group payloads concurrently.

    This converts the old sequential cold-load pattern into two parallel waves:
    inventory types first, referenced groups second.
    """
    type_ids = sorted({
        int(type_id)
        for type_id in type_ids
        if type_id
    })

    missing_types = [
        type_id
        for type_id in type_ids
        if type_id not in _eve_type_metadata_cache
    ]

    if missing_types:
        workers = min(
            max(1, int(max_workers)),
            len(missing_types),
        )

        with ThreadPoolExecutor(
            max_workers=workers
        ) as executor:
            futures = [
                executor.submit(
                    get_eve_type_metadata,
                    type_id,
                )
                for type_id in missing_types
            ]

            for future in as_completed(
                futures
            ):
                try:
                    future.result()
                except Exception:
                    pass

    group_ids = set()

    for type_id in type_ids:
        payload = _eve_type_metadata_cache.get(
            type_id,
            {},
        )
        group_id = payload.get(
            "group_id"
        )

        if group_id:
            try:
                group_ids.add(int(group_id))
            except (TypeError, ValueError):
                pass

    missing_groups = [
        group_id
        for group_id in sorted(group_ids)
        if group_id not in _eve_group_metadata_cache
    ]

    if missing_groups:
        workers = min(
            max(1, int(max_workers)),
            len(missing_groups),
        )

        with ThreadPoolExecutor(
            max_workers=workers
        ) as executor:
            futures = [
                executor.submit(
                    get_eve_group_metadata,
                    group_id,
                )
                for group_id in missing_groups
            ]

            for future in as_completed(
                futures
            ):
                try:
                    future.result()
                except Exception:
                    pass


def get_eve_type_group_name(type_id):
    """
    Resolve one inventory type's public group name.

    Phase 4O-B uses this only as a conservative classifier for the two
    universal weapon fitting skills. The future SDE Dogma layer will replace
    this classifier with modifierInfo-driven rules.
    """
    type_payload = get_eve_type_metadata(type_id)
    group_id = type_payload.get("group_id")

    if not group_id:
        return ""

    group_payload = get_eve_group_metadata(group_id)

    return str(
        group_payload.get("name")
        or ""
    ).strip()


def freeborn_is_weapon_fitting_group(type_id):
    """
    Conservative launcher/turret/smartbomb classifier for 4O-B.

    Weapon Upgrades affects CPU use of weapon turrets, launchers and
    smartbombs; Advanced Weapon Upgrades affects PG use of turrets/launchers.
    Group-name matching is temporary and intentionally narrow: unknown
    modules are left untouched rather than receiving a guessed modifier.
    """
    name = get_eve_type_group_name(type_id).casefold()

    if not name:
        return False

    keywords = (
        "launcher",
        "turret",
        "smartbomb",
    )

    return any(
        keyword in name
        for keyword in keywords
    )


def get_eve_group_category_id(group_id):
    """Resolve category_id from the shared cached group metadata payload."""
    if not group_id:
        return None

    group_id = int(group_id)

    if group_id in _eve_group_category_cache:
        return _eve_group_category_cache[group_id]

    payload = get_eve_group_metadata(
        group_id
    )
    category_id = payload.get(
        "category_id"
    )

    if category_id is not None:
        try:
            category_id = int(category_id)
        except (TypeError, ValueError):
            category_id = None

    _eve_group_category_cache[
        group_id
    ] = category_id

    return category_id


def get_eve_type_category_id(type_id):
    """Resolve an inventory type's category_id through public ESI."""
    if not type_id:
        return None

    type_id = int(type_id)

    if type_id in _eve_type_category_cache:
        return _eve_type_category_cache[type_id]

    try:
        payload = get_eve_type_metadata(type_id)
        group_id = payload.get("group_id")
        category_id = get_eve_group_category_id(group_id)

        _eve_type_category_cache[type_id] = category_id
        return category_id

    except Exception as error:
        print(
            "Freeborn Fittings ESI type category lookup failed:",
            type_id,
            repr(error),
        )
        return None


def split_eft_drone_and_cargo(extras, type_ids):
    """
    Separate post-rig EFT contents into Drone Bay and Cargo Bay.

    Classification uses EVE inventory metadata, so sentry drones and other
    drone families do not depend on fragile name heuristics. Unknown types
    fall back to Cargo Bay so no item disappears from the fitting.
    """
    drones = []
    cargo = []

    for line in extras or []:
        item_name = normalize_eft_item_name(line)
        type_id = type_ids.get(item_name.casefold())
        category_id = get_eve_type_category_id(type_id)

        if category_id == EVE_CATEGORY_DRONE:
            drones.append(line)
        else:
            cargo.append(line)

    return drones, cargo



def get_eve_dogma_attribute_metadata(attribute_id):
    """
    Return public metadata for one Dogma attribute.

    ESI source:
        /dogma/attributes/{attribute_id}/

    Cached in-process because one fitting can expose many repeated attributes.
    """
    if attribute_id is None:
        return {}

    attribute_id = int(attribute_id)

    if attribute_id in _eve_dogma_attribute_metadata_cache:
        return _eve_dogma_attribute_metadata_cache[attribute_id]

    try:
        response = requests.get(
            f"{ESI_BASE_URL}/dogma/attributes/{attribute_id}/",
            params={"datasource": "tranquility"},
            headers={
                "User-Agent": "Freeborn/3.0 Freeborn-Legacy-Discord-Bot",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json() or {}

        _eve_dogma_attribute_metadata_cache[attribute_id] = payload
        return payload

    except Exception as error:
        print(
            "Freeborn Fittings ESI Dogma attribute lookup failed:",
            attribute_id,
            repr(error),
        )
        return {}


def freeborn_dogma_attribute_label(attribute_id):
    """Human-readable normalized Dogma attribute label."""
    metadata = get_eve_dogma_attribute_metadata(attribute_id)

    parts = [
        metadata.get("name"),
        metadata.get("display_name"),
        metadata.get("description"),
    ]

    return " ".join(
        str(part)
        for part in parts
        if part
    ).casefold()


def find_capacitor_transfer_amount_attribute(type_id):
    """
    Find a likely capacitor/energy transfer amount on one module by inspecting
    the *actual* Dogma attribute metadata rather than hard-coding a module ID.

    Returns:
        {
            "attribute_id": ...,
            "value": ...,
            "name": ...,
            "display_name": ...,
            "score": ...
        }
        or None.

    The scoring is deliberately conservative. An uncertain match is rejected.
    """
    dogma = get_eve_type_dogma(type_id)

    if not dogma:
        return None

    candidates = []

    for attribute_id, value in dogma.items():
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            continue

        if numeric_value <= 0:
            continue

        metadata = get_eve_dogma_attribute_metadata(attribute_id)
        name = str(metadata.get("name") or "")
        display_name = str(metadata.get("display_name") or "")
        description = str(metadata.get("description") or "")
        haystack = " ".join(
            [name, display_name, description]
        ).casefold()

        score = 0

        # Strong positive signals.
        if "powertransferamount" in haystack:
            score += 12
        if "energytransferamount" in haystack:
            score += 12
        if "capacitortransferamount" in haystack:
            score += 12

        if "transfer" in haystack:
            score += 5
        if "amount" in haystack:
            score += 3
        if "capacitor" in haystack:
            score += 4
        if "energy" in haystack:
            score += 3
        if "power" in haystack:
            score += 2

        # Reject obvious unrelated attributes.
        for token in (
            "range",
            "optimal",
            "falloff",
            "capacitor need",
            "capacitorneed",
            "duration",
            "cpu",
            "powergrid",
            "mass",
            "volume",
            "radius",
            "bonus",
            "multiplier",
            "resonance",
            "damage",
        ):
            if token in haystack:
                score -= 8

        candidates.append({
            "attribute_id": int(attribute_id),
            "value": numeric_value,
            "name": name,
            "display_name": display_name,
            "score": score,
        })

    if not candidates:
        return None

    candidates.sort(
        key=lambda row: (
            row["score"],
            row["value"],
        ),
        reverse=True,
    )

    best = candidates[0]

    # Require meaningful confidence: do not guess from a generic positive attr.
    if best["score"] < 9:
        return None

    return best


def build_conditional_capacitor_source_dogma_probe(
    eft_sections,
    type_ids,
    capacitor_activity_audit,
):
    """
    Probe the fitted conditional capacitor sources (Nosferatu family).

    The transfer is shown as a *maximum theoretical source* and remains
    excluded from the stability calculation until target-dependent activation
    conditions are modeled.
    """
    source_rows = (
        capacitor_activity_audit.get(
            "conditional_sources",
            []
        )
        or []
    )

    results = []

    for source in source_rows:
        name = str(source.get("name") or "")
        quantity = int(source.get("quantity", 1) or 1)
        type_id = type_ids.get(name.casefold())

        row = {
            "name": name,
            "quantity": quantity,
            "type_id": type_id,
            "transfer_gj_cycle": None,
            "cycle_seconds": None,
            "max_transfer_gjs": None,
            "attribute_name": None,
            "resolved": False,
        }

        if not type_id:
            results.append(row)
            continue

        dogma = get_eve_type_dogma(type_id)
        duration_ms = dogma.get(DOGMA_DURATION)
        transfer_attr = find_capacitor_transfer_amount_attribute(
            type_id
        )

        if (
            transfer_attr
            and duration_ms is not None
            and float(duration_ms) > 0
        ):
            per_cycle = float(transfer_attr["value"])
            cycle_seconds = float(duration_ms) / 1000.0

            row.update({
                "transfer_gj_cycle": per_cycle,
                "cycle_seconds": cycle_seconds,
                "max_transfer_gjs": (
                    per_cycle
                    / cycle_seconds
                    * quantity
                ),
                "attribute_name": (
                    transfer_attr.get("display_name")
                    or transfer_attr.get("name")
                    or f'attribute {transfer_attr["attribute_id"]}'
                ),
                "resolved": True,
            })

        results.append(row)

    return results


def format_conditional_source_dogma_probe(rows):
    """
    Render an explicit technical proof of what the Dogma probe resolved.
    """
    if not rows:
        return "Aucune source conditionnelle."

    output = []

    for row in rows:
        safe_name = escape(
            str(
                row.get("name")
                or "Module inconnu"
            )
        )
        quantity = int(
            row.get("quantity", 1)
            or 1
        )

        if not row.get("resolved"):
            output.append(
                f"{quantity}× {safe_name} — attribut de transfert non résolu"
            )
            continue

        attr_name = escape(
            str(
                row.get("attribute_name")
                or "Dogma"
            )
        )

        output.append(
            f"{quantity}× {safe_name} — "
            f"{row['transfer_gj_cycle']:.2f} GJ/cycle • "
            f"{row['cycle_seconds']:.2f} s • "
            f"maximum théorique {row['max_transfer_gjs']:.2f} GJ/s "
            f"[{attr_name}]"
        )

    return "<br>".join(output)



def get_eve_type_dogma(type_id):
    """
    Return one inventory type's Dogma attribute map from public ESI.

    Result format:
        {
            attribute_id: float_value,
            ...
        }

    A small in-process cache avoids repeating the same public ESI request
    every time one fitting page is refreshed.
    """
    if not type_id:
        return {}

    type_id = int(type_id)

    if type_id in _eve_type_dogma_cache:
        return _eve_type_dogma_cache[type_id]

    cached_payload = _eve_type_metadata_cache.get(
        type_id
    )

    if cached_payload:
        dogma = {}

        for row in cached_payload.get(
            "dogma_attributes",
            [],
        ) or []:
            attribute_id = row.get(
                "attribute_id"
            )
            value = row.get(
                "value"
            )

            if (
                attribute_id is None
                or value is None
            ):
                continue

            try:
                dogma[
                    int(attribute_id)
                ] = float(value)
            except (TypeError, ValueError):
                continue

        _eve_type_dogma_cache[
            type_id
        ] = dogma

        return dogma

    try:
        response = requests.get(
            f"{ESI_BASE_URL}/universe/types/{type_id}/",
            params={"datasource": "tranquility"},
            headers={
                "User-Agent": "Freeborn/3.0 Freeborn-Legacy-Discord-Bot",
            },
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()

        if type_id not in _eve_type_metadata_cache:
            _eve_type_metadata_cache[
                type_id
            ] = payload

        dogma = {}
        for row in payload.get("dogma_attributes", []) or []:
            attribute_id = row.get("attribute_id")
            value = row.get("value")
            if attribute_id is None or value is None:
                continue
            try:
                dogma[int(attribute_id)] = float(value)
            except (TypeError, ValueError):
                continue

        _eve_type_dogma_cache[type_id] = dogma
        return dogma

    except Exception as error:
        print(
            "Freeborn Fittings ESI Dogma type lookup failed:",
            type_id,
            repr(error),
        )
        return {}


def _eft_fitted_module_counts(eft_sections, type_ids):
    """
    Return {type_id: quantity} for fitted modules only.

    Cargo, drones, charges and scripts are intentionally excluded from
    fitting-resource usage. Low/Mid/High/Rig sections are included.
    """
    counts = {}

    fitted_lines = (
        eft_sections.get("low", [])
        + eft_sections.get("mid", [])
        + eft_sections.get("high", [])
        + eft_sections.get("rigs", [])
    )

    for line in fitted_lines:
        item_name = normalize_eft_item_name(line)
        type_id = type_ids.get(item_name.casefold())

        if not type_id:
            continue

        type_id = int(type_id)
        counts[type_id] = counts.get(type_id, 0) + 1

    return counts



def find_dogma_attribute_by_names(
    type_id,
    exact_names=(),
    contains_names=(),
):
    """
    Resolve one Dogma attribute from the actual type attributes + public ESI
    attribute metadata.

    Exact normalized metadata-name matches win. contains_names are fallback
    probes only; no guessed numeric attribute IDs are required.
    """
    cache_key = (
        int(type_id or 0),
        tuple(sorted(
            str(name).strip().casefold()
            for name in exact_names
            if str(name).strip()
        )),
        tuple(sorted(
            str(name).strip().casefold()
            for name in contains_names
            if str(name).strip()
        )),
    )

    if cache_key in _eve_dogma_named_lookup_cache:
        cached = _eve_dogma_named_lookup_cache[cache_key]
        return dict(cached) if isinstance(cached, dict) else None

    dogma = get_eve_type_dogma(type_id)

    if not dogma:
        _eve_dogma_named_lookup_cache[cache_key] = None
        return None

    exact = {
        str(name).strip().casefold()
        for name in exact_names
        if str(name).strip()
    }
    contains = tuple(
        str(name).strip().casefold()
        for name in contains_names
        if str(name).strip()
    )

    fallback = []

    for attribute_id, value in dogma.items():
        metadata = get_eve_dogma_attribute_metadata(
            attribute_id
        )

        name = str(
            metadata.get("name")
            or ""
        ).strip()
        display_name = str(
            metadata.get("display_name")
            or ""
        ).strip()

        normalized_name = name.casefold()
        normalized_display = display_name.casefold()

        if (
            normalized_name in exact
            or normalized_display in exact
        ):
            result = {
                "attribute_id": int(attribute_id),
                "name": name,
                "display_name": display_name,
                "value": float(value),
            }
            _eve_dogma_named_lookup_cache[cache_key] = dict(result)
            return result

        haystack = (
            normalized_name
            + " "
            + normalized_display
        )

        if (
            contains
            and any(
                token in haystack
                for token in contains
            )
        ):
            fallback.append({
                "attribute_id": int(attribute_id),
                "name": name,
                "display_name": display_name,
                "value": float(value),
            })

    if len(fallback) == 1:
        result = fallback[0]
        _eve_dogma_named_lookup_cache[cache_key] = dict(result)
        return result

    _eve_dogma_named_lookup_cache[cache_key] = None
    return None


def get_ship_base_max_velocity(ship_type_id):
    """
    Return the hull's raw maxVelocity Dogma attribute in m/s.
    """
    row = find_dogma_attribute_by_names(
        ship_type_id,
        exact_names=(
            "maxVelocity",
            "Max Velocity",
        ),
    )

    return (
        float(row["value"])
        if row
        else None
    )



def get_ship_base_mass(ship_type_id):
    """Return the hull's raw mass Dogma attribute in kg."""
    row = find_dogma_attribute_by_names(
        ship_type_id,
        exact_names=(
            "mass",
            "Mass",
        ),
    )

    return (
        float(row["value"])
        if row
        else None
    )


def fitted_mass_additions(
    eft_sections,
    type_ids,
):
    """
    Sum positive Dogma massAddition values from fitted modules.

    This covers propulsion mass and common fitted mass additions without
    guessing from item names.
    """
    total = 0.0
    rows = []

    counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    for type_id, quantity in counts.items():
        mass_row = find_dogma_attribute_by_names(
            type_id,
            exact_names=(
                "massAddition",
                "Mass Addition",
            ),
            contains_names=(
                "mass addition",
            ),
        )

        if not mass_row:
            continue

        value = float(
            mass_row["value"]
        )

        if value <= 0:
            continue

        contribution = (
            value
            * int(quantity)
        )

        total += contribution

        metadata = get_eve_type_metadata(
            type_id
        )

        rows.append({
            "type_id": int(type_id),
            "name": str(
                metadata.get("name")
                or f"Type {type_id}"
            ),
            "quantity": int(quantity),
            "mass_addition_kg": value,
            "contribution_kg": contribution,
        })

    return {
        "total_kg": total,
        "rows": rows,
    }


def resolve_effective_propulsion_thrust(row):
    """
    Resolve propulsion thrust in Newtons without trusting a possibly scaled
    raw SDE/ESI thrust value blindly.

    For standard EVE propulsion size classes the canonical relationship is:
        effective thrust = 3 × massAddition

    Examples:
        500,000 kg   -> 1,500,000 N
        5,000,000 kg -> 15,000,000 N
        50,000,000 kg -> 150,000,000 N

    We retain the raw Dogma value and expose the scale ratio for audit.
    If massAddition is unavailable, raw thrust is used only as a fallback.
    """
    mass_addition = row.get("mass_addition")
    raw_thrust = row.get("thrust")

    canonical = None
    source = "unresolved"

    if mass_addition is not None and float(mass_addition) > 0:
        canonical = float(mass_addition) * 3.0
        source = "massAddition × 3"
    elif raw_thrust is not None and float(raw_thrust) > 0:
        canonical = float(raw_thrust)
        source = "raw Dogma fallback"

    ratio = None
    if (
        canonical is not None
        and canonical > 0
        and raw_thrust is not None
    ):
        ratio = float(raw_thrust) / canonical

    return {
        "effective_thrust_n": canonical,
        "raw_thrust": (
            float(raw_thrust)
            if raw_thrust is not None
            else None
        ),
        "raw_to_effective_ratio": ratio,
        "source": source,
    }


def effective_propulsion_thrust(row):
    """Compatibility wrapper retained for existing 4P-C call sites."""
    return resolve_effective_propulsion_thrust(
        row
    )["effective_thrust_n"]


def freeborn_propulsion_kind(
    type_id,
):
    """
    Resolve whether an EVE type is an Afterburner or Microwarpdrive.

    Do not depend on one metadata field only. EVE group naming can be broader
    than the marketed type name, so Freeborn checks type name, group name,
    then the actual propulsion Dogma signature.
    """
    metadata = get_eve_type_metadata(
        type_id
    )
    type_name = str(
        metadata.get("name")
        or ""
    ).strip()

    group_name = get_eve_type_group_name(
        type_id
    ).strip()

    haystack = (
        type_name
        + " "
        + group_name
    ).casefold()

    if (
        "microwarpdrive" in haystack
        or "micro warp drive" in haystack
        or "mwd" in haystack
    ):
        return "MWD"

    if "afterburner" in haystack:
        return "AB"

    # Final fallback: detect the characteristic propulsion attributes.
    speed_factor = find_dogma_attribute_by_names(
        type_id,
        exact_names=(
            "speedFactor",
            "Speed Factor",
            "maxVelocityBonus",
            "Maximum Velocity Bonus",
        ),
        contains_names=(
            "speed factor",
            "velocity bonus",
        ),
    )

    mass_addition = find_dogma_attribute_by_names(
        type_id,
        exact_names=(
            "massAddition",
            "Mass Addition",
        ),
        contains_names=(
            "mass addition",
        ),
    )

    thrust = find_dogma_attribute_by_names(
        type_id,
        exact_names=(
            "thrust",
            "Thrust",
        ),
        contains_names=(
            "thrust",
        ),
    )

    # Requiring at least two propulsion-specific attributes avoids treating
    # unrelated modules as prop mods.
    signature_count = sum(
        value is not None
        for value in (
            speed_factor,
            mass_addition,
            thrust,
        )
    )

    if signature_count >= 2:
        return "PROP"

    return None


def find_fitted_propulsion_modules(
    eft_sections,
    type_ids,
):
    """
    Find fitted propulsion modules and expose their actual Dogma attributes.

    4P-B fixes 4P-A's group-name-only classifier. Detection now uses:
      - type name;
      - group name;
      - Dogma propulsion signature.

    Active velocity remains deliberately unclaimed until the exact thrust /
    mass application is validated against EVE.
    """
    rows = []
    counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    for type_id, quantity in counts.items():
        kind = freeborn_propulsion_kind(
            type_id
        )

        if not kind:
            continue

        metadata = get_eve_type_metadata(
            type_id
        )

        speed_factor = find_dogma_attribute_by_names(
            type_id,
            exact_names=(
                "speedFactor",
                "Speed Factor",
                "maxVelocityBonus",
                "Maximum Velocity Bonus",
            ),
            contains_names=(
                "speed factor",
                "velocity bonus",
            ),
        )

        mass_addition = find_dogma_attribute_by_names(
            type_id,
            exact_names=(
                "massAddition",
                "Mass Addition",
            ),
            contains_names=(
                "mass addition",
            ),
        )

        thrust = find_dogma_attribute_by_names(
            type_id,
            exact_names=(
                "thrust",
                "Thrust",
            ),
            contains_names=(
                "thrust",
            ),
        )

        rows.append({
            "type_id": int(type_id),
            "name": str(
                metadata.get("name")
                or f"Type {type_id}"
            ),
            "quantity": int(quantity),
            "kind": kind,
            "group_name": get_eve_type_group_name(
                type_id
            ),
            "speed_factor": (
                speed_factor["value"]
                if speed_factor
                else None
            ),
            "speed_factor_attribute": (
                speed_factor.get("display_name")
                or speed_factor.get("name")
                if speed_factor
                else None
            ),
            "mass_addition": (
                mass_addition["value"]
                if mass_addition
                else None
            ),
            "mass_addition_attribute": (
                mass_addition.get("display_name")
                or mass_addition.get("name")
                if mass_addition
                else None
            ),
            "thrust": (
                thrust["value"]
                if thrust
                else None
            ),
            "thrust_attribute": (
                thrust.get("display_name")
                or thrust.get("name")
                if thrust
                else None
            ),
        })

    return rows


def calculate_skill_aware_velocity(
    ship_type_id,
    *,
    mode="all_v",
    skills_snapshot=None,
    eft_sections=None,
    type_ids=None,
):
    """
    Phase 4P-C velocity engine.

    OFF:
        hull maxVelocity × Navigation.

    ACTIVE AB/MWD:
        Voff × (
            1
            + effective_prop_bonus
            × effective_thrust / active_mass
        )

    effective_prop_bonus:
        speedFactor × Acceleration Control.

    active_mass:
        hull mass + positive fitted Dogma mass additions.

    Only the first fitted propulsion module is evaluated as active because
    EVE does not permit multiple propulsion modules to run simultaneously.
    """
    base_velocity = get_ship_base_max_velocity(
        ship_type_id
    )
    base_mass = get_ship_base_mass(
        ship_type_id
    )

    context = freeborn_fitting_skill_context(
        mode=mode,
        skills_snapshot=skills_snapshot,
    )

    navigation_level = (
        freeborn_context_named_skill_level(
            context,
            "Navigation",
        )
    )

    acceleration_control_level = (
        freeborn_context_named_skill_level(
            context,
            "Acceleration Control",
        )
    )

    velocity_off = (
        float(base_velocity)
        * (
            1.0
            + (0.05 * navigation_level)
        )
        if base_velocity is not None
        else None
    )

    propulsion_rows = []

    if (
        eft_sections is not None
        and type_ids is not None
    ):
        propulsion_rows = (
            find_fitted_propulsion_modules(
                eft_sections,
                type_ids,
            )
        )

    mass_audit = {
        "total_kg": 0.0,
        "rows": [],
    }

    if (
        eft_sections is not None
        and type_ids is not None
    ):
        mass_audit = fitted_mass_additions(
            eft_sections,
            type_ids,
        )

    active_mass = (
        float(base_mass)
        + float(
            mass_audit["total_kg"]
        )
        if base_mass is not None
        else None
    )

    active_velocity = None
    active_propulsion = None
    effective_bonus = None
    effective_thrust = None
    thrust_audit = {
        "effective_thrust_n": None,
        "raw_thrust": None,
        "raw_to_effective_ratio": None,
        "source": "unresolved",
    }

    if (
        velocity_off is not None
        and active_mass
        and active_mass > 0
        and propulsion_rows
    ):
        active_propulsion = propulsion_rows[0]

        speed_factor = active_propulsion.get(
            "speed_factor"
        )

        thrust_audit = (
            resolve_effective_propulsion_thrust(
                active_propulsion
            )
        )
        effective_thrust = thrust_audit[
            "effective_thrust_n"
        ]

        if (
            speed_factor is not None
            and effective_thrust is not None
        ):
            effective_bonus = (
                float(speed_factor)
                / 100.0
            ) * (
                1.0
                + (
                    0.05
                    * acceleration_control_level
                )
            )

            active_velocity = (
                float(velocity_off)
                * (
                    1.0
                    + (
                        effective_bonus
                        * float(effective_thrust)
                        / float(active_mass)
                    )
                )
            )

    return {
        "mode": context["mode"],
        "navigation_level": navigation_level,
        "acceleration_control_level": acceleration_control_level,
        "base_velocity_ms": base_velocity,
        "base_mass_kg": base_mass,
        "mass_addition_kg": mass_audit["total_kg"],
        "active_mass_kg": active_mass,
        "propulsion_off_velocity_ms": velocity_off,
        "propulsion_active_velocity_ms": active_velocity,
        "active_propulsion": active_propulsion,
        "propulsion_rows": propulsion_rows,
        "effective_propulsion_bonus": effective_bonus,
        "effective_thrust_n": effective_thrust,
        "raw_propulsion_thrust": thrust_audit[
            "raw_thrust"
        ],
        "raw_to_effective_thrust_ratio": thrust_audit[
            "raw_to_effective_ratio"
        ],
        "thrust_source": thrust_audit[
            "source"
        ],
    }



# ============================================================
# FREEBORN FITTINGS — DPS
# ============================================================
# DPS volontairement non calculé.
# Freeborn Fittings conserve l'EFT comme source et laisse au client EVE
# le calcul exact lié aux munitions, skills, implants, heat, boosts, etc.


def format_velocity(value):
    if value is None:
        return "—"

    value = float(value)

    if abs(value - round(value)) < 0.05:
        return (
            f"{int(round(value)):,} m/s"
            .replace(",", " ")
        )

    return (
        f"{value:,.1f} m/s"
        .replace(",", " ")
        .replace(".", ",")
    )


def format_propulsion_dogma_probe(rows):
    if not rows:
        return (
            "Aucun propulseur reconnu — anomalie de détection à investiguer"
        )

    parts = []

    for row in rows:
        details = []

        details.append(
            "type "
            + escape(
                str(
                    row.get("kind")
                    or "PROP"
                )
            )
        )

        group_name = str(
            row.get("group_name")
            or ""
        ).strip()

        if group_name:
            details.append(
                "groupe "
                + escape(group_name)
            )

        if row.get("speed_factor") is not None:
            label = escape(
                str(
                    row.get("speed_factor_attribute")
                    or "speedFactor"
                )
            )
            details.append(
                f"{label} "
                + f'{row["speed_factor"]:.2f}'
            )

        if row.get("mass_addition") is not None:
            label = escape(
                str(
                    row.get("mass_addition_attribute")
                    or "massAddition"
                )
            )
            details.append(
                f"{label} "
                + f'{row["mass_addition"]:,.0f} kg'
                .replace(",", " ")
            )

        if row.get("thrust") is not None:
            label = escape(
                str(
                    row.get("thrust_attribute")
                    or "thrust"
                )
            )
            details.append(
                f"{label} "
                + f'{row["thrust"]:,.0f}'
                .replace(",", " ")
            )

        parts.append(
            f'{int(row["quantity"])}× '
            + escape(row["name"])
            + " — "
            + " • ".join(details)
        )

    return "<br>".join(parts)




_freeborn_base_resource_cache = {}
_freeborn_base_capacitor_cache = {}
_freeborn_module_rows_cache = {}


def freeborn_static_fitting_cache_key(
    ship_type_id,
    eft_sections,
    type_ids,
):
    counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    return (
        int(ship_type_id or 0),
        tuple(sorted(
            (
                int(type_id),
                int(quantity),
            )
            for type_id, quantity
            in counts.items()
        )),
    )


def calculate_base_fitting_resources(
    ship_type_id,
    eft_sections,
    type_ids,
):
    """
    Calculate static/base CPU and Powergrid telemetry.

    This deliberately does NOT pretend to be a complete EVE Dogma engine.
    It uses the raw ship outputs and raw module fitting requirements exposed
    by ESI. Character skills, implants, fleet effects, modules that alter
    fitting resources, and other Dogma modifiers are not applied yet.

    Returning explicit completeness flags lets the Web UI distinguish a
    usable base figure from missing ESI data.
    """
    cache_key = freeborn_static_fitting_cache_key(
        ship_type_id,
        eft_sections,
        type_ids,
    )

    cached = _freeborn_base_resource_cache.get(cache_key)
    if cached is not None:
        return dict(cached)

    result = {
        "cpu_output": None,
        "cpu_used": 0.0,
        "cpu_complete": False,
        "power_output": None,
        "power_used": 0.0,
        "power_complete": False,
    }

    ship_dogma = get_eve_type_dogma(ship_type_id)

    if DOGMA_CPU_OUTPUT in ship_dogma:
        result["cpu_output"] = ship_dogma[DOGMA_CPU_OUTPUT]

    if DOGMA_POWER_OUTPUT in ship_dogma:
        result["power_output"] = ship_dogma[DOGMA_POWER_OUTPUT]

    module_counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    cpu_ok = result["cpu_output"] is not None
    power_ok = result["power_output"] is not None

    for type_id, quantity in module_counts.items():
        dogma = get_eve_type_dogma(type_id)

        # A module can legitimately have no CPU or PG requirement.
        # Missing Dogma entirely is treated as incomplete resolution.
        if not dogma:
            cpu_ok = False
            power_ok = False
            continue

        cpu_need = dogma.get(DOGMA_CPU_NEED, 0.0)
        power_need = dogma.get(DOGMA_POWER_NEED, 0.0)

        result["cpu_used"] += float(cpu_need) * int(quantity)
        result["power_used"] += float(power_need) * int(quantity)

    result["cpu_complete"] = cpu_ok
    result["power_complete"] = power_ok

    _freeborn_base_resource_cache[cache_key] = dict(result)
    return result



def calculate_base_capacitor_engine(
    ship_type_id,
    eft_sections,
    type_ids,
):
    """
    Phase 4O-F capacitor engine.

    This layer intentionally stays conservative. It calculates only values
    directly supported by public Dogma attributes:
      - base capacitor capacity;
      - base recharge time;
      - theoretical peak passive recharge (2.5 * capacity / recharge time);
      - capacitor drain of fitted modules exposing both capacitorNeed and
        duration.

    It does NOT yet claim final EVE stability when conditional capacitor
    warfare/injection, charges, scripts, overheating, implants, fleet effects,
    or uncovered modifier chains can alter the result.
    """
    cache_key = freeborn_static_fitting_cache_key(
        ship_type_id,
        eft_sections,
        type_ids,
    )

    cached = _freeborn_base_capacitor_cache.get(cache_key)
    if cached is not None:
        return dict(cached)

    result = {
        "capacity_gj": None,
        "recharge_seconds": None,
        "peak_recharge_gjs": None,
        "active_drain_gjs": 0.0,
        "net_peak_gjs": None,
        "complete": False,
        "consumer_count": 0,
        "unresolved_count": 0,
    }

    ship_dogma = get_eve_type_dogma(ship_type_id)
    if not ship_dogma:
        _freeborn_base_capacitor_cache[cache_key] = dict(result)
        return result

    capacity = ship_dogma.get(DOGMA_CAPACITOR_CAPACITY)
    recharge_ms = ship_dogma.get(DOGMA_CAPACITOR_RECHARGE_TIME)

    if capacity is None or recharge_ms in (None, 0):
        _freeborn_base_capacitor_cache[cache_key] = dict(result)
        return result

    capacity = float(capacity)
    recharge_seconds = float(recharge_ms) / 1000.0
    peak_recharge = (2.5 * capacity / recharge_seconds) if recharge_seconds > 0 else None

    result["capacity_gj"] = capacity
    result["recharge_seconds"] = recharge_seconds
    result["peak_recharge_gjs"] = peak_recharge

    module_counts = _eft_fitted_module_counts(eft_sections, type_ids)
    module_dogma_complete = True

    for type_id, quantity in module_counts.items():
        dogma = get_eve_type_dogma(type_id)
        if not dogma:
            module_dogma_complete = False
            result["unresolved_count"] += int(quantity)
            continue

        cap_need = dogma.get(DOGMA_CAPACITOR_NEED)
        duration_ms = dogma.get(DOGMA_DURATION)

        # No capacitorNeed means no directly measurable cyclic drain here.
        if cap_need is None or float(cap_need) <= 0:
            continue

        # A positive capacitorNeed without a usable duration cannot safely be
        # converted to GJ/s; mark the audit incomplete rather than guessing.
        if duration_ms is None or float(duration_ms) <= 0:
            module_dogma_complete = False
            result["unresolved_count"] += int(quantity)
            continue

        per_module_gjs = float(cap_need) / (float(duration_ms) / 1000.0)
        result["active_drain_gjs"] += per_module_gjs * int(quantity)
        result["consumer_count"] += int(quantity)

    if peak_recharge is not None:
        result["net_peak_gjs"] = peak_recharge - result["active_drain_gjs"]

    result["complete"] = module_dogma_complete
    _freeborn_base_capacitor_cache[cache_key] = dict(result)
    return result




_freeborn_skill_type_id_cache = {}


def freeborn_skill_type_id(skill_name):
    """
    Resolve an exact EVE skill typeID once per process through public ESI.
    This keeps the code independent from hard-coded skill typeIDs.
    """
    clean = str(skill_name or "").strip()

    if not clean:
        return None

    key = clean.casefold()

    if key in _freeborn_skill_type_id_cache:
        return _freeborn_skill_type_id_cache[key]

    type_id = resolve_eve_inventory_type_id(clean)
    _freeborn_skill_type_id_cache[key] = type_id
    return type_id


FREEBORN_FITTING_NAMED_SKILLS = (
    "Capacitor Management",
    "Capacitor Systems Operation",
    "High Speed Maneuvering",
    "Afterburner",
    "Shield Compensation",
    "Navigation",
    "Acceleration Control",
    "Controlled Bursts",
)


def prefetch_freeborn_fitting_skill_ids():
    unresolved = [
        name
        for name in FREEBORN_FITTING_NAMED_SKILLS
        if name.casefold() not in _freeborn_skill_type_id_cache
    ]

    if not unresolved:
        return

    resolved = resolve_eve_inventory_type_ids(
        unresolved
    )

    for name in unresolved:
        key = name.casefold()
        _freeborn_skill_type_id_cache[
            key
        ] = resolved.get(key)


def freeborn_context_named_skill_level(context, skill_name):
    """Resolve a named skill level for ALL V or a real ESI character."""
    if context.get("mode") == "all_v":
        return FREEBORN_ALL_V_LEVEL

    type_id = freeborn_skill_type_id(skill_name)

    if not type_id:
        return 0

    return freeborn_context_skill_level(
        context,
        type_id,
    )


def freeborn_capacitor_module_skill_modifier(
    type_id,
    context,
):
    """
    Return (cap_need_multiplier, duration_multiplier, rule_label).

    Phase 4O-H intentionally recognizes only well-defined, common fitting
    families. Unknown groups remain at 1.0 rather than receiving a guessed
    bonus. Full SDE modifierInfo coverage remains a later engine phase.
    """
    group_name = get_eve_type_group_name(type_id).casefold()

    cap_mult = 1.0
    duration_mult = 1.0
    rule = None

    if "microwarpdrive" in group_name:
        level = freeborn_context_named_skill_level(
            context,
            "High Speed Maneuvering",
        )
        cap_mult *= max(0.0, 1.0 - (0.05 * level))
        rule = f"High Speed Maneuvering {level}/5"

    elif "afterburner" in group_name:
        level = freeborn_context_named_skill_level(
            context,
            "Afterburner",
        )
        cap_mult *= max(0.0, 1.0 - (0.10 * level))
        duration_mult *= max(0.01, 1.0 - (0.05 * level))
        rule = f"Afterburner {level}/5"

    elif "shield booster" in group_name:
        level = freeborn_context_named_skill_level(
            context,
            "Shield Compensation",
        )
        cap_mult *= max(0.0, 1.0 - (0.02 * level))
        rule = f"Shield Compensation {level}/5"

    elif "turret" in group_name:
        level = freeborn_context_named_skill_level(
            context,
            "Controlled Bursts",
        )
        cap_mult *= max(0.0, 1.0 - (0.05 * level))
        rule = f"Controlled Bursts {level}/5"

    return cap_mult, duration_mult, rule


def freeborn_capacitor_recharge_rate(
    capacity_gj,
    recharge_seconds,
    capacitor_fraction,
):
    """
    EVE capacitor recharge curve used for the continuous-load estimator.

    x = capacitor fraction (0..1)
    rate = 10 * C/T * (sqrt(x) - x)

    Peak occurs at 25% capacitor and equals 2.5 * C/T.
    """
    if (
        capacity_gj is None
        or recharge_seconds in (None, 0)
    ):
        return None

    x = max(0.0, min(1.0, float(capacitor_fraction)))

    return (
        10.0
        * float(capacity_gj)
        / float(recharge_seconds)
        * ((x ** 0.5) - x)
    )


def freeborn_capacitor_continuous_state(
    capacity_gj,
    recharge_seconds,
    drain_gjs,
):
    """
    Estimate the continuous all-active capacitor state.

    Returns:
      stable=True + equilibrium_percent when average drain <= peak recharge;
      stable=False + cap_out_seconds when drain exceeds peak recharge.

    This is a continuous-load model, not yet a final discrete-cycle EVE
    simulation. Conditional gains such as Nosferatu/cap injection are not
    included.
    """
    if (
        capacity_gj is None
        or recharge_seconds in (None, 0)
        or drain_gjs is None
    ):
        return {
            "stable": None,
            "equilibrium_percent": None,
            "cap_out_seconds": None,
        }

    capacity = float(capacity_gj)
    recharge = float(recharge_seconds)
    drain = max(0.0, float(drain_gjs))
    peak = 2.5 * capacity / recharge

    if drain <= 0:
        return {
            "stable": True,
            "equilibrium_percent": 100.0,
            "cap_out_seconds": None,
        }

    if drain <= peak:
        k = drain * recharge / (10.0 * capacity)
        discriminant = max(0.0, 1.0 - (4.0 * k))
        y = (1.0 + discriminant ** 0.5) / 2.0
        equilibrium = max(0.0, min(1.0, y * y))

        return {
            "stable": True,
            "equilibrium_percent": equilibrium * 100.0,
            "cap_out_seconds": None,
        }

    # Numerical integration from 100% capacitor for an understandable
    # cap-out estimate under constant average load.
    cap = capacity
    elapsed = 0.0
    dt = 0.25
    max_seconds = 24.0 * 60.0 * 60.0

    while cap > 0 and elapsed < max_seconds:
        fraction = cap / capacity
        recharge_rate = freeborn_capacitor_recharge_rate(
            capacity,
            recharge,
            fraction,
        )
        net = float(recharge_rate or 0.0) - drain
        cap += net * dt
        elapsed += dt

    return {
        "stable": False,
        "equilibrium_percent": None,
        "cap_out_seconds": elapsed if cap <= 0 else None,
    }


def format_capacitor_duration(seconds):
    if seconds is None:
        return "—"

    seconds = max(0, int(round(float(seconds))))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)

    if hours:
        return f"{hours} h {minutes:02d} min {sec:02d} s"

    if minutes:
        return f"{minutes} min {sec:02d} s"

    return f"{sec} s"


def calculate_skill_aware_capacitor(
    ship_type_id,
    eft_sections,
    type_ids,
    *,
    mode="all_v",
    skills_snapshot=None,
):
    """
    Phase 4O-H skill-aware capacitor profile.

    Universal pilot skills:
      - Capacitor Management: +5% capacity / level
      - Capacitor Systems Operation: -5% recharge time / level

    Recognized module-use reductions are applied conservatively through
    freeborn_capacitor_module_skill_modifier().
    """
    base = calculate_base_capacitor_engine(
        ship_type_id,
        eft_sections,
        type_ids,
    )

    context = freeborn_fitting_skill_context(
        mode=mode,
        skills_snapshot=skills_snapshot,
    )

    cap_management = freeborn_context_named_skill_level(
        context,
        "Capacitor Management",
    )
    cap_systems = freeborn_context_named_skill_level(
        context,
        "Capacitor Systems Operation",
    )

    capacity = base["capacity_gj"]
    recharge = base["recharge_seconds"]

    if capacity is not None:
        capacity = float(capacity) * (
            1.0 + (0.05 * cap_management)
        )

    if recharge is not None:
        recharge = float(recharge) * max(
            0.01,
            1.0 - (0.05 * cap_systems),
        )

    module_counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    drain = 0.0
    consumers = 0
    unresolved = 0
    modified_modules = 0

    for type_id, quantity in module_counts.items():
        dogma = get_eve_type_dogma(type_id)

        if not dogma:
            unresolved += int(quantity)
            continue

        cap_need = dogma.get(DOGMA_CAPACITOR_NEED)
        duration_ms = dogma.get(DOGMA_DURATION)

        if cap_need is None or float(cap_need) <= 0:
            continue

        if duration_ms is None or float(duration_ms) <= 0:
            unresolved += int(quantity)
            continue

        cap_mult, duration_mult, rule = (
            freeborn_capacitor_module_skill_modifier(
                type_id,
                context,
            )
        )

        if rule:
            modified_modules += int(quantity)

        adjusted_need = float(cap_need) * cap_mult
        adjusted_duration_ms = float(duration_ms) * duration_mult

        if adjusted_duration_ms <= 0:
            unresolved += int(quantity)
            continue

        per_module = (
            adjusted_need
            / (adjusted_duration_ms / 1000.0)
        )

        drain += per_module * int(quantity)
        consumers += int(quantity)

    peak = (
        2.5 * float(capacity) / float(recharge)
        if (
            capacity is not None
            and recharge not in (None, 0)
        )
        else None
    )

    net_peak = (
        float(peak) - float(drain)
        if peak is not None
        else None
    )

    continuous = freeborn_capacitor_continuous_state(
        capacity,
        recharge,
        drain,
    )

    return {
        "mode": context["mode"],
        "capacitor_management_level": cap_management,
        "capacitor_systems_operation_level": cap_systems,
        "capacity_gj": capacity,
        "recharge_seconds": recharge,
        "peak_recharge_gjs": peak,
        "active_drain_gjs": drain,
        "net_peak_gjs": net_peak,
        "consumer_count": consumers,
        "modified_module_count": modified_modules,
        "unresolved_count": unresolved,
        "complete": unresolved == 0,
        "continuous_stable": continuous["stable"],
        "equilibrium_percent": continuous["equilibrium_percent"],
        "cap_out_seconds": continuous["cap_out_seconds"],
    }


# ============================================================
# FREEBORN FITTINGS — PHASE 4O-B SKILL-AWARE ENGINE
# ============================================================

# Universal Engineering skills affecting the ship's fitting outputs.
EVE_SKILL_CPU_MANAGEMENT = 3426
EVE_SKILL_POWER_GRID_MANAGEMENT = 3413

# Weapon fitting skills.
EVE_SKILL_WEAPON_UPGRADES = 3318
EVE_SKILL_ADVANCED_WEAPON_UPGRADES = 11207

FREEBORN_ALL_V_LEVEL = 5


def freeborn_skill_level_map(skills_snapshot):
    """
    Convert the ESI skills snapshot into:
        {skill_id: trained_skill_level}
    """
    levels = {}

    for row in skills_snapshot or []:
        if not isinstance(row, dict):
            continue

        try:
            skill_id = int(row.get("skill_id"))
        except (TypeError, ValueError):
            continue

        try:
            level = int(
                row.get(
                    "trained_skill_level",
                    row.get("active_skill_level", 0),
                )
                or 0
            )
        except (TypeError, ValueError):
            level = 0

        levels[skill_id] = max(0, min(5, level))

    return levels


def freeborn_fitting_skill_context(
    mode="all_v",
    skills_snapshot=None,
):
    """
    Build the skill context used by the fitting engine.

    mode='all_v':
        all relevant skills are evaluated at V.

    mode='character':
        actual trained levels from the ESI snapshot are used.
    """
    mode = str(mode or "all_v").lower()

    if mode == "all_v":
        return {
            "mode": "all_v",
            "levels": {},
        }

    if mode == "character":
        return {
            "mode": "character",
            "levels": freeborn_skill_level_map(
                skills_snapshot
            ),
        }

    raise ValueError(
        f"Unsupported Freeborn fitting skill mode: {mode}"
    )


def freeborn_context_skill_level(context, skill_id):
    """Resolve one skill level from an ALL V or character context."""
    if context.get("mode") == "all_v":
        return FREEBORN_ALL_V_LEVEL

    return int(
        context.get("levels", {}).get(
            int(skill_id),
            0,
        )
    )


def freeborn_fitted_module_rows(
    eft_sections,
    type_ids,
):
    """
    Return one normalized row per fitted module type.

    Cargo, drones, charges and scripts are excluded.
    """
    cache_key = freeborn_static_fitting_cache_key(
        0,
        eft_sections,
        type_ids,
    )

    cached = _freeborn_module_rows_cache.get(cache_key)
    if cached is not None:
        return [dict(row) for row in cached]

    rows = []
    counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    for type_id, quantity in counts.items():
        dogma = get_eve_type_dogma(type_id)

        rows.append({
            "type_id": int(type_id),
            "quantity": int(quantity),
            "cpu_base": float(
                dogma.get(DOGMA_CPU_NEED, 0.0)
                if dogma
                else 0.0
            ),
            "power_base": float(
                dogma.get(DOGMA_POWER_NEED, 0.0)
                if dogma
                else 0.0
            ),
            "dogma_ok": bool(dogma),
            "weapon_group":
                freeborn_is_weapon_fitting_group(type_id),
        })

    _freeborn_module_rows_cache[cache_key] = [
        dict(row)
        for row in rows
    ]
    return rows


def calculate_skill_aware_fitting_resources(
    ship_type_id,
    eft_sections,
    type_ids,
    *,
    mode="all_v",
    skills_snapshot=None,
):
    """
    Phase 4O-B CPU/PG engine.

    Applied in this phase:
      Ship output:
        - CPU Management: +5% CPU output / level
        - Power Grid Management: +5% PG output / level

      Weapon module fitting needs:
        - Weapon Upgrades: -5% CPU need / level
          on conservative weapon groups
        - Advanced Weapon Upgrades: -2% PG need / level
          on conservative weapon groups

    This is materially closer to EVE fitting than BASE/4O-A, but it is still
    marked "validation" until the SDE modifierInfo layer covers the remaining
    skill-conditioned module families generically.
    """
    base = calculate_base_fitting_resources(
        ship_type_id,
        eft_sections,
        type_ids,
    )

    context = freeborn_fitting_skill_context(
        mode=mode,
        skills_snapshot=skills_snapshot,
    )

    cpu_level = freeborn_context_skill_level(
        context,
        EVE_SKILL_CPU_MANAGEMENT,
    )
    pg_level = freeborn_context_skill_level(
        context,
        EVE_SKILL_POWER_GRID_MANAGEMENT,
    )
    weapon_upgrades_level = freeborn_context_skill_level(
        context,
        EVE_SKILL_WEAPON_UPGRADES,
    )
    awu_level = freeborn_context_skill_level(
        context,
        EVE_SKILL_ADVANCED_WEAPON_UPGRADES,
    )

    cpu_output = base["cpu_output"]
    power_output = base["power_output"]

    if cpu_output is not None:
        cpu_output = float(cpu_output) * (
            1.0 + (0.05 * cpu_level)
        )

    if power_output is not None:
        power_output = float(power_output) * (
            1.0 + (0.05 * pg_level)
        )

    module_rows = freeborn_fitted_module_rows(
        eft_sections,
        type_ids,
    )

    cpu_used = 0.0
    power_used = 0.0
    weapon_module_count = 0
    module_data_complete = True

    for row in module_rows:
        if not row["dogma_ok"]:
            module_data_complete = False

        cpu_need = row["cpu_base"]
        power_need = row["power_base"]

        if row["weapon_group"]:
            weapon_module_count += int(row["quantity"])

            cpu_need *= (
                1.0 - (0.05 * weapon_upgrades_level)
            )

            # AWU applies to turrets/launchers. The temporary 4O-B classifier
            # also recognizes smartbomb groups for WU; smartbomb PG is not
            # modified here.
            group_name = get_eve_type_group_name(
                row["type_id"]
            ).casefold()

            if (
                "launcher" in group_name
                or
                "turret" in group_name
            ):
                power_need *= (
                    1.0 - (0.02 * awu_level)
                )

        cpu_used += (
            float(cpu_need)
            * int(row["quantity"])
        )
        power_used += (
            float(power_need)
            * int(row["quantity"])
        )

    cpu_remaining = (
        float(cpu_output) - float(cpu_used)
        if cpu_output is not None
        else None
    )
    power_remaining = (
        float(power_output) - float(power_used)
        if power_output is not None
        else None
    )

    return {
        "mode": context["mode"],

        "cpu_management_level": cpu_level,
        "power_grid_management_level": pg_level,
        "weapon_upgrades_level": weapon_upgrades_level,
        "advanced_weapon_upgrades_level": awu_level,

        "cpu_used": cpu_used,
        "cpu_output": cpu_output,
        "cpu_remaining": cpu_remaining,
        "cpu_valid": (
            cpu_remaining is not None
            and cpu_remaining >= -0.0001
        ),

        "power_used": power_used,
        "power_output": power_output,
        "power_remaining": power_remaining,
        "power_valid": (
            power_remaining is not None
            and power_remaining >= -0.0001
        ),

        "weapon_module_count": weapon_module_count,

        "data_complete": (
            bool(base["cpu_complete"])
            and bool(base["power_complete"])
            and module_data_complete
        ),

        # 4O-B is a validation engine: universal + weapon fitting skills
        # are applied, but the full SDE modifierInfo pass is still pending.
        "official_all_v_ready": False,
    }


def format_engine_number(value, unit):
    if value is None:
        return "— " + unit

    value = float(value)

    if abs(value - round(value)) < 0.0001:
        number = f"{int(round(value)):,}".replace(",", " ")
    else:
        number = (
            f"{value:,.1f}"
            .replace(",", " ")
            .replace(".", ",")
        )

    return f"{number} {unit}"


def format_engine_resource_pair(
    used,
    output,
    unit,
):
    if used is None or output is None:
        return "— / — " + unit

    def fmt(value):
        value = float(value)

        if abs(value - round(value)) < 0.0001:
            return f"{int(round(value)):,}".replace(",", " ")

        return (
            f"{value:,.1f}"
            .replace(",", " ")
            .replace(".", ",")
        )

    return f"{fmt(used)} / {fmt(output)} {unit}"


def format_engine_margin(
    remaining,
    unit,
):
    if remaining is None:
        return "Donnée indisponible"

    value = float(remaining)
    sign = "+" if value >= 0 else "−"

    return (
        f"{sign}{format_engine_number(abs(value), unit)}"
    )




def format_engine_delta(
    character_value,
    all_v_value,
    unit,
    *,
    lower_is_better=False,
):
    """
    Format the difference Character - ALL V.

    For resource consumption (CPU/PG used), lower_is_better=True means
    a positive raw difference is displayed as a penalty.
    """
    if character_value is None or all_v_value is None:
        return "—"

    delta = float(character_value) - float(all_v_value)

    if abs(delta) < 0.0001:
        return "Identique à ALL V"

    amount = format_engine_number(abs(delta), unit)

    if lower_is_better:
        return (
            f"+{amount} vs ALL V"
            if delta > 0
            else f"−{amount} vs ALL V"
        )

    return (
        f"+{amount} vs ALL V"
        if delta > 0
        else f"−{amount} vs ALL V"
    )


def freeborn_4ob_coverage_label(engine_result):
    """
    Make the current validation scope explicit.
    4O-C still uses the 4O-B calculation kernel; this label prevents the
    partial engine from being confused with the final complete Dogma engine.
    """
    weapon_count = int(
        engine_result.get("weapon_module_count", 0) or 0
    )

    return (
        f"Universel + armes reconnues ({weapon_count} module"
        + ("" if weapon_count == 1 else "s")
        + ")"
    )



def format_fitting_resource_value(
    used,
    output,
    complete,
    unit,
):
    """Render one compact base fitting-resource value for the HUD."""
    if output is None:
        return "— / — " + unit

    # Keep one decimal only when it carries information.
    def _fmt(value):
        value = float(value)
        if abs(value - round(value)) < 0.0001:
            return f"{int(round(value)):,}".replace(",", " ")
        return f"{value:,.1f}".replace(",", " ").replace(".", ",")

    prefix = "" if complete else "≈ "
    return (
        f"{prefix}{_fmt(used)} / {_fmt(output)} {unit}"
    )


def format_eft_web_items(items, type_ids=None):
    """
    Render EFT items with normalized quantities and EVE inventory icons.

    - repeated fitted modules are collapsed;
    - trailing EFT quantities such as `x2000` become the actual quantity;
    - the suffix is removed from the displayed item name.
    """
    if not items:
        return '<div class="slot-empty">Aucun élément renseigné</div>'

    type_ids = type_ids or {}
    collapsed = []
    index_by_key = {}

    for raw_line in items:
        display_line, quantity = parse_eft_display_quantity(raw_line)

        if not display_line:
            continue

        item_name = normalize_eft_item_name(display_line)
        key = display_line.casefold()

        if key in index_by_key:
            collapsed[index_by_key[key]]["quantity"] += quantity
        else:
            index_by_key[key] = len(collapsed)
            collapsed.append({
                "line": display_line,
                "item_name": item_name,
                "quantity": quantity,
            })

    html = []

    for item in collapsed:
        type_id = type_ids.get(item["item_name"].casefold())
        icon_url = eve_type_icon_url(type_id, 64)

        icon_html = (
            f'<img class="item-icon" src="{escape(icon_url)}" '
            f'alt="" loading="lazy">'
            if icon_url
            else '<span class="item-icon item-icon-fallback">◆</span>'
        )

        html.append(
            '<div class="slot-item">'
            f'{icon_html}'
            f'<span class="slot-qty">{int(item["quantity"])}×</span>'
            f'<span class="slot-label">{escape(item["line"])}</span>'
            '</div>'
        )

    return "".join(html)


# NOTE — specialized ship holds:
# The official EFT clipboard format explicitly separates drone/fighter bay
# from cargo bay, but it does not encode Fuel/Ore/Gas/PI/etc. hold assignment.
# This renderer is intentionally generic so future specialized holds can reuse
# exactly the same icon-grid/tooltip UI when Freeborn has a trustworthy source
# for those hold contents/capacities.
def format_eft_bay_items(items, type_ids=None):
    """
    Render Drone/Cargo-style bays as an EVE-like icon grid.

    Each tile shows:
      - the EVE inventory icon when available,
      - the quantity below the icon,
      - complete item name + quantity on hover/focus.
    """
    if not items:
        return '<div class="bay-empty">Aucun élément renseigné</div>'

    type_ids = type_ids or {}
    collapsed = []
    index_by_key = {}

    for raw_line in items:
        display_line, quantity = parse_eft_display_quantity(raw_line)

        if not display_line:
            continue

        item_name = normalize_eft_item_name(display_line)
        key = display_line.casefold()

        if key in index_by_key:
            collapsed[index_by_key[key]]["quantity"] += quantity
        else:
            index_by_key[key] = len(collapsed)
            collapsed.append({
                "line": display_line,
                "item_name": item_name,
                "quantity": quantity,
            })

    tiles = []

    for item in collapsed:
        type_id = type_ids.get(item["item_name"].casefold())
        icon_url = eve_type_icon_url(type_id, 64)

        icon_html = (
            f'<img class="bay-item-icon" src="{escape(icon_url)}" '
            f'alt="" loading="lazy">'
            if icon_url
            else '<span class="bay-item-icon bay-item-fallback">◆</span>'
        )

        quantity = int(item["quantity"])
        quantity_text = f"{quantity:,}".replace(",", " ")
        tooltip = escape(f'{item["line"]} ×{quantity_text}')

        tiles.append(
            '<div class="bay-item" tabindex="0" '
            f'aria-label="{tooltip}">'
            f'{icon_html}'
            f'<span class="bay-qty">{quantity_text}×</span>'
            f'<span class="bay-tooltip">{tooltip}</span>'
            '</div>'
        )

    return "".join(tiles)




# ============================================================
# FREEBORN FITTINGS — PHASE 4R-C PERSISTENT SNAPSHOT
# ============================================================

FREEBORN_TECHNICAL_SNAPSHOT_VERSION = "4S-C-1"


def freeborn_technical_snapshot_fingerprint(fit):
    """
    Stable invalidation fingerprint.

    Status / notes / usage do not invalidate technical calculations.
    Ship type + normalized EFT do.
    """
    payload = (
        str(fit.get("ship_type_id") or "")
        + "\n"
        + str(fit.get("eft_text") or "")
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


def freeborn_technical_snapshot_valid(fit):
    snapshot = fit.get(
        "technical_snapshot"
    )

    if not isinstance(snapshot, dict):
        return False

    if (
        str(
            fit.get(
                "technical_snapshot_version"
            )
            or ""
        )
        != FREEBORN_TECHNICAL_SNAPSHOT_VERSION
    ):
        return False

    return (
        snapshot.get("fingerprint")
        == freeborn_technical_snapshot_fingerprint(
            fit
        )
    )


def persist_freeborn_technical_snapshot(
    fit,
    snapshot,
):
    """
    Persist technical data in Neon so a new Render worker can serve the page
    without rebuilding EVE static data from ESI.
    """
    with psycopg.connect(
        DATABASE_URL
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE fits
                SET
                    technical_snapshot = %s::jsonb,
                    technical_snapshot_version = %s,
                    technical_snapshot_updated_at = NOW()
                WHERE guild_id = %s
                AND fit_id = %s;
                """,
                (
                    json.dumps(
                        snapshot,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    FREEBORN_TECHNICAL_SNAPSHOT_VERSION,
                    str(fit["guild_id"]),
                    int(fit["fit_id"]),
                ),
            )

        conn.commit()

    fit["technical_snapshot"] = snapshot
    fit[
        "technical_snapshot_version"
    ] = FREEBORN_TECHNICAL_SNAPSHOT_VERSION


def freeborn_snapshot_skill_ids():
    """
    Resolve and persist the handful of named skill IDs required by the
    personalized CPU/PG/cap/velocity layer.
    """
    names = tuple(
        FREEBORN_FITTING_NAMED_SKILLS
    )

    resolved = resolve_eve_inventory_type_ids(
        names
    )

    result = {}

    for name in names:
        key = name.casefold()
        type_id = resolved.get(key)

        if type_id:
            result[name] = int(type_id)

    return result


def freeborn_snapshot_module_rows(
    eft_sections,
    type_ids,
):
    """
    Static module rows sufficient for CPU/PG and capacitor personalized
    calculations without future ESI reads.
    """
    counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    rows = []

    for type_id, quantity in counts.items():
        dogma = get_eve_type_dogma(
            type_id
        )
        group_name = (
            get_eve_type_group_name(
                type_id
            )
            or ""
        )

        rows.append({
            "type_id": int(type_id),
            "quantity": int(quantity),
            "group_name": group_name,
            "weapon_group": (
                "launcher"
                in group_name.casefold()
                or "turret"
                in group_name.casefold()
                or "smartbomb"
                in group_name.casefold()
            ),
            "cpu_base": float(
                dogma.get(
                    DOGMA_CPU_NEED,
                    0.0,
                )
                if dogma else 0.0
            ),
            "power_base": float(
                dogma.get(
                    DOGMA_POWER_NEED,
                    0.0,
                )
                if dogma else 0.0
            ),
            "cap_need": (
                float(
                    dogma[
                        DOGMA_CAPACITOR_NEED
                    ]
                )
                if (
                    dogma
                    and dogma.get(
                        DOGMA_CAPACITOR_NEED
                    ) is not None
                )
                else None
            ),
            "duration_ms": (
                float(
                    dogma[
                        DOGMA_DURATION
                    ]
                )
                if (
                    dogma
                    and dogma.get(
                        DOGMA_DURATION
                    ) is not None
                )
                else None
            ),
            "dogma_ok": bool(dogma),
        })

    return rows



def freeborn_type_volume_m3(type_id):
    """Return inventory volume from cached EVE type metadata."""
    if not type_id:
        return 0.0

    payload = get_eve_type_metadata(
        type_id
    )

    try:
        return float(
            payload.get("volume")
            or 0.0
        )
    except (TypeError, ValueError):
        return 0.0


def freeborn_bay_used_volume(
    lines,
    type_ids,
):
    """Sum item volume × EFT quantity for one bay."""
    total = 0.0
    unresolved = []

    for raw_line in lines or []:
        display_line, quantity = (
            parse_eft_display_quantity(
                raw_line
            )
        )

        item_name = normalize_eft_item_name(
            display_line
        )

        type_id = type_ids.get(
            item_name.casefold()
        )

        if not type_id:
            unresolved.append(
                item_name
            )
            continue

        total += (
            freeborn_type_volume_m3(
                type_id
            )
            * int(quantity)
        )

    return {
        "used_m3": total,
        "unresolved": unresolved,
        "complete": not unresolved,
    }


def build_freeborn_ship_resource_usage(
    ship_type_id,
    eft_sections,
    type_ids,
):
    """
    Workbench-style static resource usage:
      - Cargo Bay used / available
      - Drone Bay used / available
      - Drone Bandwidth available
    """
    ship_metadata = get_eve_type_metadata(
        ship_type_id
    )

    try:
        cargo_capacity = float(
            ship_metadata.get(
                "capacity"
            )
            or 0.0
        )
    except (TypeError, ValueError):
        cargo_capacity = 0.0

    drone_capacity_attr = (
        find_dogma_attribute_by_names(
            ship_type_id,
            exact_names=(
                "droneCapacity",
                "Drone Capacity",
                "Drone Bay Capacity",
            ),
            contains_names=(
                "drone capacity",
                "drone bay capacity",
            ),
        )
    )

    drone_bandwidth_attr = (
        find_dogma_attribute_by_names(
            ship_type_id,
            exact_names=(
                "droneBandwidth",
                "Drone Bandwidth",
            ),
            contains_names=(
                "drone bandwidth",
            ),
        )
    )

    drone_capacity = (
        float(
            drone_capacity_attr[
                "value"
            ]
        )
        if drone_capacity_attr
        else None
    )

    drone_bandwidth = (
        float(
            drone_bandwidth_attr[
                "value"
            ]
        )
        if drone_bandwidth_attr
        else None
    )

    drone_lines, cargo_lines = (
        split_eft_drone_and_cargo(
            eft_sections.get(
                "extras",
                [],
            ),
            type_ids,
        )
    )

    drone_usage = (
        freeborn_bay_used_volume(
            drone_lines,
            type_ids,
        )
    )

    cargo_usage = (
        freeborn_bay_used_volume(
            cargo_lines,
            type_ids,
        )
    )

    return {
        "cargo_used_m3":
            cargo_usage["used_m3"],
        "cargo_capacity_m3":
            cargo_capacity,
        "cargo_complete":
            cargo_usage["complete"],
        "drone_bay_used_m3":
            drone_usage["used_m3"],
        "drone_bay_capacity_m3":
            drone_capacity,
        "drone_bay_complete":
            drone_usage["complete"],
        "drone_bandwidth_used_mbps":
            0.0,
        "drone_bandwidth_available_mbps":
            drone_bandwidth,
    }


def format_resource_usage_value(
    used,
    available,
    unit,
):
    if available is None:
        return "—"

    used = float(
        used or 0.0
    )
    available = float(
        available
    )

    def fmt(value):
        if abs(
            value - round(value)
        ) < 0.05:
            return (
                f"{int(round(value)):,}"
                .replace(",", " ")
            )

        return (
            f"{value:,.1f}"
            .replace(",", " ")
            .replace(".", ",")
        )

    return (
        f"{fmt(used)} / "
        f"{fmt(available)} {unit}"
    )



def freeborn_ship_tank_base(ship_type_id):
    """
    Read raw hull hitpoints and base resistance attributes from Dogma.

    Returned resistances are normalized as percentages when possible.
    No fitted module, skill, stacking penalty or reactive effect is applied.
    """
    dogma = get_eve_type_dogma(
        ship_type_id
    )

    if not dogma:
        return {}

    aliases = {
        "shield_hp": (
            "shield capacity",
            "shieldcapacity",
        ),
        "armor_hp": (
            "armor hp",
            "armorhp",
        ),
        "structure_hp": (
            "hp",
            "structure hp",
            "structurehitpoints",
        ),
        "shield_em": (
            "shield em damage resistance",
            "shield em resistance",
        ),
        "shield_therm": (
            "shield thermal damage resistance",
            "shield thermal resistance",
        ),
        "shield_kin": (
            "shield kinetic damage resistance",
            "shield kinetic resistance",
        ),
        "shield_exp": (
            "shield explosive damage resistance",
            "shield explosive resistance",
        ),
        "armor_em": (
            "armor em damage resistance",
            "armor em resistance",
        ),
        "armor_therm": (
            "armor thermal damage resistance",
            "armor thermal resistance",
        ),
        "armor_kin": (
            "armor kinetic damage resistance",
            "armor kinetic resistance",
        ),
        "armor_exp": (
            "armor explosive damage resistance",
            "armor explosive resistance",
        ),
        "structure_em": (
            "structure em damage resistance",
            "structure em resistance",
            "hull em resistance",
        ),
        "structure_therm": (
            "structure thermal damage resistance",
            "structure thermal resistance",
            "hull thermal resistance",
        ),
        "structure_kin": (
            "structure kinetic damage resistance",
            "structure kinetic resistance",
            "hull kinetic resistance",
        ),
        "structure_exp": (
            "structure explosive damage resistance",
            "structure explosive resistance",
            "hull explosive resistance",
        ),
    }

    result = {
        key: None
        for key in aliases
    }

    # Keep structure HP from matching every generic "... hp" attribute:
    # exact matches win, otherwise require context-specific wording.
    for attribute_id, value in dogma.items():
        metadata = get_eve_dogma_attribute_metadata(
            attribute_id
        )

        name = str(
            metadata.get("name")
            or ""
        ).strip()

        display_name = str(
            metadata.get("display_name")
            or ""
        ).strip()

        normalized = (
            name
            + " "
            + display_name
        ).casefold()

        for key, terms in aliases.items():
            if result[key] is not None:
                continue

            matched = False

            if key == "structure_hp":
                matched = (
                    normalized.strip() == "hp"
                    or "structure hp" in normalized
                    or "structure hitpoints" in normalized
                )
            else:
                matched = any(
                    term in normalized
                    for term in terms
                )

            if not matched:
                continue

            try:
                numeric = float(
                    value
                )
            except (TypeError, ValueError):
                continue

            # Resistance Dogma can be either a multiplier (0..1) or percent.
            if "_em" in key or "_therm" in key or "_kin" in key or "_exp" in key:
                if 0.0 <= numeric <= 1.0:
                    # EVE often stores damage resonance; convert to resistance.
                    numeric = (
                        1.0 - numeric
                    ) * 100.0

            result[key] = numeric

    return result


def freeborn_tank_module_audit(
    eft_sections,
    type_ids,
):
    """
    Inventory fitted tank modules and expose Dogma attributes likely to affect:
      - shield/armor/structure HP;
      - EM/Thermal/Kinetic/Explosive resistances;
      - shield boost / armor repair amount;
      - cycle duration.

    This is an audit only. 4S-B deliberately does not derive final tank stats.
    """
    counts = _eft_fitted_module_counts(
        eft_sections,
        type_ids,
    )

    relevant_fragments = (
        "shield bonus",
        "armor bonus",
        "structure bonus",
        "shield capacity",
        "armor hp",
        "hp bonus",
        "resonance",
        "resistance",
        "shield boost",
        "armor repair",
        "repair amount",
        "duration",
        "cycle time",
    )

    rows = []

    for type_id, quantity in counts.items():
        metadata = get_eve_type_metadata(
            type_id
        )

        name = str(
            metadata.get("name")
            or f"Type {type_id}"
        )
        group_name = get_eve_type_group_name(
            type_id
        )

        haystack = (
            name
            + " "
            + str(group_name or "")
        ).casefold()

        tankish = any(
            token in haystack
            for token in (
                "shield",
                "armor",
                "hardener",
                "damage control",
                "bulkhead",
                "extender",
                "plate",
                "booster",
                "repairer",
                "resistance",
            )
        )

        if not tankish:
            continue

        dogma = get_eve_type_dogma(
            type_id
        )

        attributes = []

        for attribute_id, value in dogma.items():
            meta = get_eve_dogma_attribute_metadata(
                attribute_id
            )

            attr_name = str(
                meta.get("name")
                or ""
            ).strip()
            display_name = str(
                meta.get("display_name")
                or ""
            ).strip()

            normalized = (
                attr_name
                + " "
                + display_name
            ).casefold()

            if not any(
                fragment in normalized
                for fragment in relevant_fragments
            ):
                continue

            attributes.append({
                "attribute_id":
                    int(attribute_id),
                "name":
                    display_name
                    or attr_name
                    or f"attribute {attribute_id}",
                "value":
                    value,
            })

        rows.append({
            "type_id": int(type_id),
            "name": name,
            "group_name":
                str(group_name or ""),
            "quantity": int(quantity),
            "attributes": attributes,
        })

    return rows


def format_tank_resistance(value):
    if value is None:
        return "—"

    return (
        f"{float(value):.1f}%"
        .replace(".", ",")
    )


def freeborn_render_tank_audit(
    tank_base,
    modules,
):
    chunks = [
        '<strong>TANK / RÉSISTANCES — AUDIT 4S-B</strong>',
        '<br><span class="cap-audit-key">Hull brut :</span>',
        '<br>Shield HP : '
        + escape(
            str(
                tank_base.get(
                    "shield_hp",
                    "—",
                )
            )
        ),
        ' • Armor HP : '
        + escape(
            str(
                tank_base.get(
                    "armor_hp",
                    "—",
                )
            )
        ),
        ' • Structure HP : '
        + escape(
            str(
                tank_base.get(
                    "structure_hp",
                    "—",
                )
            )
        ),
        '<br><span class="cap-audit-key">Shield :</span> '
        + 'EM '
        + format_tank_resistance(
            tank_base.get("shield_em")
        )
        + ' • THERM '
        + format_tank_resistance(
            tank_base.get("shield_therm")
        )
        + ' • KIN '
        + format_tank_resistance(
            tank_base.get("shield_kin")
        )
        + ' • EXP '
        + format_tank_resistance(
            tank_base.get("shield_exp")
        ),
        '<br><span class="cap-audit-key">Armor :</span> '
        + 'EM '
        + format_tank_resistance(
            tank_base.get("armor_em")
        )
        + ' • THERM '
        + format_tank_resistance(
            tank_base.get("armor_therm")
        )
        + ' • KIN '
        + format_tank_resistance(
            tank_base.get("armor_kin")
        )
        + ' • EXP '
        + format_tank_resistance(
            tank_base.get("armor_exp")
        ),
        '<br><span class="cap-audit-key">Structure :</span> '
        + 'EM '
        + format_tank_resistance(
            tank_base.get("structure_em")
        )
        + ' • THERM '
        + format_tank_resistance(
            tank_base.get("structure_therm")
        )
        + ' • KIN '
        + format_tank_resistance(
            tank_base.get("structure_kin")
        )
        + ' • EXP '
        + format_tank_resistance(
            tank_base.get("structure_exp")
        ),
        '<br><strong>MODULES TANK DÉTECTÉS</strong>',
    ]

    if not modules:
        chunks.append(
            '<br>Aucun module tank détecté.'
        )
        return "".join(chunks)

    for row in modules:
        chunks.append(
            '<br>'
            + f'{row["quantity"]}× '
            + escape(row["name"])
            + (
                ' — '
                + escape(
                    row["group_name"]
                )
                if row["group_name"]
                else ''
            )
        )

        if not row["attributes"]:
            chunks.append(
                '<br><span class="cap-audit-muted">'
                'Aucun attribut tank filtré.'
                '</span>'
            )
            continue

        for attr in row["attributes"]:
            chunks.append(
                '<br>'
                + '<span class="cap-audit-key">'
                + escape(
                    str(attr["name"])
                )
                + '</span> = '
                + escape(
                    str(attr["value"])
                )
                + ' <span class="cap-audit-muted">[#'
                + escape(
                    str(attr["attribute_id"])
                )
                + ']</span>'
            )

    chunks.append(
        '<br><span class="cap-audit-key">État :</span> '
        '4S-B est volontairement un audit. '
        'Aucune résistance finale, EHP ou réparation/s n’est encore publiée.'
    )

    return "".join(chunks)



def freeborn_resistance_stacking_penalty(rank):
    """
    Standard EVE stacking effectiveness, rank is 1-based.
    """
    try:
        rank = max(
            1,
            int(rank),
        )
    except (TypeError, ValueError):
        rank = 1

    return 0.5 ** (
        (
            0.45
            * (rank - 1)
        ) ** 2
    )


def freeborn_resistance_bonus_from_attribute_name(
    name,
):
    """
    Map one Dogma resistance-bonus attribute label to damage type.
    Returns None for non-resistance attributes.
    """
    normalized = str(
        name or ""
    ).casefold()

    if "damage resistance bonus" not in normalized:
        return None

    if "em " in normalized or normalized.startswith("em"):
        return "em"

    if "thermal" in normalized:
        return "therm"

    if "kinetic" in normalized:
        return "kin"

    if "explosive" in normalized:
        return "exp"

    return None


def freeborn_tank_module_resistance_layer(
    module_row,
):
    """
    Determine the resistance layer affected by a validated module family.

    4S-C explicitly covers:
      - Shield Hardener -> shield
      - Armor Hardener / energized armor -> armor
      - Damage Control -> all three layers, if Dogma exposes direct bonuses

    Unknown families are excluded from the numeric result.
    """
    group = str(
        module_row.get(
            "group_name",
            "",
        )
    ).casefold()

    name = str(
        module_row.get(
            "name",
            "",
        )
    ).casefold()

    haystack = (
        group
        + " "
        + name
    )

    if "damage control" in haystack:
        return "all"

    if (
        "shield hardener" in haystack
        or "shield resistance" in haystack
    ):
        return "shield"

    if (
        "armor hardener" in haystack
        or "energized" in haystack
        or "armor resistance" in haystack
    ):
        return "armor"

    return None


def freeborn_calculate_final_resistances(
    tank_base,
    tank_modules,
):
    """
    Calculate final resistances from base hull + direct resistance modifiers.

    EVE resistance modules modify DAMAGE RESONANCE, not resistance points:
        final_resonance = base_resonance × Π(1 + bonus × stacking_penalty)
        final_resistance = 1 - final_resonance

    Dogma bonuses in the audited hardeners are negative percentages
    (e.g. -45.38), therefore factor = 1 + (-0.4538 × penalty).
    """
    damage_types = (
        "em",
        "therm",
        "kin",
        "exp",
    )
    layers = (
        "shield",
        "armor",
        "structure",
    )

    final = {
        layer: {
            damage: tank_base.get(
                f"{layer}_{damage}"
            )
            for damage in damage_types
        }
        for layer in layers
    }

    effect_buckets = {
        layer: {
            damage: []
            for damage in damage_types
        }
        for layer in layers
    }

    excluded_modules = []

    for module in tank_modules or []:
        layer = (
            freeborn_tank_module_resistance_layer(
                module
            )
        )

        if layer is None:
            continue

        found_effect = False
        quantity = max(
            1,
            int(
                module.get(
                    "quantity",
                    1,
                )
                or 1
            ),
        )

        for attr in module.get(
            "attributes",
            [],
        ):
            damage = (
                freeborn_resistance_bonus_from_attribute_name(
                    attr.get(
                        "name"
                    )
                )
            )

            if not damage:
                continue

            try:
                bonus_percent = float(
                    attr.get(
                        "value"
                    )
                )
            except (TypeError, ValueError):
                continue

            # The current audited resistance modifiers are negative percentages.
            raw_bonus = (
                bonus_percent
                / 100.0
            )

            target_layers = (
                layers
                if layer == "all"
                else (layer,)
            )

            for target_layer in target_layers:
                for _ in range(quantity):
                    effect_buckets[
                        target_layer
                    ][
                        damage
                    ].append({
                        "module":
                            module.get(
                                "name",
                                "",
                            ),
                        "raw_bonus":
                            raw_bonus,
                    })

            found_effect = True

        if not found_effect and layer is not None:
            excluded_modules.append(
                module.get(
                    "name",
                    "",
                )
            )

    audit = []

    for layer in layers:
        for damage in damage_types:
            base_resistance = final[
                layer
            ][
                damage
            ]

            if base_resistance is None:
                continue

            base_resonance = (
                1.0
                - (
                    float(
                        base_resistance
                    )
                    / 100.0
                )
            )

            effects = effect_buckets[
                layer
            ][
                damage
            ]

            # Strongest modifier first.
            effects.sort(
                key=lambda row: abs(
                    row["raw_bonus"]
                ),
                reverse=True,
            )

            resonance = (
                base_resonance
            )

            applied = []

            for rank, row in enumerate(
                effects,
                start=1,
            ):
                penalty = (
                    freeborn_resistance_stacking_penalty(
                        rank
                    )
                )

                effective_bonus = (
                    float(
                        row[
                            "raw_bonus"
                        ]
                    )
                    * penalty
                )

                factor = (
                    1.0
                    + effective_bonus
                )

                # Do not allow invalid negative resonance.
                factor = max(
                    0.0,
                    factor,
                )

                resonance *= (
                    factor
                )

                applied.append({
                    "rank": rank,
                    "module":
                        row["module"],
                    "penalty":
                        penalty,
                    "raw_bonus":
                        row[
                            "raw_bonus"
                        ],
                    "effective_bonus":
                        effective_bonus,
                    "factor":
                        factor,
                })

            resistance = (
                1.0
                - resonance
            ) * 100.0

            resistance = min(
                100.0,
                max(
                    0.0,
                    resistance,
                ),
            )

            final[
                layer
            ][
                damage
            ] = resistance

            if applied:
                audit.append({
                    "layer": layer,
                    "damage": damage,
                    "base_resistance":
                        base_resistance,
                    "final_resistance":
                        resistance,
                    "effects":
                        applied,
                })

    return {
        "final": final,
        "audit": audit,
        "excluded_modules":
            excluded_modules,
    }


def freeborn_render_final_resistance_audit(
    result,
):
    final = result.get(
        "final",
        {},
    )

    chunks = [
        '<strong>RÉSISTANCES FINALES — 4S-C</strong>',
        '<br>Calcul : résonance de base × modificateurs Dogma '
        'avec stacking penalties.',
    ]

    for layer, label in (
        ("shield", "Shield"),
        ("armor", "Armor"),
        ("structure", "Structure"),
    ):
        row = final.get(
            layer,
            {},
        )

        chunks.append(
            '<br><span class="cap-audit-key">'
            + label
            + ' :</span> '
            + 'EM '
            + format_tank_resistance(
                row.get("em")
            )
            + ' • THERM '
            + format_tank_resistance(
                row.get("therm")
            )
            + ' • KIN '
            + format_tank_resistance(
                row.get("kin")
            )
            + ' • EXP '
            + format_tank_resistance(
                row.get("exp")
            )
        )

    if result.get(
        "audit"
    ):
        chunks.append(
            '<br><strong>STACKING APPLIQUÉ</strong>'
        )

        for row in result[
            "audit"
        ]:
            chunks.append(
                '<br>'
                + escape(
                    row["layer"].upper()
                )
                + ' '
                + escape(
                    row["damage"].upper()
                )
                + ' : '
                + format_tank_resistance(
                    row[
                        "base_resistance"
                    ]
                )
                + ' → '
                + format_tank_resistance(
                    row[
                        "final_resistance"
                    ]
                )
            )

            for effect in row[
                "effects"
            ]:
                chunks.append(
                    '<br>&nbsp;&nbsp;#'
                    + str(
                        effect["rank"]
                    )
                    + ' '
                    + escape(
                        str(
                            effect[
                                "module"
                            ]
                        )
                    )
                    + ' • efficacité '
                    + f'{effect["penalty"] * 100:.3f}%'
                    + ' • bonus brut '
                    + f'{effect["raw_bonus"] * 100:+.3f}%'
                    + ' → effectif '
                    + f'{effect["effective_bonus"] * 100:+.3f}%'
                )

    chunks.append(
        '<br><span class="cap-audit-key">Couverture 4S-C :</span> '
        'résistances directes des hardeners/armure/damage control détectés. '
        'Reactive effects, heat, fleet boosts et effets conditionnels restent exclus.'
    )

    return "".join(
        chunks
    )



def freeborn_layer_omni_ehp(raw_hp, resistances):
    """Calculate EHP for one layer against a uniform 25/25/25/25 profile."""
    if raw_hp is None:
        return None

    try:
        raw_hp = float(raw_hp)
    except (TypeError, ValueError):
        return None

    resonances = []

    for damage in ("em", "therm", "kin", "exp"):
        resistance = resistances.get(damage)

        if resistance is None:
            return None

        try:
            resistance = float(resistance)
        except (TypeError, ValueError):
            return None

        resonance = 1.0 - resistance / 100.0
        resonances.append(
            min(1.0, max(0.0, resonance))
        )

    average_resonance = sum(resonances) / len(resonances)

    if average_resonance <= 0:
        return None

    return raw_hp / average_resonance


def freeborn_calculate_omni_ehp(tank_base, final_resistance_result):
    """Return Shield / Armor / Structure and total OMNI EHP."""
    final = final_resistance_result.get("final", {})

    shield_ehp = freeborn_layer_omni_ehp(
        tank_base.get("shield_hp"),
        final.get("shield", {}),
    )
    armor_ehp = freeborn_layer_omni_ehp(
        tank_base.get("armor_hp"),
        final.get("armor", {}),
    )
    structure_ehp = freeborn_layer_omni_ehp(
        tank_base.get("structure_hp"),
        final.get("structure", {}),
    )

    values = (shield_ehp, armor_ehp, structure_ehp)

    total_ehp = (
        sum(value for value in values if value is not None)
        if any(value is not None for value in values)
        else None
    )

    return {
        "profile": "OMNI 25/25/25/25",
        "shield_ehp": shield_ehp,
        "armor_ehp": armor_ehp,
        "structure_ehp": structure_ehp,
        "total_ehp": total_ehp,
    }


def format_ehp_value(value):
    if value is None:
        return "—"

    value = float(value)

    if value >= 1000000:
        return f"{value / 1000000:.2f} M".replace(".", ",")

    if value >= 1000:
        return f"{value / 1000:.2f} k".replace(".", ",")

    return f"{value:,.0f}".replace(",", " ")


def freeborn_render_ehp_audit(ehp_result):
    return (
        '<strong>EHP — MOTEUR 4S-D</strong><br>'
        '<span class="cap-audit-key">Profil :</span> '
        + escape(str(ehp_result.get("profile", "—")))
        + '<br><span class="cap-audit-key">Shield EHP :</span> '
        + escape(format_ehp_value(ehp_result.get("shield_ehp")))
        + '<br><span class="cap-audit-key">Armor EHP :</span> '
        + escape(format_ehp_value(ehp_result.get("armor_ehp")))
        + '<br><span class="cap-audit-key">Structure EHP :</span> '
        + escape(format_ehp_value(ehp_result.get("structure_ehp")))
        + '<br><span class="cap-audit-key">TOTAL EHP :</span> <strong>'
        + escape(format_ehp_value(ehp_result.get("total_ehp")))
        + '</strong>'
        + '<br><span class="cap-audit-muted">'
          'Convention 4S-D : dégâts entrants uniformes '
          '25% EM / 25% THERM / 25% KIN / 25% EXP.'
          '</span>'
    )



def freeborn_repair_module_profile(module_row):
    """
    Resolve active repair amount + cycle from one already-audited tank module.

    Supports:
      - Shield Booster
      - Armor Repairer

    Uses only attributes already captured in tank_module_audit.
    """
    name = str(
        module_row.get("name")
        or ""
    )
    group = str(
        module_row.get("group_name")
        or ""
    )

    haystack = (
        name + " " + group
    ).casefold()

    repair_layer = None

    if "shield booster" in haystack:
        repair_layer = "shield"
    elif "armor repair" in haystack:
        repair_layer = "armor"

    if not repair_layer:
        return None

    amount = None
    duration_ms = None

    for attr in module_row.get(
        "attributes",
        [],
    ):
        attr_name = str(
            attr.get("name")
            or ""
        ).casefold()

        try:
            value = float(
                attr.get("value")
            )
        except (TypeError, ValueError):
            continue

        if repair_layer == "shield":
            if (
                "shield bonus" in attr_name
                and "overload" not in attr_name
            ):
                amount = value

        if repair_layer == "armor":
            if (
                "armor repair" in attr_name
                and "overload" not in attr_name
            ):
                amount = value

        if (
            "activation time / duration" in attr_name
            or (
                "duration" in attr_name
                and "overload" not in attr_name
            )
        ):
            # Preserve the first normal duration attribute found.
            if duration_ms is None:
                duration_ms = value

    if (
        amount is None
        or duration_ms is None
        or duration_ms <= 0
    ):
        return None

    quantity = max(
        1,
        int(
            module_row.get(
                "quantity",
                1,
            )
            or 1
        ),
    )

    hp_per_second = (
        float(amount)
        / (
            float(duration_ms)
            / 1000.0
        )
        * quantity
    )

    return {
        "name": name,
        "layer": repair_layer,
        "quantity": quantity,
        "repair_amount_per_cycle":
            float(amount),
        "duration_ms":
            float(duration_ms),
        "hp_per_second":
            hp_per_second,
    }


def freeborn_omni_repair_ehps(
    raw_hps,
    resistances,
):
    """
    Convert raw repaired HP/s into OMNI EHP/s using the same
    25/25/25/25 resonance convention as 4S-D.
    """
    if raw_hps is None:
        return None

    resonances = []

    for damage in (
        "em",
        "therm",
        "kin",
        "exp",
    ):
        resistance = resistances.get(
            damage
        )

        if resistance is None:
            return None

        try:
            resistance = float(
                resistance
            )
        except (TypeError, ValueError):
            return None

        resonances.append(
            min(
                1.0,
                max(
                    0.0,
                    1.0
                    - resistance / 100.0,
                ),
            )
        )

    average_resonance = (
        sum(resonances)
        / len(resonances)
    )

    if average_resonance <= 0:
        return None

    return (
        float(raw_hps)
        / average_resonance
    )


def freeborn_calculate_active_repairs(
    tank_modules,
    final_resistance_result,
):
    """
    Aggregate active repair modules by layer.
    """
    final = final_resistance_result.get(
        "final",
        {},
    )

    modules = []
    totals = {
        "shield_raw_hps": 0.0,
        "armor_raw_hps": 0.0,
        "shield_ehps": 0.0,
        "armor_ehps": 0.0,
    }

    for module_row in tank_modules or []:
        profile = freeborn_repair_module_profile(
            module_row
        )

        if not profile:
            continue

        layer = profile[
            "layer"
        ]

        ehps = freeborn_omni_repair_ehps(
            profile[
                "hp_per_second"
            ],
            final.get(
                layer,
                {},
            ),
        )

        profile[
            "omni_ehp_per_second"
        ] = ehps

        modules.append(
            profile
        )

        if layer == "shield":
            totals[
                "shield_raw_hps"
            ] += profile[
                "hp_per_second"
            ]

            if ehps is not None:
                totals[
                    "shield_ehps"
                ] += ehps

        elif layer == "armor":
            totals[
                "armor_raw_hps"
            ] += profile[
                "hp_per_second"
            ]

            if ehps is not None:
                totals[
                    "armor_ehps"
                ] += ehps

    return {
        "profile":
            "OMNI 25/25/25/25",
        "modules":
            modules,
        **totals,
    }


def format_repairs_value(
    value,
):
    if value is None:
        return "—"

    return (
        f"{float(value):,.1f}"
        .replace(",", " ")
        .replace(".", ",")
    )


def freeborn_render_repairs_audit(
    result,
):
    chunks = [
        '<strong>RÉPARATIONS — MOTEUR 4S-E</strong>',
        '<br><span class="cap-audit-key">Profil :</span> '
        + escape(
            str(
                result.get(
                    "profile",
                    "—",
                )
            )
        ),
    ]

    modules = result.get(
        "modules",
        [],
    )

    if not modules:
        chunks.append(
            '<br>Aucun module de réparation actif résolu.'
        )
    else:
        for module in modules:
            chunks.append(
                '<br>'
                + f'{module["quantity"]}× '
                + escape(
                    str(
                        module["name"]
                    )
                )
                + ' • '
                + escape(
                    module["layer"].upper()
                )
                + ' • '
                + format_repairs_value(
                    module[
                        "repair_amount_per_cycle"
                    ]
                )
                + ' HP/cycle'
                + ' • '
                + format_repairs_value(
                    module[
                        "duration_ms"
                    ]
                    / 1000.0
                )
                + ' s'
                + ' • '
                + format_repairs_value(
                    module[
                        "hp_per_second"
                    ]
                )
                + ' HP/s'
                + ' • '
                + format_repairs_value(
                    module.get(
                        "omni_ehp_per_second"
                    )
                )
                + ' EHP/s'
            )

    chunks.append(
        '<br><span class="cap-audit-key">Shield :</span> '
        + format_repairs_value(
            result.get(
                "shield_raw_hps"
            )
        )
        + ' HP/s • '
        + format_repairs_value(
            result.get(
                "shield_ehps"
            )
        )
        + ' EHP/s'
    )

    chunks.append(
        '<br><span class="cap-audit-key">Armor :</span> '
        + format_repairs_value(
            result.get(
                "armor_raw_hps"
            )
        )
        + ' HP/s • '
        + format_repairs_value(
            result.get(
                "armor_ehps"
            )
        )
        + ' EHP/s'
    )

    chunks.append(
        '<br><span class="cap-audit-muted">'
        '4S-E exclut volontairement surchauffe, implants, boosts de flotte, '
        'effets de bastion/skills non encore modélisés dans cette couche.'
        '</span>'
    )

    return "".join(
        chunks
    )


def build_freeborn_technical_snapshot(
    fit,
    *,
    creator_display=None,
):
    """
    Expensive path, executed once per technical revision of a fitting.

    All values stored here are static with respect to the fit or ALL V
    reference. Character-specific values are intentionally not persisted.
    """
    eft_sections = parse_eft_web_sections(
        fit.get("eft_text")
    )

    all_eft_items = (
        eft_sections["low"]
        + eft_sections["mid"]
        + eft_sections["high"]
        + eft_sections["rigs"]
        + eft_sections["extras"]
    )

    eft_type_ids = (
        resolve_eve_inventory_type_ids(
            all_eft_items
        )
    )

    prefetch_eve_static_type_data(
        list(
            eft_type_ids.values()
        )
        + [fit.get("ship_type_id")],
        max_workers=8,
    )

    skill_ids = (
        freeborn_snapshot_skill_ids()
    )

    base_resources = (
        calculate_base_fitting_resources(
            fit.get("ship_type_id"),
            eft_sections,
            eft_type_ids,
        )
    )

    base_velocity = (
        get_ship_base_max_velocity(
            fit.get("ship_type_id")
        )
    )

    all_v_velocity = (
        calculate_skill_aware_velocity(
            fit.get("ship_type_id"),
            mode="all_v",
            eft_sections=eft_sections,
            type_ids=eft_type_ids,
        )
    )

    capacitor_engine = (
        calculate_base_capacitor_engine(
            fit.get("ship_type_id"),
            eft_sections,
            eft_type_ids,
        )
    )

    capacitor_activity_audit = (
        build_fitted_capacitor_activity_audit(
            eft_sections
        )
    )

    conditional_source_dogma_probe = (
        build_conditional_capacitor_source_dogma_probe(
            eft_sections,
            eft_type_ids,
            capacitor_activity_audit,
        )
    )

    all_v_cap = (
        calculate_skill_aware_capacitor(
            fit.get("ship_type_id"),
            eft_sections,
            eft_type_ids,
            mode="all_v",
        )
    )

    all_v_core = (
        calculate_skill_aware_fitting_resources(
            fit.get("ship_type_id"),
            eft_sections,
            eft_type_ids,
            mode="all_v",
        )
    )

    module_rows = (
        freeborn_snapshot_module_rows(
            eft_sections,
            eft_type_ids,
        )
    )

    ship_resource_usage = (
        build_freeborn_ship_resource_usage(
            fit.get("ship_type_id"),
            eft_sections,
            eft_type_ids,
        )
    )

    tank_base = (
        freeborn_ship_tank_base(
            fit.get("ship_type_id")
        )
    )

    tank_module_audit = (
        freeborn_tank_module_audit(
            eft_sections,
            eft_type_ids,
        )
    )

    final_resistances = (
        freeborn_calculate_final_resistances(
            tank_base,
            tank_module_audit,
        )
    )

    return {
        "version":
            FREEBORN_TECHNICAL_SNAPSHOT_VERSION,
        "fingerprint":
            freeborn_technical_snapshot_fingerprint(
                fit
            ),
        "creator_display":
            str(
                creator_display
                or ""
            ),
        "eft_type_ids": {
            str(key): int(value)
            for key, value
            in eft_type_ids.items()
        },
        "skill_ids": skill_ids,
        "module_rows": module_rows,
        "ship_resource_usage":
            ship_resource_usage,
        "tank_base":
            tank_base,
        "tank_module_audit":
            tank_module_audit,
        "final_resistances":
            final_resistances,
        "base_resources": base_resources,
        "base_velocity": base_velocity,
        "all_v_velocity": all_v_velocity,
        "capacitor_engine":
            capacitor_engine,
        "capacitor_activity_audit":
            capacitor_activity_audit,
        "conditional_source_dogma_probe":
            conditional_source_dogma_probe,
        "all_v_cap": all_v_cap,
        "all_v_core": all_v_core,
    }


def ensure_freeborn_technical_snapshot(
    fit,
    *,
    creator_display=None,
):
    """
    Fast path: return JSONB already loaded by get_fit().

    Slow path: build once, save to Neon, then every future Render worker can
    reuse it even after a cold start.
    """
    if freeborn_technical_snapshot_valid(
        fit
    ):
        return fit[
            "technical_snapshot"
        ]

    snapshot = (
        build_freeborn_technical_snapshot(
            fit,
            creator_display=creator_display,
        )
    )

    persist_freeborn_technical_snapshot(
        fit,
        snapshot,
    )

    return snapshot


def freeborn_snapshot_skill_level(
    snapshot,
    skills_snapshot,
    skill_name,
):
    type_id = (
        snapshot.get(
            "skill_ids",
            {},
        ).get(
            skill_name
        )
    )

    if not type_id:
        return 0

    levels = freeborn_skill_level_map(
        skills_snapshot
    )

    return int(
        levels.get(
            int(type_id),
            0,
        )
    )


def calculate_character_resources_from_snapshot(
    snapshot,
    skills_snapshot,
):
    """
    Character CPU/PG calculation with zero ESI static-data reads.
    """
    base = snapshot[
        "base_resources"
    ]

    levels = freeborn_skill_level_map(
        skills_snapshot
    )

    cpu_level = int(
        levels.get(
            EVE_SKILL_CPU_MANAGEMENT,
            0,
        )
    )
    pg_level = int(
        levels.get(
            EVE_SKILL_POWER_GRID_MANAGEMENT,
            0,
        )
    )
    wu_level = int(
        levels.get(
            EVE_SKILL_WEAPON_UPGRADES,
            0,
        )
    )
    awu_level = int(
        levels.get(
            EVE_SKILL_ADVANCED_WEAPON_UPGRADES,
            0,
        )
    )

    cpu_output = base.get(
        "cpu_output"
    )
    pg_output = base.get(
        "power_output"
    )

    if cpu_output is not None:
        cpu_output = float(
            cpu_output
        ) * (
            1.0
            + 0.05 * cpu_level
        )

    if pg_output is not None:
        pg_output = float(
            pg_output
        ) * (
            1.0
            + 0.05 * pg_level
        )

    cpu_used = 0.0
    pg_used = 0.0
    weapon_count = 0
    complete = True

    for row in snapshot.get(
        "module_rows",
        [],
    ):
        if not row.get(
            "dogma_ok"
        ):
            complete = False

        cpu_need = float(
            row.get(
                "cpu_base",
                0.0,
            )
        )
        pg_need = float(
            row.get(
                "power_base",
                0.0,
            )
        )

        group_name = str(
            row.get(
                "group_name",
                ""
            )
        ).casefold()

        if row.get(
            "weapon_group"
        ):
            weapon_count += int(
                row.get(
                    "quantity",
                    1,
                )
            )
            cpu_need *= (
                1.0
                - 0.05 * wu_level
            )

            if (
                "launcher" in group_name
                or "turret" in group_name
            ):
                pg_need *= (
                    1.0
                    - 0.02 * awu_level
                )

        quantity = int(
            row.get(
                "quantity",
                1,
            )
        )

        cpu_used += (
            cpu_need
            * quantity
        )
        pg_used += (
            pg_need
            * quantity
        )

    cpu_remaining = (
        float(cpu_output)
        - cpu_used
        if cpu_output is not None
        else None
    )
    pg_remaining = (
        float(pg_output)
        - pg_used
        if pg_output is not None
        else None
    )

    return {
        "mode": "character",
        "cpu_management_level":
            cpu_level,
        "power_grid_management_level":
            pg_level,
        "weapon_upgrades_level":
            wu_level,
        "advanced_weapon_upgrades_level":
            awu_level,
        "cpu_used": cpu_used,
        "cpu_output": cpu_output,
        "cpu_remaining":
            cpu_remaining,
        "cpu_valid": (
            cpu_remaining is not None
            and cpu_remaining >= -0.0001
        ),
        "power_used": pg_used,
        "power_output": pg_output,
        "power_remaining":
            pg_remaining,
        "power_valid": (
            pg_remaining is not None
            and pg_remaining >= -0.0001
        ),
        "weapon_module_count":
            weapon_count,
        "data_complete": (
            bool(
                base.get(
                    "cpu_complete"
                )
            )
            and bool(
                base.get(
                    "power_complete"
                )
            )
            and complete
        ),
        "official_all_v_ready":
            False,
    }


def freeborn_snapshot_cap_module_modifier(
    group_name,
    snapshot,
    skills_snapshot,
):
    group = str(
        group_name
        or ""
    ).casefold()

    cap_mult = 1.0
    duration_mult = 1.0
    rule = None

    if "microwarpdrive" in group:
        level = (
            freeborn_snapshot_skill_level(
                snapshot,
                skills_snapshot,
                "High Speed Maneuvering",
            )
        )
        cap_mult *= max(
            0.0,
            1.0 - 0.05 * level,
        )
        rule = (
            f"High Speed Maneuvering "
            f"{level}/5"
        )

    elif "afterburner" in group:
        level = (
            freeborn_snapshot_skill_level(
                snapshot,
                skills_snapshot,
                "Afterburner",
            )
        )
        cap_mult *= max(
            0.0,
            1.0 - 0.10 * level,
        )
        duration_mult *= max(
            0.01,
            1.0 - 0.05 * level,
        )
        rule = (
            f"Afterburner {level}/5"
        )

    elif "shield booster" in group:
        level = (
            freeborn_snapshot_skill_level(
                snapshot,
                skills_snapshot,
                "Shield Compensation",
            )
        )
        cap_mult *= max(
            0.0,
            1.0 - 0.02 * level,
        )
        rule = (
            f"Shield Compensation {level}/5"
        )

    elif "turret" in group:
        level = (
            freeborn_snapshot_skill_level(
                snapshot,
                skills_snapshot,
                "Controlled Bursts",
            )
        )
        cap_mult *= max(
            0.0,
            1.0 - 0.05 * level,
        )
        rule = (
            f"Controlled Bursts {level}/5"
        )

    return (
        cap_mult,
        duration_mult,
        rule,
    )


def calculate_character_capacitor_from_snapshot(
    snapshot,
    skills_snapshot,
):
    """
    Character capacitor profile from persisted module Dogma essentials.
    """
    base = snapshot[
        "capacitor_engine"
    ]

    cap_management = (
        freeborn_snapshot_skill_level(
            snapshot,
            skills_snapshot,
            "Capacitor Management",
        )
    )
    cap_systems = (
        freeborn_snapshot_skill_level(
            snapshot,
            skills_snapshot,
            "Capacitor Systems Operation",
        )
    )

    capacity = base.get(
        "capacity_gj"
    )
    recharge = base.get(
        "recharge_seconds"
    )

    if capacity is not None:
        capacity = float(
            capacity
        ) * (
            1.0
            + 0.05 * cap_management
        )

    if recharge is not None:
        recharge = float(
            recharge
        ) * max(
            0.01,
            1.0
            - 0.05 * cap_systems,
        )

    drain = 0.0
    consumers = 0
    unresolved = 0
    modified = 0

    for row in snapshot.get(
        "module_rows",
        [],
    ):
        quantity = int(
            row.get(
                "quantity",
                1,
            )
        )

        if not row.get(
            "dogma_ok"
        ):
            unresolved += quantity
            continue

        cap_need = row.get(
            "cap_need"
        )
        duration_ms = row.get(
            "duration_ms"
        )

        if (
            cap_need is None
            or float(cap_need) <= 0
        ):
            continue

        if (
            duration_ms is None
            or float(duration_ms) <= 0
        ):
            unresolved += quantity
            continue

        (
            cap_mult,
            duration_mult,
            rule,
        ) = (
            freeborn_snapshot_cap_module_modifier(
                row.get(
                    "group_name"
                ),
                snapshot,
                skills_snapshot,
            )
        )

        if rule:
            modified += quantity

        adjusted_need = (
            float(cap_need)
            * cap_mult
        )
        adjusted_duration = (
            float(duration_ms)
            * duration_mult
        )

        if adjusted_duration <= 0:
            unresolved += quantity
            continue

        drain += (
            adjusted_need
            / (
                adjusted_duration
                / 1000.0
            )
            * quantity
        )
        consumers += quantity

    peak = (
        2.5
        * float(capacity)
        / float(recharge)
        if (
            capacity is not None
            and recharge not in (
                None,
                0,
            )
        )
        else None
    )

    net_peak = (
        float(peak) - drain
        if peak is not None
        else None
    )

    continuous = (
        freeborn_capacitor_continuous_state(
            capacity,
            recharge,
            drain,
        )
    )

    return {
        "mode": "character",
        "capacitor_management_level":
            cap_management,
        "capacitor_systems_operation_level":
            cap_systems,
        "capacity_gj": capacity,
        "recharge_seconds": recharge,
        "peak_recharge_gjs": peak,
        "active_drain_gjs": drain,
        "net_peak_gjs": net_peak,
        "consumer_count": consumers,
        "modified_module_count":
            modified,
        "unresolved_count":
            unresolved,
        "complete":
            unresolved == 0,
        "continuous_stable":
            continuous["stable"],
        "equilibrium_percent":
            continuous[
                "equilibrium_percent"
            ],
        "cap_out_seconds":
            continuous[
                "cap_out_seconds"
            ],
    }


def calculate_character_velocity_from_snapshot(
    snapshot,
    skills_snapshot,
):
    """
    Character propulsion result from the persisted ALL V/static propulsion
    data. No EVE static endpoint is touched.
    """
    all_v = snapshot[
        "all_v_velocity"
    ]

    navigation = (
        freeborn_snapshot_skill_level(
            snapshot,
            skills_snapshot,
            "Navigation",
        )
    )
    acceleration = (
        freeborn_snapshot_skill_level(
            snapshot,
            skills_snapshot,
            "Acceleration Control",
        )
    )

    base_velocity = all_v.get(
        "base_velocity_ms"
    )

    velocity_off = (
        float(base_velocity)
        * (
            1.0
            + 0.05 * navigation
        )
        if base_velocity is not None
        else None
    )

    active_velocity = None

    active_propulsion = all_v.get(
        "active_propulsion"
    )
    active_mass = all_v.get(
        "active_mass_kg"
    )
    effective_thrust = all_v.get(
        "effective_thrust_n"
    )

    if (
        velocity_off is not None
        and active_propulsion
        and active_mass
        and effective_thrust
    ):
        speed_factor = (
            active_propulsion.get(
                "speed_factor"
            )
        )

        if speed_factor is not None:
            effective_bonus = (
                float(speed_factor)
                / 100.0
            ) * (
                1.0
                + 0.05 * acceleration
            )

            active_velocity = (
                float(velocity_off)
                * (
                    1.0
                    + (
                        effective_bonus
                        * float(
                            effective_thrust
                        )
                        / float(
                            active_mass
                        )
                    )
                )
            )

    return {
        "mode": "character",
        "navigation_level":
            navigation,
        "acceleration_control_level":
            acceleration,
        "base_velocity_ms":
            base_velocity,
        "base_mass_kg":
            all_v.get(
                "base_mass_kg"
            ),
        "mass_addition_kg":
            all_v.get(
                "mass_addition_kg"
            ),
        "active_mass_kg":
            active_mass,
        "propulsion_off_velocity_ms":
            velocity_off,
        "propulsion_active_velocity_ms":
            active_velocity,
        "active_propulsion":
            active_propulsion,
        "effective_propulsion_bonus":
            None,
        "effective_thrust_n":
            effective_thrust,
        "raw_propulsion_thrust":
            all_v.get(
                "raw_propulsion_thrust"
            ),
        "raw_to_effective_thrust_ratio":
            all_v.get(
                "raw_to_effective_thrust_ratio"
            ),
        "thrust_source":
            all_v.get(
                "thrust_source"
            ),
    }


def freeborn_fitting_web_page(fit, fit_web_token=None, pilot_profile=None):
    """
    FREEBORN FITTINGS — Phase 4R-C
    EVE-like corporate technical layout.

    The visual structure follows the final Freeborn target:
    - slots on the left,
    - fitting identity / cargo / creator notes in the centre,
    - ship render / technical telemetry on the right,
    - action bar and corporate footer at the bottom.

    EFT stored in Neon remains the source of truth.
    """
    fit = ensure_fit_ship_type_id(dict(fit))

    safe_ref = escape(format_fit_reference(fit["fit_id"]))
    safe_name = escape(str(fit.get("name") or "Fitting Freeborn"))
    safe_ship = escape(str(fit.get("ship_name") or "Vaisseau inconnu"))
    safe_usage = escape(str(fit.get("usage") or "Non précisé"))
    safe_notes = escape(str(fit.get("notes") or "Aucune note du créateur."))
    safe_eft = escape(str(fit.get("eft_text") or "EFT indisponible."))
    creator_id = str(fit.get("created_by_discord_user_id") or "")
    status = str(fit.get("status") or "proposed").lower()

    creator_display = creator_id or "Créateur inconnu"

    existing_snapshot = (
        fit.get("technical_snapshot")
        if freeborn_technical_snapshot_valid(
            fit
        )
        else None
    )

    cached_creator_display = (
        existing_snapshot.get(
            "creator_display"
        )
        if isinstance(
            existing_snapshot,
            dict,
        )
        else None
    )

    if cached_creator_display:
        creator_display = str(
            cached_creator_display
        )
    else:
        try:
            member = get_discord_member(
                str(
                    fit.get("guild_id")
                    or DISCORD_GUILD_ID
                ),
                creator_id,
            )
            if member:
                user = member.get(
                    "user"
                ) or {}
                creator_display = (
                    member.get("nick")
                    or user.get(
                        "global_name"
                    )
                    or user.get(
                        "username"
                    )
                    or creator_display
                )
        except Exception as error:
            print(
                "Freeborn Fittings creator lookup failed:",
                repr(error),
            )

    safe_creator = escape(
        str(creator_display)
    )

    raw_fit_ref = format_fit_reference(fit["fit_id"])

    pilot_start_url = (
        f"{PUBLIC_BASE_URL}/fittings/pilot/{raw_fit_ref}?"
        + urlencode({
            "token": str(fit_web_token or ""),
        })
    )

    pilot_profile = pilot_profile or None

    if pilot_profile:
        pilot_name = escape(
            str(
                pilot_profile.get("character_name")
                or "Pilote EVE"
            )
        )
        pilot_total_sp = int(
            pilot_profile.get("total_skill_points")
            or 0
        )
        pilot_skills = (
            pilot_profile.get("skills_snapshot")
            or []
        )
        pilot_skill_count = len(pilot_skills)

        pilot_updated_at = pilot_profile.get("skills_updated_at")
        if pilot_updated_at:
            try:
                pilot_updated_display = pilot_updated_at.strftime(
                    "%d/%m/%Y %H:%M"
                )
            except Exception:
                pilot_updated_display = str(pilot_updated_at)
        else:
            pilot_updated_display = "Non disponible"

        # Engine values are filled later, after EFT/type resolution.
        # Placeholders are replaced after the engine has calculated the fit.
        pilot_panel_html = f"""
        <div class="pilot-panel pilot-connected">
          <div class="pilot-panel-head">
            <span class="pilot-icon">◉</span>
            <div class="pilot-heading-copy">
              <strong>MON PERSONNAGE — {pilot_name}</strong>
              <small>Profil ESI reconnu et actualisé</small>
            </div>
          </div>

          <div class="pilot-meta">
            <span><b>{pilot_total_sp:,}</b> SP</span>
            <span><b>{pilot_skill_count}</b> compétences</span>
            <span class="pilot-ready">✓ Profil prêt</span>
          </div>

          <div class="pilot-note">
            Comparaison directe avec la référence corporate ALL V.
            Les valeurs ci-dessous utilisent les compétences réellement
            remontées par ESI pour ce Main.
          </div>

          <div class="pilot-tech-grid">
            <div class="pilot-engine-core">
              <div class="pilot-engine-title">MOTEUR 4S-E — FITTING / RESSOURCES / CAP / VITESSE / TANK / EHP / REPAIRS</div>

              <div class="pilot-engine-row">
                <span>CPU Management</span>
                <b id="pilot-cpu-skill">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Power Grid Management</span>
                <b id="pilot-pg-skill">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Weapon Upgrades</span>
                <b id="pilot-wu-skill">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Advanced Weapon Upgrades</span>
                <b id="pilot-awu-skill">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Capacitor Management</span>
                <b id="pilot-cap-management">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Capacitor Systems Operation</span>
                <b id="pilot-cap-systems">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Navigation</span>
                <b id="pilot-navigation">—</b>
              </div>

              <div class="pilot-engine-separator"></div>

              <div class="pilot-engine-row">
                <span>CPU — mon personnage</span>
                <b id="pilot-cpu-pair">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Marge CPU</span>
                <b id="pilot-cpu-margin">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Powergrid — mon personnage</span>
                <b id="pilot-pg-pair">—</b>
              </div>
              <div class="pilot-engine-row">
                <span>Marge Powergrid</span>
                <b id="pilot-pg-margin">—</b>
              </div>

              <div class="pilot-engine-compat" id="pilot-compat">
                ANALYSE EN COURS
              </div>
            </div>

            <div class="pilot-side">
              <div class="pilot-compare" id="pilot-compare">
                <div class="pilot-compare-title">
                  ÉCART AVEC LA RÉFÉRENCE ALL V
                </div>
                <div class="pilot-compare-grid">
                  <span>CPU utilisé</span><b id="pilot-delta-cpu-used">—</b>
                  <span>CPU disponible</span><b id="pilot-delta-cpu-out">—</b>
                  <span>PG utilisé</span><b id="pilot-delta-pg-used">—</b>
                  <span>PG disponible</span><b id="pilot-delta-pg-out">—</b>
                  <span>Capacité capacitor</span><b id="pilot-cap-capacity">—</b>
                  <span>Recharge capacitor</span><b id="pilot-cap-recharge">—</b>
                  <span>Drain continu</span><b id="pilot-cap-drain">—</b>
                  <span>Projection</span><b id="pilot-cap-state">—</b>
                  <span>Vitesse prop. OFF</span><b id="pilot-velocity-off">—</b>
                  <span>Vitesse prop. ACTIVE</span><b id="pilot-velocity-active">—</b>
                  <span>Acceleration Control</span><b id="pilot-acceleration-control">—</b>
                  <span>Écart ACTIVE vs ALL V</span><b id="pilot-delta-velocity">—</b>
                </div>
              </div>

              <div class="pilot-update">
                <small>Dernière mise à jour ESI</small>
                <strong>{escape(pilot_updated_display)}</strong>
              </div>

              <a class="pilot-button pilot-refresh" href="{escape(pilot_start_url)}">
                ↻ Actualiser mon profil EVE
              </a>
            </div>
          </div>
        </div>
        """
    else:
        pilot_panel_html = f"""
        <div class="pilot-panel">
          <div class="pilot-panel-head">
            <span class="pilot-icon">◉</span>
            <div>
              <strong>TESTER AVEC MON PERSONNAGE</strong>
              <small>Comparaison personnelle avec la référence corporate ALL V</small>
            </div>
          </div>
          <div class="pilot-note">
            Connecte ton Main EVE vérifié. Freeborn utilisera uniquement
            le scope compétences déjà prévu par l'intégration membre.
          </div>
          <a class="pilot-button" href="{escape(pilot_start_url)}">
            Tester avec mon personnage
          </a>
        </div>
        """

    status_map = {
        "proposed": ("PROPOSÉ", "#d8aa42"),
        "approved": ("FREEBORN APPROVED", "#79dd73"),
        "rejected": ("REFUSÉ", "#e45757"),
        "archived": ("ARCHIVÉ", "#8996a3"),
    }
    status_label, status_color = status_map.get(
        status,
        (status.upper(), "#29a9ff"),
    )

    render_url = eve_type_render_url(
        fit.get("ship_type_id"),
        512,
    )
    ship_html = (
        f'<img class="ship-render" src="{escape(render_url)}" alt="{safe_ship}">'
        if render_url
        else '<div class="ship-placeholder">VISUEL EVE<br>INDISPONIBLE</div>'
    )

    eft_sections = parse_eft_web_sections(
        fit.get("eft_text")
    )
    technical_snapshot = (
        ensure_freeborn_technical_snapshot(
            fit,
            creator_display=creator_display,
        )
    )

    eft_type_ids = {
        str(key): int(value)
        for key, value
        in technical_snapshot.get(
            "eft_type_ids",
            {},
        ).items()
    }

    base_resources = dict(
        technical_snapshot[
            "base_resources"
        ]
    )

    ship_resource_usage = dict(
        technical_snapshot.get(
            "ship_resource_usage",
            {},
        )
    )

    tank_base = dict(
        technical_snapshot.get(
            "tank_base",
            {},
        )
    )

    tank_module_audit = list(
        technical_snapshot.get(
            "tank_module_audit",
            [],
        )
    )

    tank_audit_html = (
        freeborn_render_tank_audit(
            tank_base,
            tank_module_audit,
        )
    )

    final_resistance_result = dict(
        technical_snapshot.get(
            "final_resistances",
            {},
        )
    )

    final_resistance_audit_html = (
        freeborn_render_final_resistance_audit(
            final_resistance_result
        )
    )

    final_resistance_values = (
        final_resistance_result.get(
            "final",
            {},
        )
    )

    final_shield_resistance = (
        final_resistance_values.get(
            "shield",
            {},
        )
    )

    ehp_result = freeborn_calculate_omni_ehp(
        tank_base,
        final_resistance_result,
    )

    ehp_value = escape(
        format_ehp_value(
            ehp_result.get("total_ehp")
        )
    )

    ehp_audit_html = freeborn_render_ehp_audit(
        ehp_result
    )

    active_repairs_result = (
        freeborn_calculate_active_repairs(
            tank_module_audit,
            final_resistance_result,
        )
    )

    repairs_audit_html = (
        freeborn_render_repairs_audit(
            active_repairs_result
        )
    )

    cargo_usage_value = escape(
        format_resource_usage_value(
            ship_resource_usage.get(
                "cargo_used_m3",
                0.0,
            ),
            ship_resource_usage.get(
                "cargo_capacity_m3"
            ),
            "m³",
        )
    )

    drone_bay_usage_value = escape(
        format_resource_usage_value(
            ship_resource_usage.get(
                "drone_bay_used_m3",
                0.0,
            ),
            ship_resource_usage.get(
                "drone_bay_capacity_m3"
            ),
            "m³",
        )
    )

    drone_bandwidth_value = escape(
        format_resource_usage_value(
            ship_resource_usage.get(
                "drone_bandwidth_used_mbps",
                0.0,
            ),
            ship_resource_usage.get(
                "drone_bandwidth_available_mbps"
            ),
            "Mbit/s",
        )
    )
    cpu_value = escape(
        format_fitting_resource_value(
            base_resources["cpu_used"],
            base_resources["cpu_output"],
            base_resources["cpu_complete"],
            "tf",
        )
    )
    power_value = escape(
        format_fitting_resource_value(
            base_resources["power_used"],
            base_resources["power_output"],
            base_resources["power_complete"],
            "MW",
        )
    )

    base_velocity = (
        technical_snapshot.get(
            "base_velocity"
        )
    )

    velocity_value = escape(
        format_velocity(
            base_velocity
        )
    )

    velocity_title = escape(
        "Vitesse maximale BASE du hull, propulsion désactivée. "
        "Navigation et effets AB/MWD ne sont pas appliqués à cette valeur."
    )

    all_v_velocity = dict(
        technical_snapshot[
            "all_v_velocity"
        ]
    )

    propulsion_probe = (
        all_v_velocity.get("propulsion_rows")
        or []
    )

    propulsion_probe_html = (
        format_propulsion_dogma_probe(
            propulsion_probe
        )
    )

    all_v_velocity_value = escape(
        format_velocity(
            all_v_velocity[
                "propulsion_off_velocity_ms"
            ]
        )
    )

    all_v_active_velocity_value = escape(
        format_velocity(
            all_v_velocity[
                "propulsion_active_velocity_ms"
            ]
        )
    )

    # Phase 4O-F — capacitor engine.
    # The main telemetry remains BASE while the engine audits cyclic module
    # consumption. We expose peak passive recharge but do not invent final
    # stability for conditional/special capacitor mechanics.
    capacitor_engine = dict(
        technical_snapshot[
            "capacitor_engine"
        ]
    )
    capacitor_capacity = capacitor_engine["capacity_gj"]
    capacitor_recharge_seconds = capacitor_engine["recharge_seconds"]
    capacitor_peak = capacitor_engine["peak_recharge_gjs"]
    capacitor_drain = capacitor_engine["active_drain_gjs"]
    capacitor_net_peak = capacitor_engine["net_peak_gjs"]

    if capacitor_capacity is not None and capacitor_recharge_seconds is not None:
        capacitor_value = escape(
            f"{float(capacitor_capacity):,.0f} GJ • {float(capacitor_recharge_seconds):,.0f} s"
            .replace(",", " ")
        )
        capacitor_title = escape(
            "Capaciteur BASE Dogma. "
            + (
                f"Recharge passive maximale théorique : {capacitor_peak:.2f} GJ/s. "
                if capacitor_peak is not None else ""
            )
            + (
                f"Consommation cyclique détectée : {capacitor_drain:.2f} GJ/s. "
                if capacitor_engine["consumer_count"] else
                "Aucune consommation cyclique Dogma détectée. "
            )
            + "La stabilité finale n'est pas encore déclarée tant que les effets "
              "conditionnels et modificateurs Dogma ne sont pas tous couverts."
        )
    else:
        capacitor_value = "À calculer"
        capacitor_title = "Données Dogma capaciteur indisponibles."

    if capacitor_peak is not None:
        capacitor_audit_peak = escape(f"{capacitor_peak:.2f} GJ/s")
        capacitor_audit_drain = escape(f"{capacitor_drain:.2f} GJ/s")
        capacitor_audit_net = escape(
            f"{capacitor_net_peak:+.2f} GJ/s" if capacitor_net_peak is not None else "—"
        )
        capacitor_audit_coverage = (
            "Dogma cyclique résolu"
            if capacitor_engine["complete"]
            else f"Partiel • {capacitor_engine['unresolved_count']} module(s) non résolu(s)"
        )
    else:
        capacitor_audit_peak = "—"
        capacitor_audit_drain = "—"
        capacitor_audit_net = "—"
        capacitor_audit_coverage = "Données indisponibles"


    capacitor_activity_audit = dict(
        technical_snapshot[
            "capacitor_activity_audit"
        ]
    )

    conditional_sources_html = (
        format_capacitor_audit_items(
            capacitor_activity_audit[
                "conditional_sources"
            ]
        )
    )
    injectors_html = (
        format_capacitor_audit_items(
            capacitor_activity_audit[
                "active_injectors"
            ]
        )
    )
    transfers_html = (
        format_capacitor_audit_items(
            capacitor_activity_audit[
                "energy_transfers"
            ]
        )
    )

    conditional_source_dogma_probe = list(
        technical_snapshot.get(
            "conditional_source_dogma_probe",
            [],
        )
    )

    conditional_source_dogma_html = (
        format_conditional_source_dogma_probe(
            conditional_source_dogma_probe
        )
    )

    resolved_conditional_sources = sum(
        1
        for row in conditional_source_dogma_probe
        if row.get("resolved")
    )

    max_conditional_source_gjs = sum(
        float(row.get("max_transfer_gjs") or 0.0)
        for row in conditional_source_dogma_probe
        if row.get("resolved")
    )

    all_v_cap = dict(
        technical_snapshot[
            "all_v_cap"
        ]
    )

    all_v_cap_capacity = escape(
        format_engine_number(
            all_v_cap["capacity_gj"],
            "GJ",
        )
    )
    all_v_cap_recharge = escape(
        format_engine_number(
            all_v_cap["recharge_seconds"],
            "s",
        )
    )
    all_v_cap_peak = escape(
        f'{all_v_cap["peak_recharge_gjs"]:.2f} GJ/s'
        if all_v_cap["peak_recharge_gjs"] is not None
        else "—"
    )
    all_v_cap_drain = escape(
        f'{all_v_cap["active_drain_gjs"]:.2f} GJ/s'
    )

    if all_v_cap["continuous_stable"] is True:
        all_v_cap_state = escape(
            "Stable théorique à "
            + (
                f'{all_v_cap["equilibrium_percent"]:.1f}%'
                if all_v_cap["equilibrium_percent"] is not None
                else "100%"
            )
        )
    elif all_v_cap["continuous_stable"] is False:
        all_v_cap_state = escape(
            "Cap-out théorique : "
            + format_capacitor_duration(
                all_v_cap["cap_out_seconds"]
            )
        )
    else:
        all_v_cap_state = "Indéterminé"

    capacitor_projection_policy = capacitor_verdict_policy(
        all_v_cap_state,
        capacitor_activity_audit,
    )

    capacitor_projection_label = escape(
        capacitor_projection_policy[
            "verdict"
        ]
    )
    capacitor_projection_reason = escape(
        capacitor_projection_policy[
            "reason"
        ]
    )

    character_cap = None

    if pilot_profile:
        character_cap = (
            calculate_character_capacitor_from_snapshot(
                technical_snapshot,
                pilot_profile.get(
                    "skills_snapshot"
                ) or [],
            )
        )

    all_v_core = dict(
        technical_snapshot[
            "all_v_core"
        ]
    )

    all_v_cpu_pair = escape(
        format_engine_resource_pair(
            all_v_core["cpu_used"],
            all_v_core["cpu_output"],
            "tf",
        )
    )
    all_v_pg_pair = escape(
        format_engine_resource_pair(
            all_v_core["power_used"],
            all_v_core["power_output"],
            "MW",
        )
    )
    all_v_cpu_margin = escape(
        format_engine_margin(
            all_v_core["cpu_remaining"],
            "tf",
        )
    )
    all_v_pg_margin = escape(
        format_engine_margin(
            all_v_core["power_remaining"],
            "MW",
        )
    )

    all_v_compat = (
        "✓ COMPATIBLE"
        if (
            all_v_core["cpu_valid"]
            and all_v_core["power_valid"]
        )
        else
        "✕ FITTING INSUFFISANT"
    )
    all_v_coverage = escape(
        freeborn_4ob_coverage_label(all_v_core)
    )


    character_velocity = None

    if pilot_profile:
        character_velocity = (
            calculate_character_velocity_from_snapshot(
                technical_snapshot,
                pilot_profile.get(
                    "skills_snapshot"
                ) or [],
            )
        )

        character_core = (
            calculate_character_resources_from_snapshot(
                technical_snapshot,
                pilot_profile.get(
                    "skills_snapshot"
                ) or [],
            )
        )

        pilot_compat = (
            "✓ COMPATIBLE"
            if (
                character_core["cpu_valid"]
                and character_core["power_valid"]
            )
            else "✕ NON COMPATIBLE"
        )

        pilot_compat_class = (
            "ok"
            if pilot_compat.startswith("✓")
            else "bad"
        )

        pilot_panel_html = (
            pilot_panel_html
            .replace(
                '<b id="pilot-cpu-skill">—</b>',
                '<b id="pilot-cpu-skill">'
                + escape(
                    f'{character_core["cpu_management_level"]}/5'
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-pg-skill">—</b>',
                '<b id="pilot-pg-skill">'
                + escape(
                    f'{character_core["power_grid_management_level"]}/5'
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-wu-skill">—</b>',
                '<b id="pilot-wu-skill">'
                + escape(
                    f'{character_core["weapon_upgrades_level"]}/5'
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-awu-skill">—</b>',
                '<b id="pilot-awu-skill">'
                + escape(
                    f'{character_core["advanced_weapon_upgrades_level"]}/5'
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cpu-pair">—</b>',
                '<b id="pilot-cpu-pair">'
                + escape(
                    format_engine_resource_pair(
                        character_core["cpu_used"],
                        character_core["cpu_output"],
                        "tf",
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cpu-margin">—</b>',
                '<b id="pilot-cpu-margin">'
                + escape(
                    format_engine_margin(
                        character_core["cpu_remaining"],
                        "tf",
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-pg-pair">—</b>',
                '<b id="pilot-pg-pair">'
                + escape(
                    format_engine_resource_pair(
                        character_core["power_used"],
                        character_core["power_output"],
                        "MW",
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-pg-margin">—</b>',
                '<b id="pilot-pg-margin">'
                + escape(
                    format_engine_margin(
                        character_core["power_remaining"],
                        "MW",
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-delta-cpu-used">—</b>',
                '<b id="pilot-delta-cpu-used">'
                + escape(
                    format_engine_delta(
                        character_core["cpu_used"],
                        all_v_core["cpu_used"],
                        "tf",
                        lower_is_better=True,
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-delta-cpu-out">—</b>',
                '<b id="pilot-delta-cpu-out">'
                + escape(
                    format_engine_delta(
                        character_core["cpu_output"],
                        all_v_core["cpu_output"],
                        "tf",
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-delta-pg-used">—</b>',
                '<b id="pilot-delta-pg-used">'
                + escape(
                    format_engine_delta(
                        character_core["power_used"],
                        all_v_core["power_used"],
                        "MW",
                        lower_is_better=True,
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-delta-pg-out">—</b>',
                '<b id="pilot-delta-pg-out">'
                + escape(
                    format_engine_delta(
                        character_core["power_output"],
                        all_v_core["power_output"],
                        "MW",
                    )
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cap-management">—</b>',
                '<b id="pilot-cap-management">'
                + escape(
                    f'{character_cap["capacitor_management_level"]}/5'
                    if character_cap else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cap-systems">—</b>',
                '<b id="pilot-cap-systems">'
                + escape(
                    f'{character_cap["capacitor_systems_operation_level"]}/5'
                    if character_cap else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cap-capacity">—</b>',
                '<b id="pilot-cap-capacity">'
                + escape(
                    format_engine_number(
                        character_cap["capacity_gj"],
                        "GJ",
                    )
                    if character_cap else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cap-recharge">—</b>',
                '<b id="pilot-cap-recharge">'
                + escape(
                    format_engine_number(
                        character_cap["recharge_seconds"],
                        "s",
                    )
                    if character_cap else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cap-drain">—</b>',
                '<b id="pilot-cap-drain">'
                + escape(
                    f'{character_cap["active_drain_gjs"]:.2f} GJ/s'
                    if character_cap else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-cap-state">—</b>',
                '<b id="pilot-cap-state">'
                + escape(
                    (
                        (
                            "Stable théorique "
                            f'{character_cap["equilibrium_percent"]:.1f}%'
                        )
                        if character_cap["continuous_stable"] is True
                        else (
                            "Cap-out "
                            + format_capacitor_duration(
                                character_cap["cap_out_seconds"]
                            )
                        )
                        if character_cap["continuous_stable"] is False
                        else "Indéterminé"
                    )
                    if character_cap else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-navigation">—</b>',
                '<b id="pilot-navigation">'
                + escape(
                    f'{character_velocity["navigation_level"]}/5'
                    if character_velocity else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-velocity-off">—</b>',
                '<b id="pilot-velocity-off">'
                + escape(
                    format_velocity(
                        character_velocity[
                            "propulsion_off_velocity_ms"
                        ]
                    )
                    if character_velocity else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-velocity-active">—</b>',
                '<b id="pilot-velocity-active">'
                + escape(
                    format_velocity(
                        character_velocity[
                            "propulsion_active_velocity_ms"
                        ]
                    )
                    if character_velocity else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-acceleration-control">—</b>',
                '<b id="pilot-acceleration-control">'
                + escape(
                    f'{character_velocity["acceleration_control_level"]}/5'
                    if character_velocity else "—"
                )
                + '</b>',
            )
            .replace(
                '<b id="pilot-delta-velocity">—</b>',
                '<b id="pilot-delta-velocity">'
                + escape(
                    format_engine_delta(
                        character_velocity[
                            "propulsion_active_velocity_ms"
                        ],
                        all_v_velocity[
                            "propulsion_active_velocity_ms"
                        ],
                        "m/s",
                    )
                    if (
                        character_velocity
                        and character_velocity[
                            "propulsion_active_velocity_ms"
                        ] is not None
                        and all_v_velocity[
                            "propulsion_active_velocity_ms"
                        ] is not None
                    )
                    else "—"
                )
                + '</b>',
            )
            .replace(
                '<div class="pilot-engine-compat" id="pilot-compat">\\n              ANALYSE EN COURS\\n            </div>',
                '<div class="pilot-engine-compat '
                + pilot_compat_class
                + '" id="pilot-compat">'
                + escape(pilot_compat)
                + '</div>',
            )
        )

        pilot_panel_html = re.sub(
            r'<div class="pilot-engine-compat" id="pilot-compat">\s*'
            r'ANALYSE EN COURS\s*</div>',
            (
                '<div class="pilot-engine-compat '
                + pilot_compat_class
                + '" id="pilot-compat">'
                + escape(pilot_compat)
                + '</div>'
            ),
            pilot_panel_html,
            count=1,
        )

    low_html = format_eft_web_items(
        eft_sections["low"], eft_type_ids
    )
    mid_html = format_eft_web_items(
        eft_sections["mid"], eft_type_ids
    )
    high_html = format_eft_web_items(
        eft_sections["high"], eft_type_ids
    )
    rigs_html = format_eft_web_items(
        eft_sections["rigs"], eft_type_ids
    )
    drone_items, cargo_items = split_eft_drone_and_cargo(
        eft_sections["extras"],
        eft_type_ids,
    )

    drones_html = format_eft_bay_items(
        drone_items,
        eft_type_ids,
    )
    cargo_html = format_eft_bay_items(
        cargo_items,
        eft_type_ids,
    )

    return f'''<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#020812">
<link rel="icon" type="image/png" href="/assets/favicon.png">
<title>{safe_name} — Freeborn Fittings</title>
<style>
:root {{
  color-scheme:dark;
  --space:#020711;
  --space2:#040d19;
  --panel:rgba(3,12,24,.90);
  --panel2:rgba(5,18,34,.84);
  --blue:#159cff;
  --cyan:#35c7ff;
  --cyan2:#7ddcff;
  --gold:#d6a83c;
  --gold2:#f1cb67;
  --green:#79dd73;
  --red:#e45757;
  --text:#edf5ff;
  --muted:#91abc0;
  --line:rgba(49,185,255,.72);
  --line2:rgba(49,185,255,.30);
  --status:{status_color};
}}
*{{box-sizing:border-box}}
html{{scroll-behavior:smooth}}
body{{
  margin:0;
  min-height:100vh;
  color:var(--text);
  font-family:"Segoe UI",Arial,sans-serif;
  background:
    radial-gradient(circle at 72% 15%,rgba(16,118,220,.20),transparent 30%),
    radial-gradient(circle at 18% 82%,rgba(0,72,150,.17),transparent 32%),
    linear-gradient(rgba(1,5,12,.40),rgba(1,5,12,.72)),
    url('/assets/bg-space.jpg') center/cover fixed no-repeat,
    #020711;
  padding:5px;
}}
button{{font:inherit}}
.app-shell{{
  width:min(1680px,100%);
  margin:auto;
  position:relative;
  overflow:hidden;
  border:1px solid var(--line);
  background:linear-gradient(135deg,rgba(3,12,24,.90),rgba(1,6,14,.96));
  box-shadow:0 0 38px rgba(0,0,0,.78),0 0 34px rgba(21,156,255,.10),inset 0 0 70px rgba(21,156,255,.025);
}}
.app-shell:before,.app-shell:after{{
  content:"";
  position:absolute;
  pointer-events:none;
  width:76px;
  height:76px;
  z-index:5;
}}
.app-shell:before{{left:8px;top:8px;border-left:2px solid var(--cyan);border-top:2px solid var(--cyan)}}
.app-shell:after{{right:8px;bottom:8px;border-right:2px solid var(--cyan);border-bottom:2px solid var(--cyan)}}
.topbar{{
  display:grid;
  grid-template-columns:94px 1fr auto;
  gap:18px;
  align-items:center;
  padding:7px 22px;
  min-height:84px;
  border-bottom:1px solid var(--line2);
  background:linear-gradient(90deg,rgba(2,11,23,.94),rgba(5,21,40,.72),rgba(2,8,17,.92));
}}
.logo{{width:74px;filter:drop-shadow(0 0 13px rgba(44,187,255,.22))}}
.brand h1{{margin:0;font-size:clamp(23px,2.65vw,36px);line-height:1;font-weight:560;letter-spacing:.08em;text-transform:uppercase;color:#eef6ff}}
.brand h1 span{{color:var(--gold2);font-weight:640}}
.brand p{{margin:5px 0 0;color:#c6d8e8;font-size:12px;letter-spacing:.16em;text-transform:uppercase}}
.status-badge{{border:1px solid var(--status);color:var(--status);background:color-mix(in srgb,var(--status) 9%,rgba(2,8,16,.96));padding:10px 15px;font-size:11px;font-weight:800;letter-spacing:.11em;text-transform:uppercase;white-space:nowrap;box-shadow:0 0 18px color-mix(in srgb,var(--status) 18%,transparent)}}
.fit-ref-line{{padding:8px 18px 7px;color:var(--cyan2);border-bottom:1px solid rgba(49,185,255,.18);background:rgba(1,8,17,.74);font:11px/1.25 Consolas,monospace;letter-spacing:.16em;text-transform:uppercase}}
.main-grid{{display:grid;grid-template-columns:minmax(300px,.88fr) minmax(360px,1.08fr) minmax(390px,1.15fr);gap:7px;padding:7px;align-items:stretch}}
.stack{{display:flex;flex-direction:column;gap:6px;min-width:0;height:100%}}
.right-col > .hud-panel:last-child{{flex:1}}
.center-col{{align-self:start;height:auto}}
.center-col > .hud-panel:last-child{{flex:0 0 auto}}
.hud-panel{{position:relative;border:1px solid var(--line2);background:linear-gradient(180deg,rgba(5,20,38,.88),rgba(2,8,17,.94));box-shadow:inset 0 0 24px rgba(39,186,255,.025),0 0 10px rgba(0,0,0,.18)}}
.hud-panel:before{{content:"";position:absolute;left:-1px;top:-1px;width:28px;height:2px;background:var(--cyan);box-shadow:0 0 8px rgba(53,199,255,.35)}}
.panel-title{{display:flex;align-items:center;gap:9px;min-height:31px;padding:5px 9px;border-bottom:1px solid rgba(49,185,255,.22);color:#e9f6ff;font-size:13px;font-weight:760;letter-spacing:.12em;text-transform:uppercase}}
.panel-code{{margin-left:auto;color:#6389a5;font:12px Consolas,monospace;letter-spacing:.12em}}
.slot-symbol{{width:20px;height:20px;flex:0 0 20px;display:grid;place-items:center;border:1px solid var(--cyan);border-radius:50%;color:var(--cyan2);background:rgba(16,108,174,.20);font:800 11px Consolas,monospace;box-shadow:0 0 9px rgba(53,199,255,.12)}}
.slot-symbol.low{{border-color:#9ab3c6;color:#d5e3ee}}
.slot-symbol.rig{{border-radius:3px;border-color:#8bd9ff}}
.slot-body{{padding:5px 9px 7px}}
.slot-item{{display:grid;grid-template-columns:31px 31px 1fr;align-items:center;gap:5px;padding:2px 0;border-bottom:1px solid rgba(255,255,255,.035);color:#dcecf8;font-size:13px;line-height:1.34}}
.slot-item,.panel-title,.panel-code,.info-cell,.notes-body,.metric,.resist,.action,.eft-head,pre,.fit-ref-line,.bay-item{{font-family:"Arial Narrow","Roboto Condensed","Segoe UI",Arial,sans-serif}}
.slot-item:last-child{{border-bottom:0}}
.slot-qty{{color:var(--gold2);font-family:Consolas,monospace}}
.item-icon{{width:28px;height:28px;object-fit:cover;border:1px solid rgba(49,185,255,.26);background:#07101a;box-shadow:0 0 7px rgba(53,199,255,.08)}}
.item-icon-fallback{{display:grid;place-items:center;color:#55758c;font-size:9px}}
.slot-label{{min-width:0;overflow:hidden;text-overflow:ellipsis}}
.slot-empty{{color:#627c91;font-size:12px;font-style:italic;padding:5px 0}}
.identity-panel{{padding:10px 13px 11px}}
.eyebrow{{color:var(--cyan2);font:11px Consolas,monospace;letter-spacing:.14em;text-transform:uppercase}}
.ship-name{{margin:5px 0 0;color:#eef6ff;font-size:clamp(17px,1.8vw,25px);font-weight:650;letter-spacing:.10em;text-transform:uppercase}}
.fit-name{{margin:4px 0 9px;color:var(--gold2);font-size:clamp(16px,1.55vw,21px);line-height:1.12;font-weight:600;letter-spacing:.055em;text-transform:uppercase}}
.info-grid{{display:grid;grid-template-columns:1fr 1fr;gap:7px}}
.info-cell{{border:1px solid rgba(49,185,255,.24);background:rgba(2,10,20,.45);padding:8px 10px}}
.info-cell small{{display:block;color:#6fcaff;margin-bottom:4px;font-size:11px;letter-spacing:.11em;text-transform:uppercase}}
.info-cell strong{{font-size:14px;color:#eef6ff}}
.notes-body{{min-height:86px;padding:13px 15px;color:#dbeaf5;white-space:pre-wrap;font-size:16px;line-height:1.58}}
.hold-panel .slot-body{{overflow:visible}}
.drone-bay-panel .panel-title{{color:#a9e7ff}}
.cargo-bay-panel .panel-title{{color:#d8e8f3}}
.bay-grid{{
  display:flex;
  flex-wrap:wrap;
  align-content:flex-start;
  gap:8px;
  min-height:74px;
  padding:10px 11px 12px;
}}
.bay-item{{
  position:relative;
  width:58px;
  min-height:70px;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:flex-start;
  gap:4px;
  outline:none;
}}
.bay-item-icon{{
  width:44px;
  height:44px;
  object-fit:cover;
  border:1px solid rgba(49,185,255,.30);
  background:#07101a;
  box-shadow:0 0 0 1px rgba(0,0,0,.55),0 0 8px rgba(53,199,255,.08);
}}
.bay-item:hover .bay-item-icon,
.bay-item:focus .bay-item-icon{{
  border-color:rgba(241,203,103,.70);
  box-shadow:0 0 0 1px rgba(0,0,0,.55),0 0 12px rgba(241,203,103,.16);
}}
.bay-item-fallback{{
  display:grid;
  place-items:center;
  color:#58788f;
  font-size:15px;
}}
.bay-qty{{
  color:#d9e7f3;
  font-size:13px;
  line-height:1;
  font-weight:650;
  letter-spacing:.02em;
  white-space:nowrap;
}}
.bay-tooltip{{
  position:absolute;
  z-index:60;
  left:50%;
  bottom:calc(100% + 7px);
  width:max-content;
  max-width:360px;
  transform:translate(-50%,4px);
  padding:7px 9px;
  border:1px solid rgba(180,194,207,.25);
  border-radius:4px;
  background:rgba(56,59,68,.97);
  color:#f2f4f7;
  box-shadow:0 8px 24px rgba(0,0,0,.45);
  font-family:"Arial Narrow","Roboto Condensed","Segoe UI",Arial,sans-serif;
  font-size:12px;
  font-weight:650;
  line-height:1.25;
  text-align:center;
  white-space:normal;
  opacity:0;
  visibility:hidden;
  pointer-events:none;
  transition:opacity .12s ease,transform .12s ease;
}}
.bay-tooltip:after{{
  content:"";
  position:absolute;
  top:100%;
  left:50%;
  transform:translateX(-50%);
  border:6px solid transparent;
  border-top-color:rgba(56,59,68,.97);
}}
.bay-item:hover .bay-tooltip,
.bay-item:focus .bay-tooltip{{
  opacity:1;
  visibility:visible;
  transform:translate(-50%,0);
}}
.bay-empty{{
  width:100%;
  min-height:48px;
  display:grid;
  place-items:center start;
  color:#627c91;
  font-size:12px;
  font-style:italic;
}}
.ship-panel{{min-height:270px;display:grid;grid-template-rows:auto 1fr}}
.ship-stage{{position:relative;min-height:225px;display:grid;place-items:center;overflow:hidden;background:radial-gradient(circle at 50% 45%,rgba(20,145,255,.14),transparent 44%),linear-gradient(90deg,transparent 49.8%,rgba(49,185,255,.08) 50%,transparent 50.2%),linear-gradient(transparent 49.8%,rgba(49,185,255,.06) 50%,transparent 50.2%)}}
.ship-stage:before{{content:"";position:absolute;width:64%;aspect-ratio:1;border:1px solid rgba(49,185,255,.09);border-radius:50%;box-shadow:0 0 0 45px rgba(49,185,255,.018),0 0 0 90px rgba(49,185,255,.012)}}
.ship-render{{width:96%;height:225px;object-fit:contain;position:relative;z-index:1;filter:drop-shadow(0 18px 26px rgba(0,0,0,.84))}}
.ship-placeholder{{color:#6d879b;letter-spacing:.15em;text-align:center}}
.telemetry-reference{{margin:7px 7px 0;padding:9px 11px;border:1px solid rgba(214,168,60,.34);background:rgba(214,168,60,.045)}}
.telemetry-reference strong{{display:block;color:var(--gold2);font-size:11px;letter-spacing:.09em;text-transform:uppercase}}
.telemetry-reference span{{display:block;margin-top:4px;color:#9bb4c7;font-size:11px;line-height:1.35}}
.pilot-panel{{
  margin:9px 7px 10px;
  padding:13px 14px;
  border:1px solid rgba(49,185,255,.38);
  background:
    linear-gradient(180deg,rgba(13,61,96,.18),rgba(2,12,23,.66));
  box-shadow:inset 0 0 18px rgba(53,199,255,.025);
  font-family:"Arial Narrow","Roboto Condensed","Segoe UI",Arial,sans-serif;
}}
.pilot-connected{{
  border-color:rgba(121,221,115,.38);
  background:
    linear-gradient(180deg,rgba(42,105,61,.13),rgba(2,12,23,.66));
}}
.pilot-panel-head{{
  display:flex;
  align-items:center;
  gap:10px;
}}
.pilot-icon{{
  width:32px;
  height:32px;
  flex:0 0 32px;
  display:grid;
  place-items:center;
  border:1px solid var(--cyan);
  border-radius:50%;
  color:var(--cyan2);
  background:rgba(16,108,174,.18);
  font-size:14px;
}}
.pilot-heading-copy{{min-width:0}}
.pilot-panel-head strong{{
  display:block;
  color:#eef7ff;
  font-size:16px;
  line-height:1.15;
  letter-spacing:.055em;
}}
.pilot-panel-head small{{
  display:block;
  margin-top:3px;
  color:#7fc8ef;
  font-size:13px;
  line-height:1.25;
}}
.pilot-meta{{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin-top:10px;
}}
.pilot-meta span{{
  padding:6px 9px;
  border:1px solid rgba(49,185,255,.22);
  background:rgba(0,0,0,.16);
  color:#aac2d2;
  font-size:13px;
}}
.pilot-meta b{{color:#edf6ff}}
.pilot-meta .pilot-ready{{
  color:#9cec94;
  border-color:rgba(121,221,115,.30);
}}
.pilot-note{{
  margin-top:10px;
  color:#bfd0dc;
  font-size:14px;
  line-height:1.42;
}}
.pilot-tech-grid{{
  display:grid;
  grid-template-columns:minmax(0,1.18fr) minmax(250px,.82fr);
  gap:10px;
  margin-top:11px;
  align-items:stretch;
}}
.pilot-engine-core{{
  margin:0;
  padding:10px 11px;
  border:1px solid rgba(49,185,255,.21);
  background:rgba(0,0,0,.18);
}}
.pilot-engine-title{{
  margin-bottom:8px;
  color:#72d3ff;
  font-size:13px;
  font-weight:850;
  line-height:1.2;
  letter-spacing:.075em;
}}
.pilot-engine-row{{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:14px;
  padding:5px 0;
  border-bottom:1px solid rgba(255,255,255,.045);
  color:#a9c2d3;
  font-size:13px;
  line-height:1.25;
}}
.pilot-engine-row:last-child{{border-bottom:0}}
.pilot-engine-row b{{
  color:#f0f6fb;
  font-size:13px;
  white-space:nowrap;
}}
.pilot-engine-separator{{
  height:1px;
  margin:7px 0;
  background:rgba(49,185,255,.17);
}}
.pilot-engine-compat{{
  margin-top:9px;
  padding:9px 10px;
  border:1px solid rgba(49,185,255,.20);
  text-align:center;
  color:#9fb7c8;
  font-size:14px;
  font-weight:900;
  letter-spacing:.075em;
}}
.pilot-engine-compat.ok{{
  color:#9cec94;
  border-color:rgba(121,221,115,.38);
  background:rgba(121,221,115,.055);
}}
.pilot-engine-compat.bad{{
  color:#ff8686;
  border-color:rgba(228,87,87,.40);
  background:rgba(228,87,87,.055);
}}
.pilot-side{{
  display:flex;
  flex-direction:column;
  gap:9px;
  min-width:0;
}}
.pilot-compare{{
  margin:0;
  padding:10px 11px;
  border:1px solid rgba(49,185,255,.21);
  background:rgba(0,0,0,.16);
}}
.pilot-compare-title{{
  margin-bottom:8px;
  color:#72d3ff;
  font-size:13px;
  font-weight:850;
  line-height:1.2;
  letter-spacing:.075em;
}}
.pilot-compare-grid{{
  display:grid;
  grid-template-columns:minmax(0,1fr) auto;
  gap:7px 12px;
  align-items:center;
  color:#a9c2d3;
  font-size:13px;
  line-height:1.25;
}}
.pilot-compare-grid b{{
  color:#eef6fb;
  text-align:right;
  white-space:nowrap;
  font-size:13px;
}}
.pilot-update{{
  padding:9px 11px;
  border:1px solid rgba(49,185,255,.14);
  background:rgba(0,0,0,.12);
}}
.pilot-update small{{
  display:block;
  color:#7998ad;
  font-size:11px;
  text-transform:uppercase;
  letter-spacing:.08em;
}}
.pilot-update strong{{
  display:block;
  margin-top:3px;
  color:#dbe8f1;
  font-size:13px;
}}
.pilot-button{{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:42px;
  margin-top:auto;
  padding:9px 14px;
  border:1px solid rgba(49,185,255,.78);
  background:
    linear-gradient(180deg,rgba(21,156,255,.16),rgba(21,156,255,.035));
  color:#72d3ff;
  text-decoration:none;
  font-size:13px;
  font-weight:850;
  letter-spacing:.055em;
  text-transform:uppercase;
}}
.pilot-button:hover{{
  border-color:var(--cyan2);
  box-shadow:0 0 14px rgba(53,199,255,.13);
}}
.pilot-refresh{{
  border-color:rgba(121,221,115,.55);
  color:#9cec94;
  background:
    linear-gradient(180deg,rgba(121,221,115,.10),rgba(121,221,115,.025));
}}
.allv-preview{{
  margin:8px 7px 0;
  padding:10px 11px;
  border:1px solid rgba(214,168,60,.38);
  background:
    linear-gradient(180deg,rgba(214,168,60,.065),rgba(0,0,0,.13));
  font-family:"Arial Narrow","Roboto Condensed","Segoe UI",Arial,sans-serif;
}}
.allv-head{{
  display:flex;
  justify-content:space-between;
  gap:12px;
  align-items:baseline;
}}
.allv-head strong{{
  color:var(--gold2);
  font-size:13px;
  letter-spacing:.08em;
}}
.allv-head span{{
  color:#9eb0bd;
  font-size:12px;
}}
.capacitor-audit .cap-audit-key{{
  color:#7ed8ff;
  font-weight:800;
}}
.capacitor-audit .cap-audit-verdict{{
  color:#f1cc67;
  font-weight:900;
  letter-spacing:.05em;
}}
.capacitor-audit .cap-dogma-probe{{
  color:#c8dce9;
  font-family:"Arial Narrow","Roboto Condensed","Segoe UI",Arial,sans-serif;
  font-size:11px;
  line-height:1.35;
}}
.allv-warning{{
  margin-top:7px;
  padding:6px 7px;
  border-left:2px solid rgba(214,168,60,.52);
  background:rgba(214,168,60,.035);
  color:#a79a72;
  font-size:10px;
  line-height:1.35;
}}
.allv-grid{{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:7px;
  margin-top:8px;
}}
.allv-grid>div{{
  padding:7px 8px;
  border:1px solid rgba(214,168,60,.18);
  background:rgba(0,0,0,.16);
}}
.allv-grid small{{
  display:block;
  color:#7fcfff;
  font-size:9px;
  letter-spacing:.09em;
}}
.allv-grid b{{
  display:block;
  margin-top:3px;
  color:#f4f7fa;
  font-size:13px;
}}
.allv-grid em{{
  display:block;
  margin-top:2px;
  color:#a8c0d0;
  font-size:10px;
  font-style:normal;
}}
.allv-status{{
  margin-top:7px;
  padding-top:6px;
  border-top:1px solid rgba(214,168,60,.16);
  text-align:right;
  color:#d7b95e;
  font-size:13px;
  font-weight:850;
  letter-spacing:.06em;
}}
.pilot-engine-row:last-child{{border-bottom:0}}
.pilot-engine-row b{{
  color:#edf6ff;
  font-size:11px;
  white-space:nowrap;
}}
.pilot-refresh{{
  border-color:rgba(121,221,115,.55);
  color:#9cec94;
  background:
    linear-gradient(180deg,rgba(121,221,115,.10),rgba(121,221,115,.025));
}}
.telemetry{{display:grid;grid-template-columns:1fr 1fr;gap:5px;padding:6px}}
.metric{{min-height:43px;border:1px solid rgba(49,185,255,.25);background:rgba(1,9,18,.55);padding:6px 8px;display:grid;grid-template-columns:28px 1fr;grid-template-rows:auto auto;column-gap:8px;align-items:center}}
.metric-icon{{grid-row:1/3;width:25px;height:25px;border:1px solid rgba(49,185,255,.40);display:grid;place-items:center;color:#6fd2ff;background:rgba(3,20,34,.72);font-size:16px;line-height:1;text-shadow:0 0 10px rgba(49,185,255,.35)}}
.metric small{{display:block;color:#63c8ff;font-size:10px;letter-spacing:.10em;text-transform:uppercase;align-self:end}}
.metric-mode{{font-style:normal;font-size:9px;color:#67859b;letter-spacing:.10em;margin-left:5px}}
.metric strong{{display:block;margin-top:2px;color:#e8f4fc;font:700 14px Consolas,monospace;align-self:start}}
.metric .pending{{color:#71899d;font-weight:500}}
.resists{{grid-column:1/-1;display:grid;grid-template-columns:repeat(4,1fr);gap:6px}}
.resist{{border:1px solid rgba(49,185,255,.18);background:rgba(2,10,19,.50);padding:5px;text-align:center}}
.resist-icon{{display:block;font-size:14px;line-height:1;margin-bottom:3px}}
.resist.em .resist-icon{{color:#36b8ff}}
.resist.therm .resist-icon{{color:#ff7b32}}
.resist.kin .resist-icon{{color:#c6d0d8}}
.resist.exp .resist-icon{{color:#ffc13b}}
.resist span{{display:block;color:#6b879d;font-size:10px;text-transform:uppercase;letter-spacing:.08em}}
.resist b{{display:block;margin-top:3px;color:#aebfcd;font:12px Consolas,monospace}}
.actionbar{{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:6px;padding:0 7px 7px}}
.action{{appearance:none;min-height:34px;border:1px solid rgba(214,168,60,.75);background:linear-gradient(180deg,rgba(214,168,60,.14),rgba(214,168,60,.025));color:#f4d576;padding:8px 11px;font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;transition:.16s ease}}
.action:hover{{transform:translateY(-1px);border-color:var(--gold2);box-shadow:0 0 15px rgba(214,168,60,.14)}}
.action.blue{{border-color:rgba(49,185,255,.80);background:linear-gradient(180deg,rgba(21,156,255,.15),rgba(21,156,255,.025));color:#71d2ff}}
.action.green{{border-color:rgba(121,221,115,.70);background:linear-gradient(180deg,rgba(121,221,115,.10),rgba(121,221,115,.02));color:#9cec94}}
.action:disabled{{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}}
.eft-wrap{{padding:0 9px 9px}}
.eft-panel{{display:none;border:1px solid var(--line2);background:rgba(2,8,15,.96);padding:9px}}
.eft-panel.open{{display:block}}
.eft-head{{display:flex;justify-content:space-between;gap:10px;margin-bottom:7px;color:var(--gold2);font-size:11px;letter-spacing:.10em;text-transform:uppercase}}
.eft-source{{color:#7290a8;font:12px Consolas,monospace}}
pre{{margin:0;max-height:260px;overflow:auto;padding:10px;border:1px solid rgba(255,255,255,.05);background:#040914;color:#d9e8f5;font:13px/1.48 Consolas,"Courier New",monospace;white-space:pre-wrap}}
.footer{{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;padding:7px 16px;border-top:1px solid var(--line2);color:#7fa4be;background:rgba(1,7,14,.70);font-size:10px;letter-spacing:.11em;text-transform:uppercase}}
.footer .motto{{color:var(--cyan2)}}
.footer .id{{color:var(--gold2);font-family:Consolas,monospace}}
.footer .version{{text-align:right}}
.toast{{position:fixed;right:18px;bottom:18px;z-index:30;padding:9px 13px;border:1px solid rgba(121,221,115,.70);background:#061109;color:#a7eea0;font-size:11px;font-weight:700;opacity:0;transform:translateY(8px);pointer-events:none;transition:.18s ease}}
.toast.show{{opacity:1;transform:translateY(0)}}
@media(max-width:1180px){{
  .pilot-tech-grid{{grid-template-columns:1fr}}
  .main-grid{{grid-template-columns:1fr 1fr}}
  .right-col{{grid-column:1/-1;display:grid;grid-template-columns:1.2fr .8fr}}
  .actionbar{{grid-template-columns:repeat(3,1fr)}}
}}
@media(max-width:780px){{
  body{{padding:4px}}
  .topbar{{grid-template-columns:64px 1fr;gap:10px;padding:9px 11px}}
  .logo{{width:58px}}
  .status-badge{{grid-column:1/-1;text-align:center}}
  .main-grid{{grid-template-columns:1fr}}
  .right-col{{grid-column:auto;display:flex}}
  .info-grid{{grid-template-columns:1fr}}
  .actionbar{{grid-template-columns:1fr 1fr}}
  .footer{{grid-template-columns:1fr;text-align:center;line-height:1.7}}
  .footer .version{{text-align:center}}
}}
</style>
</head>
<body>
<main class="app-shell">
  <header class="topbar">
    <img class="logo" src="/assets/logo-freeborn-legacy.png" alt="Freeborn Legacy">
    <div class="brand">
      <h1>FREEBORN <span>FITTS</span></h1>
      <p>Bibliothèque de fittings • par les FREE • pour les FREE</p>
    </div>
    <div class="status-badge">◉ {escape(status_label)}</div>
  </header>

  <div class="fit-ref-line">
    {safe_ref} // FREEBORN LEGACY // CORPORATE FITTING DATABASE
  </div>

  <section class="main-grid">
    <div class="stack left-col">
      <article class="hud-panel">
        <div class="panel-title"><span class="slot-symbol">▲</span>Emplacements hauts<span class="panel-code">HIGH</span></div>
        <div class="slot-body">{high_html}</div>
      </article>
      <article class="hud-panel">
        <div class="panel-title"><span class="slot-symbol">◆</span>Emplacements intermédiaires<span class="panel-code">MID</span></div>
        <div class="slot-body">{mid_html}</div>
      </article>
      <article class="hud-panel">
        <div class="panel-title"><span class="slot-symbol low">▼</span>Emplacements bas<span class="panel-code">LOW</span></div>
        <div class="slot-body">{low_html}</div>
      </article>
      <article class="hud-panel">
        <div class="panel-title"><span class="slot-symbol rig">◇</span>Rigs<span class="panel-code">RIG</span></div>
        <div class="slot-body">{rigs_html}</div>
      </article>
    </div>

    <div class="stack center-col">
      <article class="hud-panel identity-panel">
        <div class="eyebrow">Fiche corporate // {safe_ref}</div>
        <div class="ship-name">{safe_ship}</div>
        <div class="fit-name">{safe_name}</div>
        <div class="info-grid">
          <div class="info-cell"><small>Usage</small><strong>{safe_usage}</strong></div>
          <div class="info-cell"><small>Créé par</small><strong>{safe_creator}</strong></div>
        </div>
      </article>
      <article class="hud-panel hold-panel drone-bay-panel">
        <div class="panel-title"><span class="slot-symbol">◈</span>Drone Bay<span class="panel-code">DRONES</span></div>
        <div class="slot-body bay-grid">{drones_html}</div>
      </article>

      <article class="hud-panel hold-panel cargo-bay-panel">
        <div class="panel-title"><span class="slot-symbol">▦</span>Cargo Bay<span class="panel-code">CARGO</span></div>
        <div class="slot-body bay-grid">{cargo_html}</div>
      </article>
      <article class="hud-panel">
        <div class="panel-title"><span class="slot-symbol">N</span>Notes du créateur<span class="panel-code">NOTES</span></div>
        <div class="notes-body">{safe_notes}</div>
      </article>
    </div>

    <div class="stack right-col">
      <article class="hud-panel ship-panel">
        <div class="panel-title"><span class="slot-symbol">S</span>{safe_ship}<span class="panel-code">SHIP</span></div>
        <div class="ship-stage">{ship_html}</div>
      </article>
      <article class="hud-panel">
        <div class="panel-title"><span class="slot-symbol">T</span>Télémétrie du fitting<span class="panel-code">STATS</span></div>
        <div class="telemetry">
          <div class="metric" title="Valeur Dogma de base — compétences et modificateurs avancés non appliqués"><span class="metric-icon" aria-hidden="true">▣</span><small>CPU <em class="metric-mode">BASE</em></small><strong>{cpu_value}</strong></div>
          <div class="metric" title="Valeur Dogma de base — compétences et modificateurs avancés non appliqués"><span class="metric-icon" aria-hidden="true">ϟ</span><small>Powergrid <em class="metric-mode">BASE</em></small><strong>{power_value}</strong></div>
          <div class="metric" title="{capacitor_title}"><span class="metric-icon" aria-hidden="true">◫</span><small>Capaciteur <em class="metric-mode">BASE</em></small><strong>{capacitor_value}</strong></div>
          <div class="metric" title="{velocity_title}"><span class="metric-icon" aria-hidden="true">➤</span><small>Vitesse <em class="metric-mode">BASE</em></small><strong>{velocity_value}</strong></div>
          <div class="metric" title="DPS volontairement non calculé par Freeborn Fittings. Utilise l'EFT dans EVE pour les statistiques exactes."><span class="metric-icon" aria-hidden="true">⌖</span><small>DPS</small><strong class="pending">----</strong></div>
          <div class="metric" title="EHP OMNI 25/25/25/25"><span class="metric-icon" aria-hidden="true">⬡</span><small>EHP</small><strong>{ehp_value}</strong></div>
          <div class="resists">
            <div class="resist em"><i class="resist-icon" aria-hidden="true">✦</i><span>EM</span><b>{escape(format_tank_resistance(final_shield_resistance.get("em")))}</b></div>
            <div class="resist therm"><i class="resist-icon" aria-hidden="true">♨</i><span>Therm</span><b>{escape(format_tank_resistance(final_shield_resistance.get("therm")))}</b></div>
            <div class="resist kin"><i class="resist-icon" aria-hidden="true">◈</i><span>Kin</span><b>{escape(format_tank_resistance(final_shield_resistance.get("kin")))}</b></div>
            <div class="resist exp"><i class="resist-icon" aria-hidden="true">✹</i><span>Exp</span><b>{escape(format_tank_resistance(final_shield_resistance.get("exp")))}</b></div>
          </div>
        </div>
        <div class="allv-preview">
          <div class="allv-head">
            <strong>ALL V — VALIDATION 4S-E</strong>
            <span>{all_v_coverage}</span>
          </div>
          <div class="allv-warning">
            Calcul encore partiel : les modificateurs Dogma non couverts
            ne sont pas devinés. BASE reste donc la télémétrie officielle.
          </div>
          <div class="allv-grid">
            <div>
              <small>CPU</small>
              <b>{all_v_cpu_pair}</b>
              <em>{all_v_cpu_margin}</em>
            </div>
            <div>
              <small>POWERGRID</small>
              <b>{all_v_pg_pair}</b>
              <em>{all_v_pg_margin}</em>
            </div>
          </div>
          <div class="allv-status">{all_v_compat}</div>
          <div class="allv-warning resource-usage-audit" style="margin-top:10px">
            <strong>RESSOURCES DU VAISSEAU — 4S-A</strong><br>
            <span class="cap-audit-key">Cargo Bay :</span>
            {cargo_usage_value}<br>
            <span class="cap-audit-key">Drone Bay :</span>
            {drone_bay_usage_value}<br>
            <span class="cap-audit-key">Drone Bandwidth :</span>
            {drone_bandwidth_value}<br>
            <span class="cap-audit-muted">
              Bandwidth utilisé = 0 dans une fiche statique :
              il dépend des drones effectivement déployés.
            </span>
          </div>

          <div class="allv-warning" style="margin-top:10px">
            {tank_audit_html}
          </div>

          <div class="allv-warning" style="margin-top:10px">
            {final_resistance_audit_html}
          </div>

          <div class="allv-warning" style="margin-top:10px">
            {ehp_audit_html}
          </div>

          <div class="allv-warning" style="margin-top:10px">
            {repairs_audit_html}
          </div>
          <div class="allv-warning capacitor-audit" style="margin-top:10px">
            <strong>CAPACITEUR — DOGMA 4O-J</strong><br>
            ALL V : {all_v_cap_capacity} • recharge {all_v_cap_recharge} •
            pic {all_v_cap_peak} • drain continu {all_v_cap_drain}<br>
            Projection hors apports conditionnels : {all_v_cap_state}.<br>

            <span class="cap-audit-verdict">{capacitor_projection_label}</span>
            — {capacitor_projection_reason}<br>

            <span class="cap-audit-key">Sources conditionnelles :</span>
            {conditional_sources_html}<br>

            <span class="cap-audit-key">Lecture Dogma de la source :</span><br>
            <span class="cap-dogma-probe">{conditional_source_dogma_html}</span><br>

            <span class="cap-audit-key">Potentiel conditionnel maximum résolu :</span>
            {escape(f"{max_conditional_source_gjs:.2f} GJ/s")}
            ({resolved_conditional_sources} source(s) résolue(s))<br>

            <span class="cap-audit-key">Injecteurs :</span>
            {injectors_html}<br>
            <span class="cap-audit-key">Transferts d'énergie :</span>
            {transfers_html}<br>

            Couverture cyclique : {escape(capacitor_audit_coverage)}.
            Le potentiel du Nosferatu est maintenant lu depuis ses attributs
            Dogma mais reste volontairement EXCLU de la stabilité : sa
            disponibilité dépend de la cible et ne peut pas être garantie
            par le fitting seul.
          </div>
          <div class="allv-warning" style="margin-top:10px">
            <strong>VITESSE — MOTEUR 4P-D</strong><br>
            Hull BASE : {velocity_value} •
            ALL V, propulsion OFF : {all_v_velocity_value} •
            <strong>ALL V, propulsion ACTIVE : {all_v_active_velocity_value}</strong><br>
            Navigation ALL V : 5/5 • Acceleration Control ALL V : 5/5<br>
            <span class="cap-audit-key">Propulsion équipée :</span><br>
            {propulsion_probe_html}<br>
            <span class="cap-audit-key">Masse hull :</span>
            {escape(f'{all_v_velocity["base_mass_kg"]:,.0f} kg'.replace(",", " ") if all_v_velocity["base_mass_kg"] is not None else "—")} •
            <span class="cap-audit-key">ajouts de masse :</span>
            {escape(f'{all_v_velocity["mass_addition_kg"]:,.0f} kg'.replace(",", " "))} •
            <span class="cap-audit-key">masse active :</span>
            {escape(f'{all_v_velocity["active_mass_kg"]:,.0f} kg'.replace(",", " ") if all_v_velocity["active_mass_kg"] is not None else "—")}<br>
            <span class="cap-audit-key">Thrust Dogma brut :</span>
            {escape(f'{all_v_velocity["raw_propulsion_thrust"]:,.0f}'.replace(",", " ") if all_v_velocity["raw_propulsion_thrust"] is not None else "—")} •
            <span class="cap-audit-key">Thrust effectif :</span>
            {escape(f'{all_v_velocity["effective_thrust_n"]:,.0f} N'.replace(",", " ") if all_v_velocity["effective_thrust_n"] is not None else "—")}<br>
            <span class="cap-audit-key">Résolution thrust :</span>
            {escape(all_v_velocity["thrust_source"])} •
            <span class="cap-audit-key">ratio brut/effectif :</span>
            {escape(f'{all_v_velocity["raw_to_effective_thrust_ratio"]:.2f}×' if all_v_velocity["raw_to_effective_thrust_ratio"] is not None else "—")}<br>
            4P-D consolide la formule propulsion complète
            bonus × thrust / masse. Le thrust effectif est dérivé de la classe
            de propulsion via massAddition × 3 ; la valeur Dogma brute reste
            affichée uniquement pour audit. Les effets de vitesse supplémentaires
            (overdrive, nanofiber, implants, boosts de flotte, surchauffe)
            restent hors couverture tant que leurs modificateurs Dogma
            spécifiques ne sont pas intégrés.
          </div>

        </div>
        {pilot_panel_html}
      </article>
    </div>
  </section>

  <nav class="actionbar" aria-label="Actions du fitting">
    <button class="action" type="button" onclick="toggleEft()">▣ Afficher EFT</button>
    <button class="action" type="button" onclick="copyEft()">▤ Copier EFT</button>
    <button class="action blue" type="button" onclick="exportEft()">⇩ Exporter EFT</button>
    <button class="action blue" type="button" disabled title="Disponible après authentification Discord">✎ Modifier</button>
    <button class="action green" type="button" disabled title="Validation Web prévue après authentification Discord">✓ Approuver / Refuser</button>
  </nav>

  <section class="eft-wrap">
    <div class="eft-panel" id="eftPanel">
      <div class="eft-head">
        <strong>EFT — {safe_ref} • {safe_ship}</strong>
        <span class="eft-source">SOURCE NEON</span>
      </div>
      <pre id="eftText">{safe_eft}</pre>
    </div>
  </section>

  <footer class="footer">
    <span class="motto">Libres par choix • Unis par volonté • Héritiers de notre propre avenir</span>
    <span class="id">{safe_ref}</span>
    <span class="version">Freeborn Legacy • Fittings 4S-E</span>
  </footer>
</main>

<div class="toast" id="toast">EFT copié</div>

<script>
const fitRef = "{safe_ref}";
const shipName = "{safe_ship}";

function getEft() {{
  return document.getElementById('eftText').textContent;
}}
function toggleEft() {{
  document.getElementById('eftPanel').classList.toggle('open');
}}
async function copyEft() {{
  const text = getEft();
  try {{
    await navigator.clipboard.writeText(text);
    showToast('EFT copié dans le presse-papiers');
  }} catch (e) {{
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    showToast('EFT copié dans le presse-papiers');
  }}
}}
function exportEft() {{
  const blob = new Blob([getEft()], {{type:'text/plain;charset=utf-8'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${{fitRef}}-${{shipName}}.txt`.replace(/[^a-z0-9._-]+/gi,'-');
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}}
function showToast(message) {{
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(window.__fbToast);
  window.__fbToast = window.setTimeout(() => toast.classList.remove('show'),1800);
}}
</script>
</body>
</html>'''


@app.route("/fittings/<fit_ref>")
def fitting_web_card(fit_ref):
    token = request.args.get("token", "")

    try:
        fit_id = parse_fit_reference(fit_ref)
        token_guild_id, token_fit_id = read_fit_web_token(token)
    except (ValueError, BadSignature, SignatureExpired, KeyError, TypeError):
        return freeborn_web_page(
            "Lien de fitting invalide",
            "Ce lien Freeborn Fittings est invalide ou incomplet.",
            status="error",
        ), 403

    if token_guild_id != str(DISCORD_GUILD_ID) or token_fit_id != fit_id:
        return freeborn_web_page(
            "Accès refusé",
            "Ce lien ne correspond pas à ce fitting Freeborn.",
            status="error",
        ), 403

    fit = get_fit(token_guild_id, fit_id)

    if not fit:
        return freeborn_web_page(
            "Fitting introuvable",
            f"{format_fit_reference(fit_id)} n'existe plus dans Freeborn.",
            status="warning",
        ), 404

    pilot_profile = None
    pilot_token = request.args.get("pilot", "")

    if pilot_token:

        try:

            pilot_payload = fit_pilot_serializer.loads(
                pilot_token,
                max_age=1800,
            )

            if (
                str(pilot_payload.get("guild_id"))
                == str(token_guild_id)
                and
                int(pilot_payload.get("fit_id"))
                == int(fit_id)
            ):

                pilot_profile = get_guild_main_by_character_id_v3(
                    token_guild_id,
                    int(pilot_payload["character_id"]),
                )

        except (
            BadSignature,
            SignatureExpired,
            KeyError,
            TypeError,
            ValueError,
        ):

            pilot_profile = None

    return freeborn_fitting_web_page(
        fit,
        fit_web_token=token,
        pilot_profile=pilot_profile,
    )


@app.route("/fittings/pilot/<fit_ref>")
def fitting_pilot_start(fit_ref):
    """
    Start the voluntary EVE SSO flow used by
    'Tester avec mon personnage'.
    """
    token = request.args.get("token", "")

    try:
        fit_id = parse_fit_reference(fit_ref)
        token_guild_id, token_fit_id = read_fit_web_token(token)
    except (ValueError, BadSignature, SignatureExpired, KeyError, TypeError):
        return freeborn_web_page(
            "Lien de fitting invalide",
            "Ce lien Freeborn Fittings est invalide ou incomplet.",
            status="error",
        ), 403

    if (
        token_guild_id != str(DISCORD_GUILD_ID)
        or token_fit_id != fit_id
    ):
        return freeborn_web_page(
            "Accès refusé",
            "Ce lien ne correspond pas à ce fitting Freeborn.",
            status="error",
        ), 403

    if not get_fit(token_guild_id, fit_id):
        return freeborn_web_page(
            "Fitting introuvable",
            f"{format_fit_reference(fit_id)} n'existe plus dans Freeborn.",
            status="warning",
        ), 404

    state = state_serializer.dumps({
        "guild_id": str(token_guild_id),
        "verification_type": "fit_pilot",
        "fit_id": int(fit_id),
        "fit_web_token": str(token),
    })

    params = {
        "response_type": "code",
        "redirect_uri": EVE_CALLBACK_URL,
        "client_id": EVE_CLIENT_ID,
        "state": state,
        "scope": " ".join(FREEBORN_EVE_SCOPES),
    }

    return redirect(
        f"{EVE_AUTHORIZE_URL}?{urlencode(params)}"
    )


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
    # MODAL SUBMIT — FREEBORN FITTINGS
    # ========================================================

    if (
        data["type"]
        ==
        5
    ):

        return handle_fit_modal_submit(
            data
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
    # /fit-liste — FREEBORN FITTINGS
    # ========================================================

    if command_name == "fit-liste":
        if not interaction_has_any_role(data, FITTING_CREATOR_ROLE_IDS):
            return jsonify({"type": 4, "data": {"content": "⛔ Accès réservé aux membres Freeborn.", "flags": 64}})

        return jsonify({
            "type": 4,
            "data": {
                "content": build_fit_list_message(guild_id),
                "flags": 64,
            },
        })

    # ========================================================
    # /fit-afficher — FREEBORN FITTINGS
    # Public corporation card in the current channel.
    # ========================================================

    if command_name == "fit-afficher":
        if not interaction_has_any_role(data, FITTING_CREATOR_ROLE_IDS):
            return jsonify({"type": 4, "data": {"content": "⛔ Accès réservé aux membres Freeborn.", "flags": 64}})

        fit_ref = None
        for option in data["data"].get("options", []):
            if option.get("name") == "ref":
                fit_ref = option.get("value")
                break

        try:
            fit_id = parse_fit_reference(fit_ref)
        except ValueError as error:
            return jsonify({"type": 4, "data": {"content": f"❌ {error}", "flags": 64}})

        fit = get_fit(guild_id, fit_id)
        if not fit:
            return jsonify({"type": 4, "data": {"content": f"❌ {format_fit_reference(fit_id)} n'existe pas dans Freeborn.", "flags": 64}})

        return jsonify({
            "type": 4,
            "data": {
                "embeds": [build_fit_embed(fit)],
                "components": build_fit_components(fit["fit_id"], guild_id),
            },
        })

    # ========================================================
    # /fit-approuver + /fit-refuser — FREEBORN FITTINGS
    # Staff workflow: PROPOSÉ -> FREEBORN APPROVED / REFUSÉ.
    # ========================================================

    if command_name in {"fit-approuver", "fit-refuser"}:
        if not interaction_has_any_role(data, FITTING_MANAGER_ROLE_IDS):
            return jsonify({
                "type": 4,
                "data": {
                    "content": (
                        "⛔ **Accès refusé**\n\n"
                        "La validation des fittings est réservée au staff Fittings "
                        "(Fleet Commander et hiérarchie supérieure)."
                    ),
                    "flags": 64,
                },
            })

        fit_ref = None
        for option in data["data"].get("options", []):
            if option.get("name") == "ref":
                fit_ref = option.get("value")
                break

        try:
            fit_id = parse_fit_reference(fit_ref)
        except ValueError as error:
            return jsonify({"type": 4, "data": {"content": f"❌ {error}", "flags": 64}})

        fit = get_fit(guild_id, fit_id)
        if not fit:
            return jsonify({"type": 4, "data": {"content": f"❌ {format_fit_reference(fit_id)} n'existe pas dans Freeborn.", "flags": 64}})

        new_status = "approved" if command_name == "fit-approuver" else "rejected"
        updated = set_fit_status(guild_id, fit_id, new_status)

        if not updated:
            return jsonify({"type": 4, "data": {"content": "❌ Mise à jour impossible.", "flags": 64}})

        action_text = (
            "🟢 **FREEBORN APPROVED**"
            if new_status == "approved"
            else "🔴 **FIT REFUSÉ**"
        )

        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    f"{action_text} — **{format_fit_reference(fit_id)}**\n\n"
                    f"**{updated['ship_name']} — {updated['name']}**\n"
                    f"Statut : {fit_status_label(updated['status'])}"
                ),
                "flags": 64,
            },
        })

    # ========================================================
    # /fit-supprimer — FREEBORN FITTINGS
    # Real deletion from Neon after confirmation.
    # ========================================================

    if command_name == "fit-supprimer":
        fit_ref = None
        for option in data["data"].get("options", []):
            if option.get("name") == "ref":
                fit_ref = option.get("value")
                break

        try:
            fit_id = parse_fit_reference(fit_ref)
        except ValueError as error:
            return jsonify({"type": 4, "data": {"content": f"❌ {error}", "flags": 64}})

        fit = get_fit(guild_id, fit_id)
        if not fit:
            return jsonify({"type": 4, "data": {"content": f"❌ {format_fit_reference(fit_id)} n'existe pas dans Freeborn.", "flags": 64}})

        if not can_delete_fit(data, fit):
            return jsonify({
                "type": 4,
                "data": {
                    "content": (
                        "⛔ **Suppression refusée**\n\n"
                        "Seul le créateur du fit ou le staff Fittings peut le supprimer."
                    ),
                    "flags": 64,
                },
            })

        token = create_fit_delete_token(fit["fit_id"], discord_user_id)

        return jsonify({
            "type": 4,
            "data": {
                "content": (
                    f"⚠️ **Supprimer définitivement {format_fit_reference(fit['fit_id'])} ?**\n\n"
                    f"Vaisseau : **{fit['ship_name']}**\n"
                    f"Fit : **{fit['name']}**\n\n"
                    "Cette action supprimera réellement le fitting de Neon."
                ),
                "components": [
                    {
                        "type": 1,
                        "components": [
                            {
                                "type": 2,
                                "style": 4,
                                "label": "Supprimer définitivement",
                                "custom_id": f"fit_del_yes:{token}",
                            },
                            {
                                "type": 2,
                                "style": 2,
                                "label": "Annuler",
                                "custom_id": f"fit_del_no:{token}",
                            },
                        ],
                    },
                ],
                "flags": 64,
            },
        })

    # ========================================================
    # /fit-creer — FREEBORN FITTINGS
    # ========================================================

    if command_name == "fit-creer":

        if not interaction_has_any_role(
            data,
            FITTING_CREATOR_ROLE_IDS,
        ):
            return jsonify({
                "type": 4,
                "data": {
                    "content": (
                        "⛔ **Accès refusé**\n\n"
                        "La création de fittings est réservée aux membres Freeborn."
                    ),
                    "flags": 64,
                },
            })

        return jsonify({
            "type": 9,
            "data": {
                "custom_id": "freeborn_fit_create_v1",
                "title": "Freeborn Fittings — Nouveau fit",
                "components": [
                    {
                        "type": 1,
                        "components": [
                            {
                                "type": 4,
                                "custom_id": "fit_name",
                                "label": "Nom du fit",
                                "style": 1,
                                "min_length": 1,
                                "max_length": 80,
                                "required": True,
                                "placeholder": "Ex. Retribution — Abyssal T1",
                            }
                        ],
                    },
                    {
                        "type": 1,
                        "components": [
                            {
                                "type": 4,
                                "custom_id": "fit_usage",
                                "label": "Usage",
                                "style": 1,
                                "min_length": 1,
                                "max_length": 40,
                                "required": True,
                                "placeholder": "PvE, PvP, Wormhole, Exploration...",
                            }
                        ],
                    },
                    {
                        "type": 1,
                        "components": [
                            {
                                "type": 4,
                                "custom_id": "fit_eft",
                                "label": "Copier-coller EFT",
                                "style": 2,
                                "min_length": 3,
                                "max_length": 4000,
                                "required": True,
                                "placeholder": "[Retribution, Nom du fit]\n...",
                            }
                        ],
                    },
                    {
                        "type": 1,
                        "components": [
                            {
                                "type": 4,
                                "custom_id": "fit_notes",
                                "label": "Notes du créateur (facultatif)",
                                "style": 2,
                                "max_length": 500,
                                "required": False,
                                "placeholder": "Ex. Capacitor Management V recommandé...",
                            }
                        ],
                    },
                ],
            },
        })

    # ========================================================
    # /guide-membre + /guide-staff
    # V3 — private visual command guides
    # Both responses are always ephemeral (visible only to caller).
    # ========================================================

    if command_name == "guide-membre":

        guide_member_image_url = (
            f"{PUBLIC_BASE_URL}"
            "/assets/guide-membre.png"
        )

        return jsonify({
            "type": 4,
            "data": {
                "embeds": [
                    {
                        "title": "📘 GUIDE MEMBRE — FREEBORN VERIFY V3",
                        "description": (
                            "Guide personnel des commandes et du parcours "
                            "Freeborn Legacy."
                        ),
                        "image": {"url": guide_member_image_url},
                        "color": 0xD9A21B,
                        "footer": {
                            "text": "Freeborn Legacy • Guide Membre"
                        },
                    }
                ],
                "flags": 64,
            },
        })

    if command_name == "guide-staff":

        try:
            member_roles = {
                str(role_id)
                for role_id in data["member"]["roles"]
            }
        except (KeyError, TypeError):
            member_roles = set()

        if not (member_roles & MODERATION_ROLE_IDS):
            return jsonify({
                "type": 4,
                "data": {
                    "content": (
                        "⛔ **Accès refusé**\n\n"
                        "Le Guide Staff est réservé aux rôles **CEO**, "
                        "**Haut Conseil**, **Direction**, "
                        "**Ressources Humaines** et **Officier**."
                    ),
                    "flags": 64,
                },
            })

        guide_staff_image_url = (
            f"{PUBLIC_BASE_URL}"
            "/assets/guide-staff.png"
        )

        return jsonify({
            "type": 4,
            "data": {
                "embeds": [
                    {
                        "title": "🛡️ GUIDE STAFF — FREEBORN VERIFY V3",
                        "description": (
                            "Référence privée des commandes de gestion "
                            "et du parcours de recrutement."
                        ),
                        "image": {"url": guide_staff_image_url},
                        "color": 0xD9A21B,
                        "footer": {
                            "text": "Freeborn Legacy • Guide Staff"
                        },
                    }
                ],
                "flags": 64,
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
        state_data.get(
            "discord_user_id"
        )
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

    if verification_type in {"freeborn", "fit_pilot"}:

        missing_scopes = (
            set(FREEBORN_EVE_SCOPES)
            -
            set(granted_scopes)
        )

        if missing_scopes:

            return freeborn_web_page(
                "Autorisation ESI incomplète",
                (
                    "Le scope ESI nécessaire aux compétences n'a pas été accordé. "
                    + (
                        "Retourne sur la fiche Freeborn Fittings et relance "
                        "« Tester avec mon personnage »."
                        if verification_type == "fit_pilot"
                        else
                        "Relance /freeborn et accepte l'autorisation EVE demandée."
                    )
                ),
                status="error",
                character_name=character_name,
            ), 403

        if (
            verification_type == "freeborn"
            and
            not refresh_token
        ):

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

    affiliation_source = "characters/affiliation"
    affiliation_result = get_eve_character_affiliation(
        character_id
    )

    if affiliation_result:

        character_data = (
            affiliation_result["data"]
        )

        corporation_response = (
            affiliation_result["response"]
        )

        corporation_id = (
            character_data[
                "corporation_id"
            ]
        )

    else:

        # Fallback to the existing public character route so an outage or
        # unexpected response from /characters/affiliation/ does not break
        # the integration flow.
        affiliation_source = "characters/{character_id}"

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

        corporation_response = (
            character_response
        )

    # ========================================================
    # TEMPORARY ESI CORPORATION DIAGNOSTIC
    # Safe diagnostic only: no token, code, state or secret logged.
    # ========================================================

    esi_date = corporation_response.headers.get(
        "Date",
        "",
    )

    esi_expires = corporation_response.headers.get(
        "Expires",
        "",
    )

    esi_age = corporation_response.headers.get(
        "Age",
        "",
    )

    esi_etag = corporation_response.headers.get(
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
        f"affiliation_source={affiliation_source!r} "
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
    # FREEBORN FITTINGS — PILOT TEST SSO
    # ========================================================

    if verification_type == "fit_pilot":

        try:
            fit_id = int(state_data["fit_id"])
            fit_web_token = str(state_data["fit_web_token"])
        except (KeyError, TypeError, ValueError):
            return freeborn_web_page(
                "Test pilote invalide",
                "Le lien de test du fitting est incomplet. Retourne sur la fiche et relance le test.",
                status="error",
                character_name=character_name,
            ), 400

        pilot_record = get_guild_main_by_character_id_v3(
            guild_id,
            character_id,
        )

        if (
            not pilot_record
            or
            not pilot_record["in_corporation"]
        ):
            return freeborn_web_page(
                "Main EVE non reconnu",
                (
                    "Ce personnage n'est pas enregistré comme Main Freeborn "
                    "pour ce serveur. Utilise d'abord /freeborn sur Discord "
                    "avec ton Main EVE."
                ),
                status="warning",
                character_name=character_name,
            ), 403

        try:
            update_guild_main_skills_snapshot_v3(
                guild_id,
                character_id,
                skill_summary,
            )
        except Exception as error:
            print(
                "Freeborn Fittings pilot snapshot refresh failed:",
                repr(error),
            )
            return freeborn_web_page(
                "Profil pilote indisponible",
                "Freeborn n'a pas pu actualiser les compétences de ce Main EVE.",
                status="warning",
                character_name=character_name,
            ), 500

        pilot_token = fit_pilot_serializer.dumps({
            "guild_id": str(guild_id),
            "fit_id": int(fit_id),
            "character_id": int(character_id),
        })

        target_url = (
            f"{PUBLIC_BASE_URL}/fittings/"
            f"{format_fit_reference(fit_id)}?"
            + urlencode({
                "token": fit_web_token,
                "pilot": pilot_token,
            })
        )

        return redirect(target_url)

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
                skills_snapshot=skill_summary["skills"],
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
                "fit-creer",

            "description":
                "Proposer un fitting Freeborn à partir d'un copier-coller EFT",

            "type":
                1,
        },

        {
            "name":
                "fit-liste",

            "description":
                "Afficher la bibliothèque des fittings Freeborn",

            "type":
                1,
        },

        {
            "name":
                "fit-afficher",

            "description":
                "Publier la fiche d'un fitting Freeborn",

            "type":
                1,

            "options": [
                {
                    "type": 3,
                    "name": "ref",
                    "description": "Référence du fit (ex. FREE-0001)",
                    "required": True,
                }
            ],
        },

        {
            "name":
                "fit-approuver",

            "description":
                "Valider un fitting comme FREEBORN APPROVED",

            "type":
                1,

            "default_member_permissions":
                "0",

            "options": [
                {
                    "type": 3,
                    "name": "ref",
                    "description": "Référence du fit (ex. FREE-0001)",
                    "required": True,
                }
            ],
        },

        {
            "name":
                "fit-refuser",

            "description":
                "Refuser un fitting proposé",

            "type":
                1,

            "default_member_permissions":
                "0",

            "options": [
                {
                    "type": 3,
                    "name": "ref",
                    "description": "Référence du fit (ex. FREE-0001)",
                    "required": True,
                }
            ],
        },

        {
            "name":
                "fit-supprimer",

            "description":
                "Supprimer définitivement un fitting Freeborn",

            "type":
                1,

            "options": [
                {
                    "type": 3,
                    "name": "ref",
                    "description": "Référence du fit (ex. FREE-0001)",
                    "required": True,
                }
            ],
        },

        {
            "name":
                "guide-membre",

            "description":
                "Afficher ton guide privé Freeborn Verify V3",

            "type":
                1,
        },

        {
            "name":
                "guide-staff",

            "description":
                "Afficher le guide privé des commandes staff V3",

            "type":
                1,

            "default_member_permissions":
                "0",
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
                "/freeborn, /fit-creer, /fit-liste, /fit-afficher, /fit-approuver, /fit-refuser, /fit-supprimer, "
                "/guide-membre, /guide-staff, /verification, "
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

# ============================================================
# PHASE 4O-H — ADVANCED CAPACITOR MODEL
# ============================================================

CAPACITOR_EFFECT_CLASSES = {
    "continuous_consumer": (
        "microwarpdrive", "afterburner", "shield booster", "armor repairer",
        "armor repair", "hardener", "tracking computer", "guidance computer",
        "sensor booster", "remote", "ecm", "warp disrupt", "warp scram",
        "stasis web", "target painter", "cloaking device", "tractor beam",
    ),
    "conditional_source": ("nosferatu", "energy nosferatu"),
    "active_injector": ("capacitor booster", "cap booster"),
    "energy_transfer": ("energy transfer", "remote capacitor"),
}

def classify_capacitor_item(type_name):
    name = (type_name or "").strip().lower()
    if not name:
        return "neutral_or_unknown"
    for cls in ("conditional_source", "active_injector", "energy_transfer"):
        if any(token in name for token in CAPACITOR_EFFECT_CLASSES[cls]):
            return cls
    if any(token in name for token in CAPACITOR_EFFECT_CLASSES["continuous_consumer"]):
        return "continuous_consumer"
    return "neutral_or_unknown"

def build_capacitor_activity_audit(item_names):
    audit = {
        "continuous_consumers": [], "conditional_sources": [],
        "active_injectors": [], "energy_transfers": [],
        "neutral_or_unknown": [],
    }
    keymap = {
        "continuous_consumer": "continuous_consumers",
        "conditional_source": "conditional_sources",
        "active_injector": "active_injectors",
        "energy_transfer": "energy_transfers",
        "neutral_or_unknown": "neutral_or_unknown",
    }
    for item in item_names or []:
        audit[keymap[classify_capacitor_item(item)]].append(item)
    return audit


def build_fitted_capacitor_activity_audit(
    eft_sections,
):
    """
    Build a capacitor-behaviour audit from the modules actually fitted.

    Returns display-ready rows with quantities. Cargo, drones and charges
    are deliberately excluded.
    """
    fitted_lines = (
        eft_sections.get("low", [])
        + eft_sections.get("mid", [])
        + eft_sections.get("high", [])
        + eft_sections.get("rigs", [])
    )

    counts = {}

    for raw_line in fitted_lines:
        item_name = normalize_eft_item_name(raw_line)

        if not item_name:
            continue

        key = item_name.casefold()

        if key not in counts:
            counts[key] = {
                "name": item_name,
                "quantity": 0,
            }

        counts[key]["quantity"] += 1

    audit = {
        "continuous_consumers": [],
        "conditional_sources": [],
        "active_injectors": [],
        "energy_transfers": [],
        "neutral_or_unknown": [],
    }

    keymap = {
        "continuous_consumer": "continuous_consumers",
        "conditional_source": "conditional_sources",
        "active_injector": "active_injectors",
        "energy_transfer": "energy_transfers",
        "neutral_or_unknown": "neutral_or_unknown",
    }

    for row in counts.values():
        classification = classify_capacitor_item(
            row["name"]
        )

        audit[keymap[classification]].append(
            row
        )

    return audit


def format_capacitor_audit_items(rows):
    """Compact HTML-safe list such as '1× Corpus X-Type Heavy Energy Nosferatu'."""
    if not rows:
        return "Aucun"

    parts = []

    for row in rows:
        quantity = int(
            row.get("quantity", 1)
            or 1
        )
        name = escape(
            str(
                row.get("name")
                or "Module inconnu"
            )
        )

        parts.append(
            f"{quantity}× {name}"
        )

    return " • ".join(parts)


def capacitor_verdict_policy(base_projection, audit):
    audit = audit or {}
    conditional = (
        audit.get("conditional_sources", [])
        + audit.get("active_injectors", [])
        + audit.get("energy_transfers", [])
    )
    if conditional:
        return {
            "projection": base_projection,
            "verdict": "PROJECTION CONDITIONNELLE",
            "is_final_eve_verdict": False,
            "reason": "Source, injection ou transfert de capaciteur conditionnel détecté.",
            "conditional_items": conditional,
        }
    return {
        "projection": base_projection,
        "verdict": "PROJECTION ALL-ACTIVE",
        "is_final_eve_verdict": False,
        "reason": "Projection théorique limitée aux effets Dogma actuellement couverts.",
        "conditional_items": [],
    }


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
