-- supabase/schema.sql
-- ============================================================
-- Reference schema for angket-bot's Supabase Postgres tables.
-- NOT applied automatically by any code path - this project has no
-- migrations framework (see bot/detectors/url/offline/vectors.py's
-- url_vectors table, which has no SQL committed anywhere either, same
-- manual-provisioning convention). Run manually via Supabase's SQL
-- editor when provisioning or updating a project. Checked in (unlike
-- url_vectors) because this is the second and third table added this
-- way - one undocumented schema was tolerable, two wasn't.
-- ============================================================

-- Per-day Freemium/Individual usage counters (file/link/token quotas).
-- One row per (user_id, day); a new day gets a fresh row on first use
-- (see bot/storage/subscription.py's _get_or_create_today), which is
-- what makes the daily reset "free" - nothing has to zero anything out.
--
-- user_id is bigint, not integer - Telegram user ids can exceed 2^31,
-- which plain Postgres `integer` can't hold (SQLite's dynamically-typed
-- `integer` never had this ceiling, so this is a real fix, not cosmetic).
create table if not exists daily_usage (
    user_id bigint not null,
    usage_date date not null,
    files_used integer not null default 0,
    links_messages_used integer not null default 0,
    tokens_used integer not null default 0,
    file_limit_notified boolean not null default false,
    links_messages_limit_notified boolean not null default false,
    primary key (user_id, usage_date)
);

-- One row per user: Live Detect trial clock + its one-shot "trial
-- ended" notice flag + the user's chosen language. trial_started_at is
-- set once (insert ... on conflict do nothing) and never reset (see
-- subscription.py's module docstring for why - no real payment system
-- exists yet, so nothing currently clears an expired trial). lang is
-- nullable: null means "never explicitly chosen", callers fall back to
-- DEFAULT_LANG exactly like the old context.user_data.get("lang",
-- DEFAULT_LANG) did.
create table if not exists user_state (
    user_id bigint primary key,
    trial_started_at timestamptz,
    notified_trial_ended boolean not null default false,
    lang text,
    updated_at timestamptz not null default now()
);
