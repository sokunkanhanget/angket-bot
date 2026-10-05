"""
tests/test_update_logging.py
==============================
The per-update log line must describe an update's shape, never its content.

Privacy fix (2026-10-05): bot.py used to log full Message objects at INFO -
text, names and @usernames for every update, including Business chat, where
the sender is a business owner's CUSTOMER who never used this bot. All of it
landed in Render's log stream.

Built from real python-telegram-bot objects (Update.de_json), not mocks, so
attribute access matches what production updates actually carry.
"""

from __future__ import annotations

import datetime

from telegram import Bot, Update

from bot.bot import summarize_update

_BOT = Bot("123456:FAKE_TOKEN_FOR_THIS_TEST")
_NOW = int(datetime.datetime(2026, 10, 5, tzinfo=datetime.timezone.utc).timestamp())

SECRET_TEXT = "my ABA pin is 4821 and my password is hunter2"
FIRST, LAST, HANDLE = "Sokha", "Chan", "sokha_private"


def _update(payload: dict) -> Update:
    return Update.de_json(payload, _BOT)


def _user(uid=777001):
    return {"id": uid, "is_bot": False, "first_name": FIRST, "last_name": LAST, "username": HANDLE}


def _private_message(text=SECRET_TEXT, **extra):
    return {
        "message_id": 55, "date": _NOW, "text": text,
        "chat": {"id": 777001, "type": "private", "first_name": FIRST, "username": HANDLE},
        "from": _user(), **extra,
    }


def _assert_no_content_or_identity(line: str) -> None:
    for leaked in (SECRET_TEXT, "4821", "hunter2", FIRST, LAST, HANDLE):
        assert leaked not in line, f"{leaked!r} leaked into the log line: {line}"


def test_private_message_text_and_names_never_reach_the_log():
    line = summarize_update(_update({"update_id": 1, "message": _private_message()}))

    _assert_no_content_or_identity(line)
    assert "user=777001" in line          # pseudonymous id kept for support
    assert f"text_len={len(SECRET_TEXT)}" in line


def test_business_customer_messages_are_not_logged():
    # The strongest case: the customer never interacted with the bot.
    payload = {"update_id": 2, "business_message": {
        **_private_message(), "business_connection_id": "conn-1",
    }}
    line = summarize_update(_update(payload))

    _assert_no_content_or_identity(line)
    assert "kind=business_message" in line
    assert "business=yes" in line


def test_check_reply_debugging_signal_is_preserved():
    # /check-as-reply was debugged entirely from whether reply_to_message
    # arrived. Keep that flag and the command word, drop the replied text
    # and any arguments.
    replied = _private_message(text="send me $500 now, urgent")
    payload = {"update_id": 3, "message": {
        **_private_message(text="/check@AngketIs_bot https://evil.example/login"),
        "chat": {"id": -100123, "type": "supergroup", "title": "Family Group"},
        "reply_to_message": replied,
        "entities": [{"type": "bot_command", "offset": 0, "length": 19}],
    }}
    line = summarize_update(_update(payload))

    assert "reply_to=yes" in line
    assert "command=/check@AngketIs_bot" in line
    assert "evil.example" not in line
    assert "$500" not in line
    assert "Family Group" not in line
    assert "chat_type=supergroup" in line


def test_document_name_is_not_logged_only_its_size():
    payload = {"update_id": 4, "message": {
        "message_id": 9, "date": _NOW,
        "chat": {"id": 777001, "type": "private"}, "from": _user(),
        "document": {"file_id": "f", "file_unique_id": "u",
                     "file_name": "Sokha_Chan_ID_card.pdf.rar", "file_size": 1600000},
    }}
    line = summarize_update(_update(payload))

    assert "ID_card" not in line
    assert "document_bytes=1600000" in line


def test_updates_without_a_message_still_summarize():
    payload = {"update_id": 5, "callback_query": {
        "id": "cb", "from": _user(), "chat_instance": "ci", "data": "lang:km",
    }}
    line = summarize_update(_update(payload))

    assert "kind=callback_query" in line
    assert "lang:km" not in line
    _assert_no_content_or_identity(line)
