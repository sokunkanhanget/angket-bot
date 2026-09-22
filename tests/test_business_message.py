"""
tests/test_business_message.py
================================
Tests for handle_business_message - the unified text+link+file check for
Telegram Business chat automation. Business chat is fully owned by this
handler now (see bot/route.py and bot.py's group 3), so these cover both
"stays silent" and "notifies the owner privately" behavior.

Two-stage notification (2026-09-14, direct user spec): the owner used to
get ONE message only once the full check finished, with zero feedback
while it ran. Now a status message (header identifying WHO it's from +
"Checking...") goes out immediately via context.bot.send_message, then
gets edited in place (status.edit_text) once the real verdict is ready -
or deleted (status.delete) if the result turns out to be one of the
"stay silent" cases. _context()'s mocked send_message return value
(`status`) carries its own edit_text/delete AsyncMocks so tests can
assert on either stage independently.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import bot.context_engine.context_engine as context_engine
from bot.handlers.url_handler import handle_business_message
from bot.response.buttons import t
from bot.storage import subscription


def _business_update(text=None, has_document=False):
    update = MagicMock()
    update.effective_message.text = text
    update.effective_message.caption = None
    update.effective_message.business_connection_id = "conn1"
    update.effective_message.document = (
        MagicMock(file_id="fake-doc", file_name="invoice.pdf") if has_document else None
    )
    update.effective_message.photo = None
    update.effective_message.date = None
    # username=None explicitly - a bare MagicMock's unset attributes are
    # themselves truthy MagicMocks, which would silently defeat
    # _sender_header's "only show (@handle) when one really exists" check.
    update.effective_user = MagicMock(full_name="Customer", id=42, username=None)
    return update


def _context():
    context = MagicMock()
    context.bot_data = {"_vectors_seeded": True}
    status = MagicMock()
    status.edit_text = AsyncMock()
    status.delete = AsyncMock()
    context.bot.send_message = AsyncMock(return_value=status)
    return context


@pytest.mark.asyncio
async def test_status_message_shows_sender_header_immediately():
    # The actual feature: the owner must see WHO the message is from
    # right away, before the (possibly several-second) real check even
    # starts - not just a bare "Checking" with no context.
    update = _business_update(text="URGENT: send $800 now, don't call, just trust me")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam", "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": [],
         })):
        await handle_business_message(update, context)

    status_call = context.bot.send_message.call_args
    assert status_call.kwargs["chat_id"] == 555
    assert status_call.kwargs["text"].startswith(
        f"{t('en', 'business_new_activity')}\n\n👤 `Customer`\n🆔 42\n🕒 —\n\n"
    )
    assert t("en", "status_checking") in status_call.kwargs["text"]
    assert status_call.kwargs["parse_mode"] == "Markdown"


@pytest.mark.asyncio
async def test_final_verdict_edits_the_same_status_message():
    update = _business_update(text="URGENT: send $800 now, don't call, just trust me")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam", "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    # Only ONE message ever sent (the status message); the real verdict
    # lands via editing it, not a second send_message.
    context.bot.send_message.assert_awaited_once()
    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    body = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    assert "reply_markup" not in status.edit_text.call_args.kwargs  # direct user spec: no buttons
    assert "LIKELY A SCAM" in body
    assert "📁 *TYPE: text*" in body
    assert "Urgent money request" in body
    assert "─" not in body
    assert body.rstrip().endswith("Double-check important information before taking action.")
    assert body.startswith(f"{t('en', 'business_new_activity')}\n\n👤 `Customer`\n🆔 42\n🕒 —\n\n")
    status.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_flips_the_status_phase_before_the_gemini_call():
    # 2026-09-22 (direct user spec: "show the real detail" instead of one
    # static status line) - same real two-phase animation as the private-
    # DM/group /check path (see test_text_handler.py's equivalent test):
    # the phase Event handed to animate_status must be genuinely .set()
    # by the time analyze_unified runs, a real code event (evidence-
    # gathering finished), not a guessed timer.
    update = _business_update(text="URGENT: send $800 now, don't call, just trust me")
    context = _context()

    captured = {}

    async def _fake_animate_status(status, lang, suffix="", prefix="", phase=None):
        captured["phase"] = phase

    async def _fake_analyze_unified(*args, **kwargs):
        captured["phase_set_during_gemini_call"] = captured["phase"].is_set()
        return {"verdict": "Scam", "risk_percentage": 95, "key_reasons": [], "recommendations": []}

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", _fake_animate_status), \
         patch("bot.handlers.url_handler.analyze_unified", _fake_analyze_unified):
        await handle_business_message(update, context)

    assert captured["phase"] is not None
    assert captured["phase_set_during_gemini_call"] is True


@pytest.mark.asyncio
async def test_stays_silent_when_there_is_truly_nothing_to_check():
    # No text, no caption, no link, no file - genuinely nothing to
    # reason about (e.g. a plain photo with no caption at all - there is
    # no image-content scanning in this bot). The status message still
    # goes out (we don't know yet it'll be empty) but must be cleaned up
    # afterward, not left showing "Checking..." forever.
    update = _business_update(text=None)
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()):
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()  # the status message
    status = context.bot.send_message.return_value
    status.delete.assert_awaited_once()
    status.edit_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_stays_silent_for_genuinely_benign_text():
    # Text IS present, and the full Gemini reasoning (not a crude local
    # keyword list) judges it not a scam - product decision (2026-09-22,
    # matches the pitch deck's Live Scan flowchart): a safe TEXT-ONLY
    # message stays quiet, status deleted, no owner notification at all.
    # Link/file findings still always render regardless of verdict - this
    # silent path is text-only-specific.
    update = _business_update(text="hey, are we still on for lunch?")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Not a Scam",
             "risk_percentage": 5,
             "key_reasons": [],
             "recommendations": [],
         })):
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()
    status = context.bot.send_message.return_value
    status.delete.assert_awaited_once()
    status.edit_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_notifies_owner_for_scam_text_with_no_keyword_match_no_link_no_file():
    # Regression: this is the exact bug found live-testing - gating on
    # the crude local keyword list (instead of the full Gemini verdict)
    # silently missed a "Hi Mom, send $800 now, don't call" style
    # family-emergency scam, since it matches none of
    # bot.config.config.SUSPICIOUS_KEYWORDS and has no link or file at all.
    update = _business_update(
        text="Mom, this is urgent, send $800 right now, don't call, just trust me."
    )
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Classic family-emergency scam pattern", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    status.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_notifies_owner_for_suspicious_text():
    update = _business_update(text="URGENT: send $800 now, don't call, just trust me")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    kwargs = status.edit_text.call_args.kwargs
    body = kwargs.get("text") or status.edit_text.call_args.args[0]
    assert "reply_markup" not in kwargs  # direct user spec: no buttons
    assert "LIKELY A SCAM" in body
    assert "📁 *TYPE: text*" in body
    assert "Urgent money request" in body
    assert "─" not in body
    assert body.rstrip().endswith("Double-check important information before taking action.")
    # New spec: "👀 New Activity Detected" header + 👤/🆔/🕒 block above the
    # same body every other surface (text/link/file) renders.
    assert body.startswith(
        f"{t('en', 'business_new_activity')}\n\n👤 `Customer`\n🆔 42\n🕒 —\n\n"
    )


@pytest.mark.asyncio
async def test_sender_header_shows_at_handle_when_one_exists():
    # angket-bot-message.drawio spec: "From: username (@username)" - a
    # real gap this session found, since _sender_header used to render
    # only the display name, never the @handle at all. The header shows
    # up on the STATUS message (sent immediately), not just the final one.
    update = _business_update(text="URGENT: send $800 now, don't call, just trust me")
    update.effective_user = MagicMock(full_name="Customer", id=42, username="real_customer")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    status_text = context.bot.send_message.call_args.kwargs["text"]
    assert status_text.startswith(
        f"{t('en', 'business_new_activity')}\n\n👤 `Customer (@real_customer)`\n🆔 42\n🕒 —\n\n"
    )
    status = context.bot.send_message.return_value
    final_text = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    assert final_text.startswith(
        f"{t('en', 'business_new_activity')}\n\n👤 `Customer (@real_customer)`\n🆔 42\n🕒 —\n\n"
    )


@pytest.mark.asyncio
async def test_stays_silent_when_owner_cannot_be_resolved():
    update = _business_update(text="URGENT: send $800 now")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=None)):
        await handle_business_message(update, context)

    context.bot.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_stays_silent_for_the_owners_own_message():
    # Real bug, confirmed live: nothing distinguished "a customer messaged
    # the business" from "the business owner sent/replied to a message in
    # their own connected chat" - every message in the conversation, in
    # EITHER direction, got the full unified Gemini check, including the
    # owner's own casual replies ("Working now", "send again" were the
    # real examples that surfaced this). Also what was burning through the
    # Gemini free-tier quota so fast during testing - a short back-and-
    # forth meant several Gemini calls, not one. A private chat's chat_id
    # equals that user's own user_id in Telegram, and owner_chat_id IS
    # exactly the owner's user_id (BusinessConnection.user_chat_id) - so
    # sender.id == owner_chat_id reliably means "the owner sent this".
    update = _business_update(text="ok sounds good, talk soon")
    update.effective_user = MagicMock(full_name="Business Owner", id=555)
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])) as check_full, \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock()) as unified, \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)):
        await handle_business_message(update, context)

    context.bot.send_message.assert_not_awaited()
    # Must exit before doing ANY real work, not just before notifying -
    # this is the actual quota-burning fix, so it must never even reach
    # the link/Gemini checks for the owner's own messages.
    check_full.assert_not_awaited()
    unified.assert_not_awaited()


@pytest.mark.asyncio
async def test_attached_file_is_scanned_and_always_notifies():
    # A file being sent at all is worth telling the owner about, even if
    # VirusTotal comes back clean - matches handle_file's non-Business
    # behavior of never staying silent about a scanned file.
    update = _business_update(text=None, has_document=True)
    context = _context()

    fake_file = MagicMock()

    async def _download(buf):
        buf.write(b"fake file bytes")
    fake_file.download_to_memory = AsyncMock(side_effect=_download)
    context.bot.get_file = AsyncMock(return_value=fake_file)

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler.scan_file", AsyncMock(return_value={
             "found": True, "malicious": 0, "suspicious": 0, "total": 70,
         })), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Not a Scam",
             "risk_percentage": 5,
             "key_reasons": [{"text": "File is clean on VirusTotal", "source": "file_evidence"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    # file_verdict must have actually been passed through to the unified call
    kwargs = mock_unified.call_args.kwargs
    args = mock_unified.call_args.args
    passed_file_verdict = args[3] if len(args) > 3 else kwargs.get("file_verdict")
    assert passed_file_verdict["malicious"] == 0
    sent_text = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    # New spec: no filename/extension header any more (dropped project-wide
    # in favor of the "📁 TYPE:" line) - a file being part of the check is
    # now signalled there instead.
    assert "📁 *TYPE: file*" in sent_text


@pytest.mark.asyncio
async def test_a_filename_with_underscores_does_not_break_the_notification():
    # Real bug, confirmed live (when this reply used to render the raw
    # filename): Telegram's legacy Markdown treats a bare "_" as an
    # italics delimiter, and an odd number of underscores in a real
    # filename ("Week4_DOM_Lab_Exercises.docx") broke entity parsing
    # entirely. The filename is no longer rendered into this reply at
    # all (superseded by the "📁 TYPE:" line - see the previous test), so
    # that specific vector is gone; this just confirms an unusual
    # filename still can't break the notification some other way (e.g.
    # via scan_file/log_url_scan choking on it).
    update = _business_update(text=None, has_document=True)
    update.effective_message.document.file_name = "Week4_DOM_Lab_Exercises.docx"
    context = _context()

    fake_file = MagicMock()

    async def _download(buf):
        buf.write(b"fake file bytes")
    fake_file.download_to_memory = AsyncMock(side_effect=_download)
    context.bot.get_file = AsyncMock(return_value=fake_file)

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler.scan_file", AsyncMock(return_value={
             "found": True, "malicious": 0, "suspicious": 0, "total": 70,
         })), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Not a Scam", "risk_percentage": 5,
             "key_reasons": [{"text": "File is clean on VirusTotal", "source": "file_evidence"}],
             "recommendations": [],
         })):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    assert status.edit_text.call_args.kwargs["parse_mode"] == "Markdown"  # succeeded on the first try


@pytest.mark.asyncio
async def test_send_failure_falls_back_to_plain_text_instead_of_total_silence():
    # Defense-in-depth for the same real bug class: even with the
    # backtick fix above, a FUTURE unforeseen Markdown edge case must
    # not be able to silently kill the whole notification again, the
    # way it did before this fix existed. Every other failure mode in
    # this handler already degrades gracefully (Gemini down, VirusTotal
    # down) - this proves the very last step (editing in the real
    # verdict) does too. The risky step is now the EDIT, not the
    # original send (the status message's own "Checking..." text is
    # simple/fixed and can't hit a real filename's Markdown edge case).
    from telegram.error import BadRequest

    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()
    status = context.bot.send_message.return_value
    status.edit_text = AsyncMock(side_effect=[
        BadRequest("Can't parse entities: can't find end of the entity starting at byte offset 131"),
        None,  # the plain-text retry succeeds
    ])

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam", "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    assert status.edit_text.await_count == 2
    first_call, second_call = status.edit_text.await_args_list
    assert first_call.kwargs["parse_mode"] == "Markdown"
    assert "parse_mode" not in second_call.kwargs  # plain text - no entity parsing at all
    assert second_call.args[0] == first_call.args[0]  # same real verdict, just unformatted


@pytest.mark.asyncio
async def test_stays_silent_for_benign_text_during_a_real_gemini_outage(fake_vector_store, monkeypatch):
    # Regression for the exact bug the /code-review pass found: the
    # fallback verdict used to be able to return only "Scam" or
    # "Uncertain", never "Not a Scam". This exercises the REAL
    # analyze_unified -> _grounded_fallback path (not mocked), with the
    # client forced to None to simulate an outage, through the full
    # handler - a benign text-only message during an outage stays silent
    # (status deleted), same text-only-safe rule as the non-outage path.
    monkeypatch.setattr(context_engine, "_primary_pool", [])

    update = _business_update(text="hey, are we still on for lunch tomorrow?")
    context = _context()

    with patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.delete.assert_awaited_once()
    status.edit_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_notifies_owner_for_near_exact_scam_script_during_a_real_gemini_outage(fake_vector_store, monkeypatch):
    # The other half of the same regression: a near-verbatim repeat of a
    # known scam script must still notify even in degraded (no-LLM) mode.
    monkeypatch.setattr(context_engine, "_primary_pool", [])
    await fake_vector_store.seed()

    update = _business_update(
        text=("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
              "I need you to send $800 right now to help me, don't call, just trust me "
              "on this one time.")
    )
    context = _context()

    with patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    # 2026-09-11 spec: a degraded (no-AI) reply shows its OWN real
    # reasons/recommendations, not a generic "AI unavailable" admission
    # - see context_engine.py's _grounded_fallback and _FALLBACK_RECOMMENDATIONS.
    text = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    assert "offline pattern matching only" not in text
    assert "closely matches a known" in text  # the real scam-script-match reason
    assert "Verify with the sender through a separate channel" in text  # real recommendation


@pytest.mark.asyncio
async def test_photo_caption_is_checked_like_any_other_message():
    # No image-content scanning happens anywhere in this bot (team
    # decision: text, links, and files only - no QR/image analysis) -
    # but a photo's CAPTION is still just text, so it must go through
    # the same unified check as a plain text message rather than being
    # silently skipped just because the message happens to carry a photo.
    update = _business_update(text=None)
    update.effective_message.photo = [MagicMock(file_id="fake-photo")]
    update.effective_message.caption = "official update, click http://free-prize-winner.tk/claim"
    context = _context()

    real_link_verdict = [{"host": "free-prize-winner.tk", "level": "dangerous",
                           "score": 80, "reasons": ["scam TLD"]}]

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=real_link_verdict)), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 80,
             "key_reasons": [{"text": "Dangerous link", "source": "link_evidence"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    # the caption text must have actually reached analyze_unified, not an
    # empty string
    args = mock_unified.call_args.args
    assert args[0] == "official update, click http://free-prize-winner.tk/claim"


@pytest.mark.asyncio
async def test_a_failed_file_check_does_not_discard_an_already_successful_link_check():
    # Regression found by /code-review: the concurrent link+file gather
    # had no return_exceptions=True, so a file-check failure (Telegram
    # download limit, VirusTotal hiccup, etc.) crashed the whole handler
    # and discarded an ALREADY-SUCCEEDED link result - the owner learned
    # about neither, even though the link check had genuinely finished.
    update = _business_update(text="check this out http://free-prize-winner.tk/claim", has_document=True)
    context = _context()

    real_link_verdict = [{"host": "free-prize-winner.tk", "level": "dangerous",
                           "score": 80, "reasons": ["scam TLD"]}]

    with patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=real_link_verdict)), \
         patch("bot.handlers.url_handler.download_and_hash", AsyncMock(side_effect=RuntimeError("file too large"))), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 80,
             "key_reasons": [{"text": "Dangerous link", "source": "link_evidence"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    # The owner must still be notified about the link, not left with nothing.
    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    # analyze_unified must have received the real link result and None
    # for the file (not have been skipped entirely).
    args = mock_unified.call_args.args
    assert args[2] == real_link_verdict
    assert args[3] is None


@pytest.mark.asyncio
async def test_notification_uses_the_owners_language_not_the_customers():
    # The owner reads this notification, never the customer who sent the
    # message - must translate based on the OWNER's stored language
    # preference (Application.user_data, keyed by their own user_id/
    # chat_id), not context.user_data for the current (customer's) update.
    # Applies to BOTH the immediate status message and the final verdict.
    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()
    owner_chat_id = 555
    # The owner previously ran /start and switched to Khmer in their own
    # private chat with the bot - that's exactly what text_handler.py's
    # start()/handle_text() would have written into this same store.
    context.application.user_data = {owner_chat_id: {"lang": "km"}}

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=owner_chat_id)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "សំណើសុំប្រាក់បន្ទាន់", "source": "message_text"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    status_text = context.bot.send_message.call_args.kwargs["text"]
    assert t("km", "status_checking") in status_text

    status = context.bot.send_message.return_value
    body = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    # The Khmer verdict label must render, not the English one.
    assert "ទំនងជាការឆបោក" in body
    assert "LIKELY A SCAM" not in body
    # And analyze_unified itself must have been asked to respond in Khmer.
    assert mock_unified.call_args.args[4] == "km"


@pytest.mark.asyncio
async def test_notification_defaults_to_english_when_owner_has_no_stored_language():
    # The owner has never run /start directly - Application.user_data has
    # no entry for them at all. Must default cleanly to English, not
    # crash on a missing dict key.
    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()
    context.application.user_data = {}  # owner never interacted with the bot directly

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    body = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    assert "LIKELY A SCAM" in body
    assert mock_unified.call_args.args[4] == "en"


@pytest.mark.asyncio
async def test_live_detect_trial_expiry_blocks_automation_and_notifies_owner():
    # Once the owner's 7-day Live Detect trial has expired (and they're
    # not on the paid tier - is_paid_user() always False for now), the
    # automation must not run at all - the owner gets ONE notice instead
    # of a real scam-check reasoning over the customer's message. This
    # path returns BEFORE the two-stage status message even starts, so
    # it's still a single direct send_message, unlike the tests above.
    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()
    context.application.user_data = {}

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.check_message_full") as mock_check, \
         patch("bot.handlers.url_handler.analyze_unified") as mock_unified, \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch.object(subscription, "live_detect_allowed", return_value=False):
        await handle_business_message(update, context)

    # The cheap, local, offline keyword check runs regardless (no real
    # cost) - what matters is that the EXPENSIVE work (network trace,
    # vector search, the real Gemini call) never happens once expired.
    mock_check.assert_not_called()
    mock_unified.assert_not_called()
    context.bot.send_message.assert_awaited_once()
    call = context.bot.send_message.call_args
    assert call.kwargs["chat_id"] == 555
    assert "trial" in call.kwargs["text"].lower() or "Live Detect" in call.kwargs["text"]
    # Not the two-stage status message shape - a direct, final notice.
    status = context.bot.send_message.return_value
    status.edit_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_live_detect_trial_expiry_only_notifies_owner_once():
    # Direct user spec (2026-09-15): the owner is told Live Detect
    # stopped working ONCE, not on every customer message that arrives
    # while the trial is still over - previously every message re-sent
    # the same notice.
    context = _context()
    context.application.user_data = {}

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.check_message_full") as mock_check, \
         patch("bot.handlers.url_handler.analyze_unified") as mock_unified, \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch.object(subscription, "live_detect_allowed", return_value=False):
        first_update = _business_update(text="URGENT: send $800 now, don't call")
        await handle_business_message(first_update, context)
        context.bot.send_message.assert_awaited_once()  # 1st customer message: notified
        context.bot.send_message.reset_mock()

        second_update = _business_update(text="another urgent message")
        await handle_business_message(second_update, context)  # 2nd: silent

    mock_check.assert_not_called()
    mock_unified.assert_not_called()
    context.bot.send_message.assert_not_called()


@pytest.mark.asyncio
async def test_live_detect_within_trial_runs_normally():
    # Sanity check for the opposite branch - an active trial must not
    # block anything (already implicitly covered by every other test in
    # this file passing, but this pins it explicitly against a
    # `live_detect_allowed` mock instead of relying on the real 7-day
    # clock never having started for id 555 in other tests).
    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch.object(subscription, "live_detect_allowed", return_value=True), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam", "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    mock_unified.assert_awaited_once()


@pytest.mark.asyncio
async def test_unexpected_failure_mid_check_still_edits_the_status_message():
    # New failure path introduced by the two-stage flow: if something
    # inside the try block raises unexpectedly (not one of the per-task
    # failures asyncio.gather(..., return_exceptions=True) already
    # absorbs, and not one of analyze_unified's own internally-caught
    # failure modes, which never raise - see its docstring), the status
    # message must still get SOME real content (a translated "couldn't
    # finish checking" notice), not be left showing "Checking..."
    # forever with no error surfaced anywhere the owner can see.
    # ensure_vectors_seeded is awaited directly (not inside the gather),
    # so raising there is a clean way to exercise this specific path.
    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()

    with patch("bot.handlers.url_handler.ensure_vectors_seeded", AsyncMock(side_effect=RuntimeError("boom"))), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    body = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]
    assert t("en", "scan_failed") in body
    status.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_business_owner_gets_the_trusted_link_notice_not_the_full_template():
    # Real bug, found by code review (2026-09-16): handle_business_message
    # was the one caller of analyze_unified() that never checked
    # unified.get("trusted_link_notice_host") - a customer sending a bare
    # trusted-brand link (e.g. https://facebook.com) still produced the
    # full VERDICT/KEY REASONS/WHAT TO DO template for the owner instead
    # of the intended one-line notice every other surface already got.
    update = _business_update(text="https://facebook.com")
    context = _context()

    trusted_unified = {
        "verdict": "Not a Scam",
        "risk_percentage": 0,
        "key_reasons": [],
        "recommendations": [],
        "trusted_link_notice_host": "facebook.com",
    }

    with patch("bot.handlers.url_handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.handlers.url_handler.extract_text_link_entities", return_value=[]), \
         patch("bot.handlers.url_handler.check_message_full",
               AsyncMock(return_value=[{"host": "facebook.com", "score": 0, "level": "safe",
                                        "reasons": [], "detail": [], "trusted_brand": True}])), \
         patch("bot.handlers.url_handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.handlers.url_handler.animate_status", AsyncMock()), \
         patch("bot.handlers.url_handler.analyze_unified", AsyncMock(return_value=trusted_unified)):
        await handle_business_message(update, context)

    status = context.bot.send_message.return_value
    status.edit_text.assert_awaited_once()
    body = status.edit_text.call_args.kwargs.get("text") or status.edit_text.call_args.args[0]

    assert "facebook.com" in body
    assert "VERDICT" not in body
    assert "KEY REASONS" not in body
    # The header (who it's from) must still be there - only the
    # verdict/reasons/what-to-do part gets replaced by the short notice.
    assert "Customer" in body
