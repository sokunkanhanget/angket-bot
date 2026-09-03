"""
tests/test_business_message.py
================================
Tests for handle_business_message - the unified text+link+file check for
Telegram Business chat automation. Business chat is fully owned by this
handler now (see bot/route.py and bot.py's group 3), so these cover both
"stays silent" and "notifies the owner privately" behavior.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import bot.context_engine as context_engine
from bot.url_checker.message.handler import handle_business_message


def _business_update(text=None, has_document=False):
    update = MagicMock()
    update.effective_message.text = text
    update.effective_message.caption = None
    update.effective_message.business_connection_id = "conn1"
    update.effective_message.document = MagicMock(file_id="fake-doc") if has_document else None
    update.effective_message.photo = None
    update.effective_message.date = None
    update.effective_user = MagicMock(full_name="Customer", id=42)
    return update


def _context():
    context = MagicMock()
    context.bot_data = {"_vectors_seeded": True}
    context.bot.send_message = AsyncMock()
    return context


@pytest.mark.asyncio
async def test_stays_silent_when_there_is_truly_nothing_to_check():
    # No text, no caption, no link, no file - genuinely nothing to
    # reason about (e.g. a plain photo with no caption at all - there is
    # no image-content scanning in this bot).
    update = _business_update(text=None)
    context = _context()

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)):
        await handle_business_message(update, context)

    context.bot.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_stays_silent_for_genuinely_benign_text():
    # Text IS present, but the full Gemini reasoning (not a crude local
    # keyword list) judges it not a scam - must not notify the owner
    # for every mundane customer message.
    update = _business_update(text="hey, are we still on for lunch?")
    context = _context()

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Not a Scam",
             "risk_percentage": 5,
             "key_reasons": [],
             "recommendations": [],
         })):
        await handle_business_message(update, context)

    context.bot.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_notifies_owner_for_scam_text_with_no_keyword_match_no_link_no_file():
    # Regression: this is the exact bug found live-testing - gating on
    # the crude local keyword list (instead of the full Gemini verdict)
    # silently missed a "Hi Mom, send $800 now, don't call" style
    # family-emergency scam, since it matches none of
    # bot.config.SUSPICIOUS_KEYWORDS and has no link or file at all.
    update = _business_update(
        text="Mom, this is urgent, send $800 right now, don't call, just trust me."
    )
    context = _context()

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Classic family-emergency scam pattern", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()


@pytest.mark.asyncio
async def test_notifies_owner_for_suspicious_text():
    update = _business_update(text="URGENT: send $800 now, don't call, just trust me")
    context = _context()

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": ["Verify independently"],
         })):
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()
    kwargs = context.bot.send_message.call_args.kwargs
    assert kwargs["chat_id"] == 555
    assert "LIKELY A SCAM" in kwargs["text"]
    assert "Urgent money request" in kwargs["text"]


@pytest.mark.asyncio
async def test_stays_silent_when_owner_cannot_be_resolved():
    update = _business_update(text="URGENT: send $800 now")
    context = _context()

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=None)):
        await handle_business_message(update, context)

    context.bot.send_message.assert_not_awaited()


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

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler.scan_vt_hash", AsyncMock(return_value={
             "found": True, "malicious": 0, "suspicious": 0, "total": 70,
         })), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Not a Scam",
             "risk_percentage": 5,
             "key_reasons": [{"text": "File is clean on VirusTotal", "source": "file_evidence"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()
    # file_verdict must have actually been passed through to the unified call
    _, kwargs = mock_unified.call_args
    args = mock_unified.call_args.args
    passed_file_verdict = args[3] if len(args) > 3 else kwargs.get("file_verdict")
    assert passed_file_verdict["malicious"] == 0
    assert "📄" in context.bot.send_message.call_args.kwargs["text"]


@pytest.mark.asyncio
async def test_stays_silent_for_benign_text_during_a_real_gemini_outage(fake_vector_store, monkeypatch):
    # Regression for the exact bug the /code-review pass found: the
    # fallback verdict used to be able to return only "Scam" or
    # "Uncertain", never "Not a Scam", so a Gemini outage meant the
    # owner got notified on EVERY customer message, including mundane
    # ones. This exercises the REAL analyze_unified -> _grounded_fallback
    # path (not mocked), with the client forced to None to simulate an
    # outage, through the full handler.
    monkeypatch.setattr(context_engine, "_client", None)

    update = _business_update(text="hey, are we still on for lunch tomorrow?")
    context = _context()

    with patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)):
        await handle_business_message(update, context)

    context.bot.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_notifies_owner_for_near_exact_scam_script_during_a_real_gemini_outage(fake_vector_store, monkeypatch):
    # The other half of the same regression: a near-verbatim repeat of a
    # known scam script must still notify even in degraded (no-LLM) mode.
    monkeypatch.setattr(context_engine, "_client", None)
    await fake_vector_store.seed()

    update = _business_update(
        text=("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
              "I need you to send $800 right now to help me, don't call, just trust me "
              "on this one time.")
    )
    context = _context()

    with patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)):
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()
    assert "offline pattern matching only" in context.bot.send_message.call_args.kwargs["text"]


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

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": False, "matches": []}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=real_link_verdict)), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 80,
             "key_reasons": [{"text": "Dangerous link", "source": "link_evidence"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    context.bot.send_message.assert_awaited_once()
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

    with patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=real_link_verdict)), \
         patch("bot.url_checker.message.handler.download_and_hash", AsyncMock(side_effect=RuntimeError("file too large"))), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 80,
             "key_reasons": [{"text": "Dangerous link", "source": "link_evidence"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    # The owner must still be notified about the link, not left with nothing.
    context.bot.send_message.assert_awaited_once()
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
    update = _business_update(text="URGENT: send $800 now, don't call")
    context = _context()
    owner_chat_id = 555
    # The owner previously ran /start and switched to Khmer in their own
    # private chat with the bot - that's exactly what text_handler.py's
    # start()/handle_text() would have written into this same store.
    context.application.user_data = {owner_chat_id: {"lang": "km"}}

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=owner_chat_id)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "សំណើសុំប្រាក់បន្ទាន់", "source": "message_text"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    # The Khmer verdict label must render, not the English one.
    body = context.bot.send_message.call_args.kwargs["text"]
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

    with patch("bot.url_checker.message.handler.analyze_text", return_value={"suspicious": True, "matches": ["urgent"]}), \
         patch("bot.url_checker.message.handler.extract_text_link_entities", return_value=[]), \
         patch("bot.url_checker.message.handler.check_message_full", AsyncMock(return_value=[])), \
         patch("bot.url_checker.message.handler._owner_chat_id", AsyncMock(return_value=555)), \
         patch("bot.url_checker.message.handler.analyze_unified", AsyncMock(return_value={
             "verdict": "Scam",
             "risk_percentage": 95,
             "key_reasons": [{"text": "Urgent money request", "source": "message_text"}],
             "recommendations": [],
         })) as mock_unified:
        await handle_business_message(update, context)

    body = context.bot.send_message.call_args.kwargs["text"]
    assert "LIKELY A SCAM" in body
    assert mock_unified.call_args.args[4] == "en"
