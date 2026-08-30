"""
bot/route.py
=============
Routing policy for handler group 0 (teammate's text/LLM scanner) — see
bot.py's Handler groups comment for the full group 0/1 picture.
"""

from telegram.ext import filters

from bot.url_checker.features.lexical import URL_REGEX

# A business chat with a link still gets the link checker's full report
# via its own owner-DM flow (see url_checker/message/handler.py), so
# skip the text scanner there to avoid a second reply. A link can arrive
# either as plain message text or as a photo/document caption.
#
# Plain PRIVATE chat is NOT excluded here anymore: handle_text now
# reasons over text and any link together in one call (see
# bot/context_engine.py) rather than falling back to a link-only
# verdict that never saw why the message text itself was a scam.
_BUSINESS_LINK_TAKEOVER = filters.UpdateType.BUSINESS_MESSAGE & (
    filters.Regex(URL_REGEX) | filters.CaptionRegex(URL_REGEX)
)

TEXT_FILTER = (
    ((filters.TEXT | filters.CAPTION) & ~filters.COMMAND)
    | filters.UpdateType.BUSINESS_MESSAGE
) & ~_BUSINESS_LINK_TAKEOVER
