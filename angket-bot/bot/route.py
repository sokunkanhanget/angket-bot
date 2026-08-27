"""
bot/route.py
=============
Routing policy for handler group 0 (teammate's text/LLM scanner) — see
bot.py's Handler groups comment for the full group 0/1 picture.
"""

from telegram.ext import filters

from bot.linkchecker.lexical import URL_REGEX

# A private/business chat with a link already gets the link checker's
# full report, so skip the text scanner there to avoid a second reply.
# Business chat.type is "private" too, so ChatType.PRIVATE covers both.
_LINK_TAKEOVER = filters.ChatType.PRIVATE & filters.Regex(URL_REGEX)

TEXT_FILTER = (
    (filters.TEXT & ~filters.COMMAND) | filters.UpdateType.BUSINESS_MESSAGE
) & ~_LINK_TAKEOVER
