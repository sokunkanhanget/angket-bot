"""
bot/route.py
=============
Routing policy for handler group 2 (teammate's text/LLM scanner) — see
bot.py's Handler groups comment for the full picture.
"""

from telegram.ext import filters

# GROUP/supergroup and plain PRIVATE chat only. Business chat is excluded
# entirely: it's fully owned by handle_business_message (bot.py group 3),
# which checks text, links, AND files together in one call and reports
# privately to the owner - handle_text firing here too would either
# duplicate that (link-free messages) or reply directly in the business
# chat where the customer could see it (handle_text has no owner-DM logic
# at all).
TEXT_FILTER = (filters.TEXT | filters.CAPTION) & ~filters.COMMAND & ~filters.UpdateType.BUSINESS_MESSAGE
