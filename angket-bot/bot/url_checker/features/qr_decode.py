"""
bot/url_checker/features/qr_decode.py
=======================================
QR codes shared as photos are invisible to the rest of this package -
extract_urls() only ever regexes message.text, and a Telegram photo
carries no text at all. Decodes any QR code in an image so its
content can be run through the exact same check_url()/pipeline flow
as a typed link.

Uses OpenCV's built-in QRCodeDetector - no external system binary
(zbar) required, same approach already proven in
next-gen-test/concepts/qr-link-detection-py.
"""

from __future__ import annotations

import cv2
import numpy as np

_detector = cv2.QRCodeDetector()


def decode_qr(image_bytes: bytes) -> str | None:
    """Decoded QR content, or None if no QR code is found / the image
    is unreadable. Never raises - a corrupt or non-image upload is
    just "nothing found", not a crash, same pattern as the rest of
    this package's best-effort network/DB helpers."""
    try:
        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        data, _points, _straight_qrcode = _detector.detectAndDecode(img)
        return data or None
    except Exception:                          # noqa: BLE001 - corrupt image data must not crash the bot
        return None
