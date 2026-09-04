"""MEMVERSE Image Scanner — EXIF strip, format validate, hash + base64.

Pure Python (Pillow). No external services. Used by the backend API gate
to validate, sanitise, and hash image uploads before they enter the pipeline.
"""

import hashlib
import base64
from io import BytesIO

from PIL import Image


# ---------------------------------------------------------------------------
# Operation 1 — Size check: reject anything >10MB before even opening it.
# ---------------------------------------------------------------------------
def check_size(bytes_: bytes, max_bytes: int = 10 * 1024 * 1024) -> str | None:
    """Return error string if image exceeds max_bytes, else None."""
    if len(bytes_) > max_bytes:
        return f"Image size {len(bytes_) // 1024}KB exceeds 10MB limit"
    return None


# ---------------------------------------------------------------------------
# Operation 2 — Format validation: Pillow must open it; allowed formats only.
# ---------------------------------------------------------------------------
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP", "GIF"}


def validate_format(filename: str, bytes_: bytes) -> str | None:
    """Return error string if format is invalid, else None."""
    try:
        img = Image.open(BytesIO(bytes_))
        if img.format not in ALLOWED_FORMATS:
            return f"Unsupported format: {img.format}. Allowed: {', '.join(ALLOWED_FORMATS)}"
        return None
    except Exception as e:
        return f"Invalid image file: {e}"


# ---------------------------------------------------------------------------
# Operation 3 — EXIF strip: recreate image from pixel data, no info dict.
#    Critical: we must NOT just drop the EXIF tag — we must rebuild the image
#    so that no hidden EXIF trailer survives.
def strip_exif(bytes_: bytes, max_dim: int = 1200) -> tuple[bytes, bytes]:
    """Strip EXIF metadata and resize safely to preserve memory (Render Free 512MB RAM).

    Returns (clean_bytes, original_hash) where:
      - clean_bytes: new image bytes with NO EXIF information, bounded resolution
      - original_hash: SHA-256 of the original bytes (for audit)
    """
    original_hash = hashlib.sha256(bytes_).hexdigest()

    with Image.open(BytesIO(bytes_)) as img:
        # Convert to RGB directly to drop alpha/palette without allocating large raw lists
        rgb_img = img.convert("RGB")
        
        # Downscale proportionally if resolution exceeds max_dim to avoid OOM spikes
        if max(rgb_img.width, rgb_img.height) > max_dim:
            rgb_img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

        out_buf = BytesIO()
        # Saving freshly converted RGB image without info dict strips 100% of EXIF trailers
        rgb_img.save(out_buf, format="JPEG", quality=80, optimize=True)
        clean_bytes = out_buf.getvalue()

    return clean_bytes, original_hash


# ---------------------------------------------------------------------------
# Operation 4 — Hash + base64
# ---------------------------------------------------------------------------
def compute_hash(bytes_: bytes) -> str:
    """SHA-265 hex digest of raw bytes."""
    return hashlib.sha256(bytes_).hexdigest()


def to_base64(bytes_: bytes) -> str:
    """Base64-encode image bytes for API transmission."""
    return base64.b64encode(bytes_).decode("utf-8")


# ---------------------------------------------------------------------------
# Public API: process_image_upload
#    Sequences the 4 operations and returns a metadata dict.
#    Never returns image bytes to callers outside this module.
# ---------------------------------------------------------------------------
def process_image_upload(bytes_: bytes, filename: str, face_declared: str = "false", consent: bool = True) -> dict:
    """Run the full 4-operation pipeline on an uploaded image.

    Returns dict with keys:
      success: bool
      error: str | None   — present only if success == False
      original_hash: str
      clean_hash: str
      clean_b64: str      — base64 of EXIF-stripped image (JPEG, compressed)
      dimensions: {w, h}
      format: str
      face_declared: str
      consent: bool
    """
    # --- Operation 1: Size check ---
    size_err = check_size(bytes_)
    if size_err:
        return {"success": False, "error": size_err, "face_declared": face_declared, "consent": consent}

    # --- Operation 2: Format validation ---
    fmt_err = validate_format(filename, bytes_)
    if fmt_err:
        return {"success": False, "error": fmt_err, "face_declared": face_declared, "consent": consent}

    # --- Operation 3: EXIF strip ---
    clean_bytes, original_hash = strip_exif(bytes_)
    clean_hash = compute_hash(clean_bytes)
    clean_b64 = to_base64(clean_bytes)

    # --- Operation 4: Metadata assembly ---
    try:
        img = Image.open(BytesIO(bytes_))
        dimensions = {"w": img.width, "h": img.height}
        fmt = img.format or "JPEG"
    except Exception:
        dimensions = {"w": 0, "h": 0}
        fmt = "JPEG"

    result = {
        "success": True,
        "error": None,
        "original_hash": original_hash,
        "clean_hash": clean_hash,
        "clean_b64": clean_b64,
        "dimensions": dimensions,
        "format": fmt,
        "face_declared": face_declared,
        "consent": consent,
    }
    return result