# utils/stego_embed.py

from pathlib import Path
import cv2
import numpy as np

# ------------------------------------------------------------
# Utility functions to embed/extract payload bytes into/from images
# using LSB of the blue channel (1 bit per pixel). PNG recommended.
# ------------------------------------------------------------

def _bytes_to_bits(b: bytes) -> np.ndarray:
    """Convert bytes to numpy array of bits (0/1)."""
    bits = np.unpackbits(np.frombuffer(b, dtype=np.uint8))
    return bits.astype(np.uint8)

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    """Convert numpy array of bits (length multiple of 8) to bytes."""
    arr = np.packbits(bits.astype(np.uint8))
    return arr.tobytes()

def capacity_pixels(img_shape):
    """Return available bits capacity when using one LSB in blue channel."""
    h, w, c = img_shape
    return h * w  # 1 bit per pixel in blue channel

# ------------------------------------------------------------
# Embed payload into image
# ------------------------------------------------------------
def embed_payload_in_image(in_image_path: str, out_image_path: str, payload_bytes: bytes):
    """
    Embed payload_bytes into in_image_path and write to out_image_path.
    Raises ValueError if not enough capacity.
    """
    img = cv2.imread(str(in_image_path), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Cannot read image: {in_image_path}")
    h, w, c = img.shape
    if c < 3:
        raise ValueError("Image must have 3 color channels (BGR)")

    # Header: 4-byte payload length
    payload_len = len(payload_bytes)
    if payload_len >= (1 << 32):
        raise ValueError("Payload too large (>4GB)")
    header = payload_len.to_bytes(4, byteorder='big')
    data = header + payload_bytes

    # Convert to bits
    bits = _bytes_to_bits(data)
    needed = bits.size
    cap = capacity_pixels(img.shape)
    if needed > cap:
        raise ValueError(f"Not enough capacity: need {needed} bits, capacity {cap} bits. Use larger image.")

    # Embed bits into LSB of blue channel
    flat_blue = img[:, :, 0].flatten()
    flat_blue[:needed] = (flat_blue[:needed] & ~1) | bits
    img[:, :, 0] = flat_blue.reshape((h, w))

    # Write PNG (lossless) to preserve embedded bits
    cv2.imwrite(str(out_image_path), img, [cv2.IMWRITE_PNG_COMPRESSION, 3])

    return out_image_path

# ------------------------------------------------------------
# Extract payload from image
# ------------------------------------------------------------
def extract_payload_from_image(image_path: str) -> bytes:
    """
    Extracts payload bytes from an image created with embed_payload_in_image.
    Returns payload_bytes (without 4-byte header).
    """
    img = cv2.imread(str(image_path), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(f"Cannot read image: {image_path}")
    h, w, c = img.shape
    flat_blue = img[:, :, 0].flatten()

    # Read header (first 4 bytes = 32 bits) for payload length
    header_bits = flat_blue[:32] & 1
    header_bytes = _bits_to_bytes(header_bits)
    payload_len = int.from_bytes(header_bytes, byteorder='big')

    total_bits = 32 + payload_len * 8
    cap = capacity_pixels(img.shape)
    if total_bits > cap:
        raise ValueError(f"Payload length header claims {payload_len} bytes but capacity is {cap//8} bytes.")

    # Extract payload bits
    bits = flat_blue[:total_bits] & 1
    payload_bytes = _bits_to_bytes(bits[32:])  # skip header
    return payload_bytes
