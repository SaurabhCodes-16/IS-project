from PIL import Image


def embed_bytes_in_image(cover_path: str, data: bytes, out_path: str):
    img = Image.open(cover_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size

    # prepend 4 bytes = length header
    length = len(data)
    header = length.to_bytes(4, 'big')
    payload = header + data

    # convert payload to bit list
    bits = []
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    bit_idx = 0
    for y in range(height):
        for x in range(width):
            if bit_idx >= len(bits):
                break

            r, g, b = pixels[x, y]

            # modify R
            r = (r & ~1) | bits[bit_idx]
            bit_idx += 1

            # modify G if bits remain
            if bit_idx < len(bits):
                g = (g & ~1) | bits[bit_idx]
                bit_idx += 1

            # modify B if bits remain
            if bit_idx < len(bits):
                b = (b & ~1) | bits[bit_idx]
                bit_idx += 1

            pixels[x, y] = (r, g, b)

        if bit_idx >= len(bits):
            break

    img.save(out_path, 'PNG')



def extract_bytes_from_image(stego_path: str) -> bytes:
    img = Image.open(stego_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size

    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)

    # first 32 bits => payload length
    length_bits = bits[:32]
    length = 0
    for b in length_bits:
        length = (length << 1) | b

    total_bits_needed = (length + 4) * 8
    if total_bits_needed > len(bits):
        raise ValueError('Image does not contain full payload')

    data_bytes = bytearray()
    for i in range(32, total_bits_needed):
        if (i - 32) % 8 == 0:
            data_bytes.append(0)
        data_bytes[-1] = (data_bytes[-1] << 1) | bits[i]

    return bytes(data_bytes)
