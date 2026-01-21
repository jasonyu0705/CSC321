from Crypto.Cipher import AES

def read_bmp(path):
    with open(path, "rb") as f:
        data = f.read()

    # BMP signature check (optional but helpful)
    if data[:2] != b"BM":
        raise ValueError("Not a BMP file")

    # Pixel array offset is stored at bytes 10–13 (little-endian)
    pixel_offset = int.from_bytes(data[10:14], "little")

    header = data[:pixel_offset]
    pixels = data[pixel_offset:]
    return header, pixels

def main():
    header,pixels=read_bmp("Assignment1/images/cp-logo.bmp")
    # img2=Image.open("Assignment1/images/mustang.bmp")
    if pixels % 16 != 0:
        padding_length = 16 - (len(pixels) % 16)
        
    elif pixels % 16 == 0:
        padding_length = 0



if __name__ == "__main__":
    main()