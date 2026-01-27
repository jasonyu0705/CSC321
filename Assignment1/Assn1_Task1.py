from Crypto.Cipher import AES
import random
import argparse

def read_bmp(path):
    with open(path, "rb") as f:
        data = f.read()
    
    # Pixel array offset is stored at bytes 10–13 (little-endian)
    pixel_offset = int.from_bytes(data[10:14], "little")

    header = data[:pixel_offset]
    pixels = data[pixel_offset:]
    return header, pixels

def ECB_Encrypt(key, data):
    split_data = split_blocks(PKCS7_Pad(data))
    encrypted_blocks = []
    for block in split_data:
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_block = cipher.encrypt(block)
        encrypted_blocks.append(encrypted_block)
        
    return b''.join(encrypted_blocks)

def CBC_Encrypt(key, data , iv):
    split_data = split_blocks(PKCS7_Pad(data))
    encrypted_blocks = []
    prev_out = iv
    for block in split_data:
        cipher = AES.new(key, AES.MODE_ECB)
        next_in = bytes(a ^ b for a, b in zip(block, prev_out))
        encrypted_block= cipher.encrypt(next_in)
        prev_out = encrypted_block
        encrypted_blocks.append(encrypted_block)
    return b''.join(encrypted_blocks)
    
def PKCS7_Pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def split_blocks(data, block_size=16):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def get_IV():
    # Returns a random 16-byte IV
    return random.randbytes(16)
    
def write_bmp(path, header, pixels):
    with open(path, "wb") as f:
        f.write(header + pixels)

def main():
    parser = argparse.ArgumentParser(
        description="Encrypt BMP image using ECB or CBC mode",
        epilog="Examples:\n"
               "  python Assn1_Task1.py ECB input.bmp output.bmp\n"
               "  python Assn1_Task1.py CBC input.bmp output.bmp",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("mode", choices=["ECB", "CBC"], help="Encryption mode: ECB or CBC")
    parser.add_argument("input_file", help="Input BMP file path")
    parser.add_argument("output_file", help="Output BMP file path")
    
    args = parser.parse_args()
    
    header, pixels = read_bmp(args.input_file)
    key = random.randbytes(16)
    
    if args.mode == "ECB":
        pixels_out = ECB_Encrypt(key, pixels)
    else:  # CBC
        iv = get_IV()
        pixels_out = CBC_Encrypt(key, pixels, iv)
    
    write_bmp(args.output_file, header, pixels_out)
    print(f"Encrypted image saved to {args.output_file}")

   
if __name__ == "__main__":
    main()