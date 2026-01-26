from Crypto.Cipher import AES
import random




def split_blocks(data, block_size=16):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


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

def CBC_Decrypt(key, data , iv):
    split_data = split_blocks(data)
    decrypted_blocks = []
    prev_out = iv
    for block in split_data:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_block = cipher.decrypt(block)
        next_out = bytes(a ^ b for a, b in zip(decrypted_block, prev_out))
        prev_out = block
        decrypted_blocks.append(next_out)
    return remove_PKCS7_Pad(b''.join(decrypted_blocks))
    
def remove_PKCS7_Pad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def PKCS7_Pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def get_IV():
    # Returns a random 16-byte IV
    return random.randbytes(16)




"""
Semicolon (;): %3B
Equal sign (=): %3D 
"""

def submit(userInput, key, iv):
    PREPEND_STR = "userid=456; userdata="
    APPEND_STR = "; session-id=31337"

    cleaned_input = userInput.replace(";", "%3B").replace("=", "%3D")
    full_string = PREPEND_STR + cleaned_input + APPEND_STR

    padded_data = PKCS7_Pad(full_string.encode())   # .encode() converts str to bytes

    return CBC_Encrypt(key, padded_data, iv)
    
def verify(encrypted, key, iv):
    decrypted = CBC_Decrypt(key, encrypted, iv)
    if b";admin=true;" in decrypted:
        return True
    else:
        return False

def main():
    key = random.randbytes(16)
    iv = get_IV()
    cypher_text = submit("mcijadomjciodjmaosjidcmajsdjcaiosdcmjasoicjdasojcmdjiasmcdjasoicjdaiosjcmdjiamsiodoiacmjdoiajscmoimjacoisjdmoiajsd", key, iv)

    # Flip bits to get ";admin=true;" in the decrypted plaintext

    block_size = 16

    prepend_str = "userid=456; userdata="

    # length of ;admin=true; is 13 bytes
    target = b";admin=true;"

    target_length = len(target)
    prepend_length = len(prepend_str)

    offset = prepend_length + (block_size - (prepend_length % block_size))  # start of next block

    modified_cypher = bytearray(cypher_text)

    decrypted_og = CBC_Decrypt(key, cypher_text, iv)

    # If we flip bits in the previous block, we can control the decrypted bytes of the next block
    for i in range(target_length):
        byte_index = offset + i
        byte_index_in_block = byte_index % block_size
        prev_block_index = byte_index // block_size - 1  # previous block

        original_byte = cypher_text[prev_block_index * block_size + byte_index_in_block]
        desired_byte = target[i]

        str_byte = decrypted_og[byte_index] # Assuming that we knew something about the payload

        flip_byte = str_byte ^ desired_byte

        modified_cypher[prev_block_index * block_size + byte_index_in_block] ^= flip_byte


    # This could be used if we didn't know anything about the payload

    # decrypted_mod = CBC_Decrypt(key, bytes(modified_cypher), iv)

    # # Pass 2: XOR ciphertext with the result from Pass 1 and desired byte
    # for i in range(target_length):
    #     byte_index = offset + i
    #     byte_index_in_block = byte_index % block_size
    #     prev_block_index = byte_index // block_size - 1  # previous block

    #     result_byte = decrypted_mod[byte_index]  # What we got from Pass 1
    #     desired_byte = target[i]
        
    #     # Modify ciphertext again: XOR with result and desired byte
    #     modified_cypher[prev_block_index * block_size + byte_index_in_block] ^= result_byte ^ desired_byte

    admin_bool = verify(cypher_text, key, iv)
    admin_bool_mod = verify(bytes(modified_cypher), key, iv)

    decrypted_mod = CBC_Decrypt(key, bytes(modified_cypher), iv)

    print("OG Decrypted text:", decrypted_og)
    print("Modified Decrypted text:", decrypted_mod)

    print("\nOG Admin access:", admin_bool)  # Expected: False
    print("Modified Admin access:", admin_bool_mod)  # Expected: True
    
if __name__ == "__main__":
    main()