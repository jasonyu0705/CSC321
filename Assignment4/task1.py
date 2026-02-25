import Crypto.Hash.SHA256 as SHA
import time
import os

def hash_input(text):
    # Ensure text is bytes. If it's a string, encode it.
    if isinstance(text, str):
        data = text.encode('utf-8')
    else:
        # Assuming text is already bytes
        data = text
    digest = SHA.new(data).digest()
    return digest

def get_truncated_hash(digest, n_bits):
    digest_int = int.from_bytes(digest, byteorder='big')
    # Use a mask to keep only the first n_bits.
    # SHA256 is 256 bits. We want the most significant n_bits or least?
    # Usually truncation takes the leftmost bits.
    # To get the first n_bits (leftmost), we shift right by (256 - n_bits).
    truncated = digest_int >> (256 - n_bits)
    return truncated

def flip_bit(data, byte_index, bit_index):

    """Flips a specific bit in a byte array."""
    data_list = bytearray(data)
    data_list[byte_index] ^= (1 << bit_index)
    return bytes(data_list)

def part_a():
    print("--- Part A: SHA256 Hashing ---")
    inputs = ["Hello World", "Crypto", "123456"]
    for s in inputs:
        digest = hash_input(s)
        print(f"Input: '{s}'")
        print(f"Digest: {digest.hex()}")
    print()

def part_b():
    print("--- Part B: Avalanche Effect (Hamming Distance 1) ---")
    base_input = "Hello World"
    # Convert to bytes to easily flip bits
    base_bytes = base_input.encode('utf-8')
    
    # Generate variations with 1 bit flipped
    variations = [
        flip_bit(base_bytes, 0, 0), # Flip 0th bit of 0th byte
        flip_bit(base_bytes, 0, 1), # Flip 1st bit of 0th byte
        flip_bit(base_bytes, 1, 0), # Flip 0th bit of 1st byte
    ]

    print(f"Original Input: {base_bytes}")
    original_digest = hash_input(base_bytes)
    print(f"Original Digest: {original_digest.hex()}\n")

    for i, modified_bytes in enumerate(variations):
        modified_digest = hash_input(modified_bytes)
        print(f"Modified Input {i+1}: {modified_bytes}")
        print(f"Modified Digest: {modified_digest.hex()}")
        
        # Calculate bit differences in hash (optional but helpful to see effect)
        # Convert bytes to int for XOR
        orig_int = int.from_bytes(original_digest, byteorder='big')
        mod_int = int.from_bytes(modified_digest, byteorder='big')
        diff_bits = bin(orig_int ^ mod_int).count('1')
        print(f"Bit difference in digest: {diff_bits} bits\n")

def part_c():
    print("--- Part C: Finding Collisions (Birthday Attack) ---")
    print(f"{'Bits':<10} {'Inputs':<15} {'Time (s)':<15}")
    print("-" * 40)
    
    # Starting from 8 bits up to 50 bits (step 2)
    for bits in range(8, 51, 2):
        start_time = time.time()
        seen_hashes = {}
        inputs_count = 0
        collision_found = False
        
        # Pre-calculate mask if needed, but get_truncated_hash handles it
        
        while not collision_found:
            # Generate random input
            msg = os.urandom(16) 
            inputs_count += 1
            
            digest = hash_input(msg)
            # Truncate
            digest_int = int.from_bytes(digest, byteorder='big')
            truncated = digest_int >> (256 - bits)
            
            if truncated in seen_hashes:
                collision_found = True
                end_time = time.time()
                elapsed = end_time - start_time
                print(f"{bits:<10} {inputs_count:<15} {elapsed:.6f}")
            else:
                seen_hashes[truncated] = msg

def main():
    part_a()
    part_b()
    part_c() 







if __name__ == "__main__":
    main()