# Your implementation should support 
# variable length primes (up to 2048 bits), and use the value e=65537. 


from sympy import gcd
import argparse
from Crypto.Util.number import inverse
from Crypto.Cipher import AES
from Crypto.Util import number

def mod_inverse(e, phi):
    d = 0
    x1, x2, y1, y2 = 0, 1, 1, 0
    temp_phi = phi
    while e > 0:
        temp1, temp2 = temp_phi // e, temp_phi % e
        temp_phi, e = e, temp2
        x = x2 - temp1 * x1
        y = y2 - temp1 * y1
        x2, x1 = x1, x
        y2, y1 = y1, y
    if temp_phi == 1:
        return y2 + phi


def rsa_key_gen(prime1, prime2, e=65537):
    
    n = prime1 * prime2
    phi_n = (prime1 - 1) * (prime2 - 1)

    if gcd(e, phi_n) != 1:
        raise ValueError("e must be coprime to φ(n)")

    d = mod_inverse(e, phi_n)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def encrypt_rsa(public_key, plaintext):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    if plaintext_int >= n:
        raise ValueError("Plaintext too large for the key size")
    ciphertext_int = pow(plaintext_int, e, n)
    return ciphertext_int


def decrypt_rsa(private_key, ciphertext_int):
    d, n = private_key
    plaintext_int = pow(ciphertext_int, d, n)
    byte_length = (plaintext_int.bit_length() + 7) // 8
    plaintext = plaintext_int.to_bytes(byte_length, byteorder='big')
    return plaintext

def get_rand_prime(bits=2048):

    return number.getPrime(bits)

def main():
    # Generate a prime number (up to 2048 bits)
    parser = argparse.ArgumentParser(description="RSA Key Generation, Encryption, and Decryption")
    parser.add_argument('--bits', type=int, default=2048, help='Bit length of the prime numbers (default: 2048)')
    parser.add_argument('--message', type=str, required=True, help='Message to encrypt and decrypt')

    args = parser.parse_args()

    prime_1 = get_rand_prime(args.bits)
    prime_2 = get_rand_prime(args.bits)

    public_key, private_key = rsa_key_gen(prime_1, prime_2)

    # test encryption and decryption
    message_bytes = args.message.encode('utf-8')
    ciphertext = encrypt_rsa(public_key, message_bytes)
    print(f"Ciphertext (int): {ciphertext}")
    decrypted_message = decrypt_rsa(private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message.decode('utf-8')}")


# Discard original c
# Mallory can send any value that she knows and encrypt is with the public key
# Since we know Alice uses that as the seed for AES, we can compute the same AES key
def mallory_send(public_key, our_key):
    return encrypt_rsa(public_key, our_key)

def get_AES_key(key):
    return AES.new(key.to_bytes(16, byteorder='big'), AES.MODE_ECB)

def malleability_attack():
    alice_public, alice_private = rsa_key_gen(get_rand_prime(), get_rand_prime())
    bob_public, bob_private = rsa_key_gen(get_rand_prime(), get_rand_prime())

    # Bob would send C as the seed for AES, but Mallory intercepts it and changes it instead

    mallory_c = mallory_send(alice_public, 42069)  # Mallory chooses 42069 as the AES key
    aes_cipher = get_AES_key(42069)

    # Alice decrypts mallory_c to get the AES key
    alice_aes_key_int = decrypt_rsa(alice_private, mallory_c)
    alice_aes_key = get_AES_key(alice_aes_key_int)

    # Now if Alice sends an encrypted message to Bob using this AES key, Mallory can decrypt it
    alice_output = alice_aes_key.encrypt(b'Hi Bob!')  # AES block size is 16 bytes
    mallory_decrypted = aes_cipher.decrypt(alice_output)

    print(f"Mallory decrypted message: {mallory_decrypted}")

if __name__ == "__main__":
    main()
