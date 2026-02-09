from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import hashlib
from Crypto.Cipher import AES


def compute(a,b,p):
    if b == 0:
        return 1
    else:
        return pow(a, b)%p

def int_to_fixed_bytes(x, p):
    # fixed length based on modulus size (important for consistency)
    nbytes = (p.bit_length() + 7) // 8
    return x.to_bytes(nbytes, "big")

def main():
    message_alice = b"calpoly"
    message_bob =b"mustangs"
    #2 public keys
    alice_pub_key = 37
    #modulus
    tamperedKey= 1# THIS WILL BE MESSED WITH BY MALLORY 
    #generator 

    alice_priv_key = 4
    bob_priv_key = 3
    alice_gen_key= compute(tamperedKey, alice_priv_key, alice_pub_key)#Ya
    bob_gen_key= compute(tamperedKey, bob_priv_key, alice_pub_key)#Yb

                 
    s_alice = compute(alice_gen_key, alice_priv_key, alice_pub_key)
    s_bob = compute(bob_gen_key, bob_priv_key, alice_pub_key)


    # derive symmetric keys
    k_alice = hashlib.sha256(int_to_fixed_bytes(s_alice, alice_pub_key)).digest()
    k_bob = hashlib.sha256(int_to_fixed_bytes(s_bob, alice_pub_key)).digest()

    c0 = AES.new(k_alice, AES.MODE_ECB)
    c1 = AES.new(k_bob, AES.MODE_ECB)

    # Encrypt a test message
  
    ciphertext_alice = c0.encrypt(message_alice.ljust(16, b'\x00'))
    ciphertext_bob = c1.encrypt(message_bob.ljust(16, b'\x00'))
    print("Alice Ciphertext:", ciphertext_alice.hex())
    print("Bob Ciphertext:", ciphertext_bob.hex())

    
    c0 = AES.new(k_alice, AES.MODE_ECB)
    c1 = AES.new(k_bob, AES.MODE_ECB)
    decrypted_message_alice = c0.decrypt(ciphertext_alice).rstrip(b'\x00')
    decrypted_message_bob = c1.decrypt(ciphertext_bob).rstrip(b'\x00')
    print("Decrypted Alice's message by Alice:", decrypted_message_alice.decode())
    print("Decrypted Bob's message by Bob:", decrypted_message_bob.decode())







    #mallory 
    shared_secret = compute(tamperedKey, alice_priv_key, alice_pub_key)

    mallory_key = hashlib.sha256(int_to_fixed_bytes(shared_secret, alice_pub_key)).digest()

    mallory_c = AES.new(mallory_key, AES.MODE_ECB)

    decrypted_message_alice = mallory_c.decrypt(ciphertext_alice).rstrip(b'\x00')
    decrypted_message_bob = mallory_c.decrypt(ciphertext_bob).rstrip(b'\x00')

    print("Decrypted Alice's message by Mallory:", decrypted_message_alice.decode())
    print("Decrypted Bob's message by Mallory:", decrypted_message_bob.decode())



if __name__ == "__main__":
    main()

    #  # print results

    # print("Alice Generated Key:", alice_gen_key)
    # print("Bob Generated Key:", bob_gen_key)

    # print("Alice Shared Secret:", s_alice)
    # print("Bob Shared Secret:", s_bob)
    # print("Alice Secret Key:", k_alice.hex())
    # print("Bob Secret Key:", k_bob.hex())
    # print("keys equal?", k_alice == k_bob)