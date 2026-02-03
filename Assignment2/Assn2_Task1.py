from Crypto.Hash import SHA256

from Crypto.Cipher import AES

def compute(a,b,p):
    if b == 0:
        return 1
    else:
        return pow(a, b)%p

def int_to_fixed_bytes(x, p):
    nbytes = (p.bit_length() + 7) // 8
    return x.to_bytes(nbytes, "big")

def derive_aes_key_from_shared_secret(shared_secret_int, p):
    s_bytes = int_to_fixed_bytes(shared_secret_int, p)
    return SHA256.new(s_bytes).digest()  

def main():

    #2 public keys
    #alice_pub_key = 37 
    alice_pub_key_hex ="B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
    #bob_pub_key= 5 
    bob_pub_key_hex= "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"
    
    alice_message = b"calpoly"
    bob_message = b"mustangs"
    alice_pub_key = int(alice_pub_key_hex.replace(" ", ""), 16)
    bob_pub_key = int(bob_pub_key_hex.replace(" ", ""), 16)

    alice_priv_key = 4
    bob_priv_key = 3

    alice_gen_key= compute(bob_pub_key, alice_priv_key, alice_pub_key)
    bob_gen_key= compute(bob_pub_key, bob_priv_key, alice_pub_key)
    s_alice = compute(bob_gen_key, alice_priv_key, alice_pub_key)
    s_bob = compute(alice_gen_key, bob_priv_key, alice_pub_key)

    k_alice_bytes = derive_aes_key_from_shared_secret(s_alice, alice_pub_key)
    k_bob_bytes = derive_aes_key_from_shared_secret(s_bob, alice_pub_key)
    #sending a message both ways
    c0 = AES.new(k_alice_bytes, AES.MODE_ECB)
    c1 = AES.new(k_bob_bytes, AES.MODE_ECB)
    #encrypting the message usign AES
    ciphertext_alice = c0.encrypt(alice_message.ljust(16, b'\x00'))
    ciphertext_bob = c1.encrypt(bob_message.ljust(16, b'\x00'))
    print("Alice Ciphertext:", ciphertext_alice.hex())
    print("Bob Ciphertext:", ciphertext_bob.hex())
    #decrypting using AES
    msg_to_bob = c1.decrypt(ciphertext_alice).rstrip(b'\x00')
    msg_to_alice = c0.decrypt(ciphertext_bob).rstrip(b'\x00')
    print("message to alice:", msg_to_alice.decode())
    print("Message to bob:", msg_to_bob.decode())


if __name__ == "__main__":
    main()


    # print("Alice Generated Key:", alice_gen_key)
    # print("Bob Generated Key:", bob_gen_key)
    # print("Alice Secret Key:", k_alice)
    # print("Bob Secret Key:", k_bob)