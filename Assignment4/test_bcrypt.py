import bcrypt
import time

def test_single():
    # Bilbo's hash from file
    target = b"$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq"
    
    # We suspect 'hobbit' might be the password (just a guess, but good for testing)
    # Or just 'apple', 'hello' etc.
    words = ["apple", "banana", "hobbit", "orange", "wizard"]
    
    print("Testing specific words against Bilbo's hash...")
    for w in words:
        start = time.time()
        if bcrypt.checkpw(w.encode('utf-8'), target):
            print(f"MATCH FOUND: {w}")
        else:
            print(f"No match: {w}")
        print(f"Time: {time.time()-start:.4f}s")

if __name__ == "__main__":
    test_single()
