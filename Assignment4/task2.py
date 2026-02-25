import nltk
from nltk.corpus import words
import bcrypt
import time
import multiprocessing
import os
import sys

# Ensure this function is defined at module level for Windows compatibility
def check_chunk(chunk, target_hash_str, user_name, result_q, stop_event):
    """
    Worker function to check a chunk of words against a target hash.
    """
    try:
        target_bytes = target_hash_str.encode('utf-8')
    except AttributeError:
        # Should be string, but if bytes, use directly
        target_bytes = target_hash_str

    for word in chunk:
        if stop_event.is_set():
            return
        
        # Check password
        try:
            if bcrypt.checkpw(word.encode('utf-8'), target_bytes):
                result_q.put((user_name, word))
                stop_event.set()
                return
        except ValueError:
            # Handle potential encoding issues or invalid hash formats
            continue


def main():
    # 1. Download/Load NLTK words

    print("Loading NLTK words...")
    try:
        nltk.data.find('corpora/words')
    except LookupError:
        nltk.download('words')
    
    from nltk.corpus import words
    word_list = words.words()
    
    # Filter for 6-10 letters
    filtered_words = [w for w in word_list if 6 <= len(w) <= 10]
    print(f"Loaded {len(filtered_words)} words of length 6-10.")

    # 2. Read Shadow File
    shadow_file = os.path.join(os.path.dirname(__file__), 'shadow.txt')
    users = []
    with open(shadow_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':', 1)
            if len(parts) == 2:
                users.append((parts[0], parts[1]))
    
    print(f"Loaded {len(users)} users from shadow file.")

    # 3. Crack passwords
    num_cores = multiprocessing.cpu_count()
    print(f"Starting crack with {num_cores} cores...")

    total_start = time.time()
    
    # Create chunks for workers
    chunk_size = len(filtered_words) // num_cores + 1
    chunks = [filtered_words[i:i + chunk_size] for i in range(0, len(filtered_words), chunk_size)]
    
    total_start_time = time.time()

    for user, target_hash in users:
        print(f"\n--- Cracking user: {user} ---")
        print(f"Hash: {target_hash}")
        
        # Parse workfactor for info
        try:
            # Hash format: $2b$WF$salt...
            wf_str = target_hash.split('$')[2]
            print(f"Workfactor: {wf_str}")
        except IndexError:
            print("Could not parse workfactor")

        user_start_time = time.time()
        
        # Setup multiprocessing
        result_q = multiprocessing.Queue()
        stop_event = multiprocessing.Event()
        processes = []

        for chunk_words in chunks:
            p = multiprocessing.Process(
                target=check_chunk, 
                args=(chunk_words, target_hash, user, result_q, stop_event)
            )
            processes.append(p)
            p.start()

        # Monitor progress
        found_password = None
        while any(p.is_alive() for p in processes):
            if not result_q.empty():
                _, found_password = result_q.get()
                stop_event.set() # Signal all workers to stop
                break
            time.sleep(0.1) # Check every 100ms
        
        # Ensure cleanup
        for p in processes:
            p.join()
            
        elapsed = time.time() - user_start_time
        
        if found_password:
            print(f"SUCCESS! Password for {user} is: '{found_password}'")
        else:
            print(f"FAILED. Password not found in dictionary.")
        print(f"Time taken: {elapsed:.2f} seconds")

    total_end_time = time.time()
    print(f"\nTotal execution time: {total_end_time - total_start_time:.2f} seconds")

if __name__ == "__main__":

    multiprocessing.freeze_support()
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt.")

