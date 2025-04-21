# 🚀 Bitcoin Puzzle Solver - Optimized for Terminal
import hashlib
import random
import time
import base58
import ecdsa
import concurrent.futures  

# ✅ Expanded Puzzle Table
PUZZLE_TABLES = {
    "Puzzle #69": {"nonce_min": int("100000000000000000", 16), "nonce_max": int("1fffffffffffffffff", 16), "btc_address": "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG", "prize": 6.90013661},
    "Puzzle #71": {"nonce_min": int("400000000000000000", 16), "nonce_max": int("7fffffffffffffffff", 16), "btc_address": "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU", "prize": 7.1000437},
    "Puzzle #135": {"nonce_min": int("4000000000000000000000000000000000", 16), "nonce_max": int("7fffffffffffffffffffffffffffffffff", 16), "btc_address": "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v", "prize": 13.50003408, "public_key": "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"},
}

def get_puzzle_list():
    """ Returns all available puzzles dynamically. """
    return list(PUZZLE_TABLES.keys())

def get_puzzle_info(puzzle_name):
    """ Fetches puzzle details. """
    return PUZZLE_TABLES.get(puzzle_name, None)

class PuzzleSolver:
    def __init__(self):
        self.search_active = False  
        self.seen_nonces = set()

    def private_key_to_address(self, private_key, compressed=True):
        """ Converts private key to Bitcoin address. """
        key_bytes = bytes.fromhex(private_key)
        sk = ecdsa.SigningKey.from_string(key_bytes, curve=ecdsa.SECP256k1)
        vk_bytes = b'\x02' + sk.verifying_key.to_string()[:32] if compressed else b'\x04' + sk.verifying_key.to_string()
        ripemd160 = hashlib.new('ripemd160', hashlib.sha256(vk_bytes).digest()).digest()
        extended_ripemd160 = b'\x00' + ripemd160
        first_sha256 = hashlib.sha256(extended_ripemd160).digest()
        second_sha256 = hashlib.sha256(first_sha256).digest()
        checksum = second_sha256[:4]
        return base58.b58encode(extended_ripemd160 + checksum).decode()

    def parallel_nonce_bounce(self, nonce_min, nonce_max, puzzle_address, thread_count=4):
        """ Runs nonce bouncing in parallel threads. """
        print(f"⚡ Parallel nonce bouncing started with {thread_count} threads!")
        start_time = time.time()
        tested_count = 0
        self.search_active = True  

        def search_nonce():
            while self.search_active:
                random_nonce = random.randint(nonce_min, nonce_max)  

                if random_nonce in self.seen_nonces:
                    continue  # Avoid redundant searches
                self.seen_nonces.add(random_nonce)

                private_key_hex = hex(random_nonce)[2:].zfill(64)
                compressed_address = self.private_key_to_address(private_key_hex, compressed=True)
                uncompressed_address = self.private_key_to_address(private_key_hex, compressed=False)

                if compressed_address == puzzle_address or uncompressed_address == puzzle_address:
                    elapsed_time = time.time() - start_time
                    print(f"✅ WINNER FOUND: {private_key_hex} (Checked: {tested_count}) (Time: {elapsed_time:.2f}s)")
                    self.search_active = False  
                    return  

                tested_count += 1
                print(f"❌ {private_key_hex} (Checked: {tested_count})")

        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(search_nonce) for _ in range(thread_count)]
            concurrent.futures.wait(futures)

# ✅ Keeps the script running until the user decides to exit
while True:
    print("\n🚀 Bitcoin Puzzle Solver - Terminal Version")
    
    print("\n🔹 Available Puzzles:")
    for puzzle in get_puzzle_list():
        print(f"• {puzzle}")

    puzzle_name = input("\nEnter puzzle name exactly as shown: ")
    puzzle_info = get_puzzle_info(puzzle_name)

    if not puzzle_info:
        print("❌ Invalid puzzle. Please try again.")
        continue

    print(f"\n✅ Selected Puzzle: {puzzle_name}")
    print(f"💰 Prize: {puzzle_info['prize']} BTC")
    print(f"🔢 Searching between {hex(puzzle_info['nonce_min'])} and {hex(puzzle_info['nonce_max'])}")
    print(f"📍 Bitcoin Address: {puzzle_info['btc_address']}")

    # 🔹 Add a search method selection menu:
    print("\n🔹 Choose a search method:")
    print("1️⃣ Parallel Nonce Bounce (Multi-threaded)")
    method_choice = input("Enter method (1): ")

    solver = PuzzleSolver()
    if method_choice == "1":
        solver.parallel_nonce_bounce(puzzle_info["nonce_min"], puzzle_info["nonce_max"], puzzle_info["btc_address"])
    else:
        print("❌ Invalid choice. Please try again.")