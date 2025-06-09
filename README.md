# puzzlesolver
for solving bitcoin puzzles with legacy addresses.

I don't have a machine powerful enough to hit the harder to solve puzzles, if you get a winner with the program and feel like donating(I vibe coded this over a period of a couple weeks with Microsoft edge browser) here is a donation address: 34aYRB9jeSDXxNpjZBZpfETLJ2Tcw1H36G

here is the python script.

one script:

#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, time, random, datetime, hashlib, ecdsa, json

# -------------------- Helper Functions --------------------
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    num = int.from_bytes(b, byteorder="big")
    encode = ""
    while num:
        num, rem = divmod(num, 58)
        encode = ALPHABET[rem] + encode
    n_pad = len(b) - len(b.lstrip(b'\x00'))
    return "1" * n_pad + encode

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def private_key_to_wif(private_key_int: int, compressed: bool) -> str:
    pk_bytes = private_key_int.to_bytes(32, byteorder="big")
    payload = b'\x80' + pk_bytes + (b'\x01' if compressed else b'')
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum)

def private_key_to_address(private_key_int: int, compressed: bool) -> str:
    pk_bytes = private_key_int.to_bytes(32, byteorder="big")
    sk = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    if compressed:
        x = vk.to_string()[:32]
        y = int.from_bytes(vk.to_string()[32:], 'big')
        prefix = b'\x02' if (y % 2 == 0) else b'\x03'
        public_key = prefix + x
    else:
        public_key = b'\x04' + vk.to_string()
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    payload = b'\x00' + ripemd160_hash
    checksum = double_sha256(payload)[:4]
    return base58_encode(payload + checksum).strip()

def parse_public_key(hex_str):
    hex_str = "".join(c for c in hex_str if c in "0123456789abcdefABCDEF")
    data = bytes.fromhex(hex_str)
    curve = ecdsa.SECP256k1.curve
    p = curve.p()
    if len(data) == 33:
        if data[0] not in (2, 3):
            raise ValueError("Invalid compressed key prefix.")
        x = int.from_bytes(data[1:], 'big')
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p+1)//4, p)
        if (data[0] == 2 and y % 2) or (data[0] == 3 and y % 2 == 0):
            y = p - y
        uncompressed = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        vk = ecdsa.VerifyingKey.from_string(uncompressed[1:], curve=ecdsa.SECP256k1)
        return vk.pubkey.point
    elif len(data) == 65:
        if data[0] != 0x04:
            raise ValueError("Invalid uncompressed key prefix.")
        vk = ecdsa.VerifyingKey.from_string(data[1:], curve=ecdsa.SECP256k1)
        return vk.pubkey.point
    else:
        raise ValueError("Public key must be either 33 or 65 bytes.")

# -------------------- Default Parameters --------------------
DEFAULT_NONCE_START = 0x8000000
DEFAULT_NONCE_END   = 0xfffffff
DEFAULT_TARGET_ADDRESS = "12jbtzBb54r97TCwW3G1gCFoumpckRAPdY"

# -------------------- WorkerPair with Progress --------------------
class WorkerPair:
    def __init__(self, start, end):
        self.original_start = start
        self.original_end = end
        self.forward_pos = start
        self.backward_pos = end
        self.lock = threading.Lock()
    
    def get_progress(self):
        total = self.original_end - self.original_start + 1
        scanned = (self.forward_pos - self.original_start) + (self.original_end - self.backward_pos + 1)
        return scanned / total if total != 0 else 0

# -------------------- Global Winner Flag --------------------
winner_lock = threading.Lock()
winner_found = False  # Global flag

# -------------------- Scanner Thread Classes --------------------
class LinearForwardScannerThread(threading.Thread):
    def __init__(self, app, worker_pair, thread_id, start_pos=None):
        super().__init__()
        self.app = app
        self.worker_pair = worker_pair
        self.thread_id = thread_id
        if start_pos is not None:
            self.worker_pair.forward_pos = start_pos
        self.paused = False
        self.stopped = False
    
    def run(self):
        global winner_found
        while not self.stopped and not winner_found:
            if self.paused:
                time.sleep(0.1)
                continue
            with self.worker_pair.lock:
                if self.worker_pair.forward_pos > self.worker_pair.backward_pos:
                    break
                current = self.worker_pair.forward_pos
                self.worker_pair.forward_pos += 1
            key_hex = f"{current:064x}"
            comp_addr = private_key_to_address(current, compressed=True)
            uncomp_addr = private_key_to_address(current, compressed=False)
            comp_wif = private_key_to_wif(current, compressed=True)
            uncomp_wif = private_key_to_wif(current, compressed=False)
            current_info = (f"{key_hex} | Comp WIF: {comp_wif} | Uncomp WIF: {uncomp_wif}\n"
                            f"Comp Addr: {comp_addr} | Uncomp Addr: {uncomp_addr}")
            self.app.update_current_key(self.thread_id, current_info)
            if comp_addr in self.app.target_addresses or uncomp_addr in self.app.target_addresses:
                with winner_lock:
                    if not winner_found:
                        winner_found = True
                        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        win_msg = (f"[Thread {self.thread_id} - Linear Forward] {ts}\n"
                                   f"Key: {key_hex}\n"
                                   f"Comp WIF: {comp_wif}\n"
                                   f"Uncomp WIF: {uncomp_wif}\n"
                                   f"Comp Addr: {comp_addr}\n"
                                   f"Uncomp Addr: {uncomp_addr}\n{'-'*50}\n")
                        self.app.append_winning_output(win_msg)
                        self.app.increment_winning_count()
                break
            self.app.increment_total_keys(1)
            time.sleep(0.0001)
    
    def pause(self):
        self.paused = True
    def resume(self):
        self.paused = False
    def stop(self):
        self.stopped = True
    def get_state(self):
        return {
            "thread_id": self.thread_id,
            "mode": "linear_forward",
            "current_position": self.worker_pair.forward_pos,
            "original_start": self.worker_pair.original_start,
            "original_end": self.worker_pair.original_end,
            "nonce_step": 1
        }

class LinearBackwardScannerThread(threading.Thread):
    def __init__(self, app, worker_pair, thread_id, start_pos=None):
        super().__init__()
        self.app = app
        self.worker_pair = worker_pair
        self.thread_id = thread_id
        if start_pos is not None:
            self.worker_pair.backward_pos = start_pos
        self.paused = False
        self.stopped = False
    
    def run(self):
        global winner_found
        while not self.stopped and not winner_found:
            if self.paused:
                time.sleep(0.1)
                continue
            with self.worker_pair.lock:
                if self.worker_pair.backward_pos < self.worker_pair.forward_pos:
                    break
                current = self.worker_pair.backward_pos
                self.worker_pair.backward_pos -= 1
            key_hex = f"{current:064x}"
            comp_addr = private_key_to_address(current, compressed=True)
            uncomp_addr = private_key_to_address(current, compressed=False)
            comp_wif = private_key_to_wif(current, compressed=True)
            uncomp_wif = private_key_to_wif(current, compressed=False)
            current_info = (f"{key_hex} | Comp WIF: {comp_wif} | Uncomp WIF: {uncomp_wif}\n"
                            f"Comp Addr: {comp_addr} | Uncomp Addr: {uncomp_addr}")
            self.app.update_current_key(self.thread_id, current_info)
            if comp_addr in self.app.target_addresses or uncomp_addr in self.app.target_addresses:
                with winner_lock:
                    if not winner_found:
                        winner_found = True
                        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        win_msg = (f"[Thread {self.thread_id} - Linear Backward] {ts}\n"
                                   f"Key: {key_hex}\n"
                                   f"Comp WIF: {comp_wif}\n"
                                   f"Uncomp WIF: {uncomp_wif}\n"
                                   f"Comp Addr: {comp_addr}\n"
                                   f"Uncomp Addr: {uncomp_addr}\n{'-'*50}\n")
                        self.app.append_winning_output(win_msg)
                        self.app.increment_winning_count()
                break
            self.app.increment_total_keys(1)
            time.sleep(0.0001)
    
    def pause(self):
        self.paused = True
    def resume(self):
        self.paused = False
    def stop(self):
        self.stopped = True
    def get_state(self):
        return {
            "thread_id": self.thread_id,
            "mode": "linear_backward",
            "current_position": self.worker_pair.backward_pos,
            "original_start": self.worker_pair.original_start,
            "original_end": self.worker_pair.original_end,
            "nonce_step": 1
        }

class DividedRandomScannerThread(threading.Thread):
    def __init__(self, app, range_start, range_end, thread_id, worker_pair=None):
        super().__init__()
        self.app = app
        self.worker_pair = worker_pair
        if worker_pair is None:
            self.range_start = range_start
            self.range_end = range_end
        self.thread_id = thread_id
        self.paused = False
        self.stopped = False
        self.last_random = None
    
    def run(self):
        global winner_found
        while not self.stopped and not winner_found:
            if self.paused:
                time.sleep(0.1)
                continue
            if self.worker_pair is not None:
                with self.worker_pair.lock:
                    lower_bound = self.worker_pair.forward_pos
                    upper_bound = self.worker_pair.backward_pos
                if lower_bound > upper_bound:
                    break
                current = random.randint(lower_bound, upper_bound)
            else:
                current = random.randint(self.range_start, self.range_end)
            self.last_random = current
            key_hex = f"{current:064x}"
            comp_addr = private_key_to_address(current, compressed=True)
            uncomp_addr = private_key_to_address(current, compressed=False)
            comp_wif = private_key_to_wif(current, compressed=True)
            uncomp_wif = private_key_to_wif(current, compressed=False)
            current_info = (f"{key_hex} | Comp WIF: {comp_wif} | Uncomp WIF: {uncomp_wif}\n"
                            f"Comp Addr: {comp_addr} | Uncomp Addr: {uncomp_addr}")
            self.app.update_current_key(self.thread_id, current_info)
            if comp_addr in self.app.target_addresses or uncomp_addr in self.app.target_addresses:
                with winner_lock:
                    if not winner_found:
                        winner_found = True
                        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        win_msg = (f"[Thread {self.thread_id} - Random] {ts}\n"
                                   f"Key: {key_hex}\n"
                                   f"Comp WIF: {comp_wif}\n"
                                   f"Uncomp WIF: {uncomp_wif}\n"
                                   f"Comp Addr: {comp_addr}\n"
                                   f"Uncomp Addr: {uncomp_addr}\n{'-'*50}\n")
                        self.app.append_winning_output(win_msg)
                        self.app.increment_winning_count()
                break
            self.app.increment_total_keys(1)
            time.sleep(0.0001)
    
    def pause(self):
        self.paused = True
    def resume(self):
        self.paused = False
    def stop(self):
        self.stopped = True
    def get_state(self):
        if self.worker_pair is not None:
            return {
                "thread_id": self.thread_id,
                "mode": "random",
                "last_generated_key": self.last_random,
                "nonce_step": 1
            }
        else:
            return {
                "thread_id": self.thread_id,
                "mode": "random",
                "last_generated_key": self.last_random,
                "range_start": self.range_start,
                "range_end": self.range_end,
                "nonce_step": 1
            }

# -------------------- SOLVER GUI --------------------
class SolverGUI:
    def __init__(self, root):
        # Default parameters; these can be changed via the popup.
        self.puzzle_name = "SOLVER"
        self.nonce_range_start = DEFAULT_NONCE_START
        self.nonce_range_end = DEFAULT_NONCE_END
        # For multiple target addresses, store as a list.
        self.target_addresses = [DEFAULT_TARGET_ADDRESS]
        self.root = root
        self.root.title(self.puzzle_name)
        self.threads = []
        self.worker_pairs = []  # For progress calculations in Linear/Hybrid modes.
        self.winning_count = 0
        self.total_keys = 0
        self.current_keys = {}
        self.last_update = {}
        self.worker_count = 4  # Default worker count.
        self.search_mode = tk.StringVar(value="Linear")  # "Linear", "Random", or "Hybrid"
        self.worker_count_var = tk.IntVar(value=self.worker_count)
        self.create_widgets()
        self.update_progress()  # Start periodic progress updates

    def create_widgets(self):
        # Top info frame.
        top_frame = ttk.Frame(self.root)
        top_frame.pack(padx=10, pady=5, fill="x")
        self.info_label = ttk.Label(top_frame,
                                    text=f"{self.puzzle_name} – Nonce Range: {hex(self.nonce_range_start)} to {hex(self.nonce_range_end)}",
                                    font=("Helvetica", 12, "bold"))
        self.info_label.pack(side="left", anchor="w")
        
        # Statistics frame.
        stats_frame = ttk.Frame(self.root)
        stats_frame.pack(padx=10, pady=5, fill="x")
        self.total_keys_label = ttk.Label(stats_frame, text="Total Keys Checked: 0", font=("Helvetica", 10))
        self.total_keys_label.pack(side="left", padx=(0,20))
        self.winning_count_label = ttk.Label(stats_frame, text="Winning Count: 0", font=("Helvetica", 10))
        self.winning_count_label.pack(side="left", padx=(0,20))
        self.progress_label = ttk.Label(stats_frame, text="Progress: 0.000000000%", font=("Helvetica", 10))
        self.progress_label.pack(side="left")
        
        # Current keys frame.
        current_frame = ttk.LabelFrame(self.root, text="Current Generated Keys (Latest per Thread)")
        current_frame.pack(padx=10, pady=5, fill="both", expand=False)
        self.curr_keys_text = tk.Text(current_frame, height=6, wrap="word", state=tk.DISABLED)
        self.curr_keys_text.pack(fill="both", expand=True)
        
        # Log frame.
        log_frame = ttk.LabelFrame(self.root, text="Scan Log (Live Output)")
        log_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=15, wrap="none")
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=log_scroll.set)
 
        # Winning results frame.
        win_frame = ttk.LabelFrame(self.root, text="Winning Results (Copy/Paste)")
        win_frame.pack(padx=10, pady=5, fill="both", expand=True)
        self.win_text = tk.Text(win_frame, height=8, wrap="word")
        self.win_text.pack(fill="both", expand=True)
        
        # Mode selection frame.
        mode_frame = ttk.LabelFrame(self.root, text="Search Mode")
        mode_frame.pack(padx=10, pady=5, fill="x")
        ttk.Radiobutton(mode_frame, text="Linear", variable=self.search_mode,
                        value="Linear").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        ttk.Radiobutton(mode_frame, text="Random", variable=self.search_mode,
                        value="Random").grid(row=0, column=1, padx=5, pady=2, sticky="w")
        ttk.Radiobutton(mode_frame, text="Hybrid", variable=self.search_mode,
                        value="Hybrid").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        
        # Worker count settings.
        worker_frame = ttk.LabelFrame(self.root, text="Worker Settings")
        worker_frame.pack(padx=10, pady=5, fill="x")
        self.worker_label = ttk.Label(worker_frame, text="Worker Count:")
        self.worker_label.grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.worker_entry = ttk.Entry(worker_frame, textvariable=self.worker_count_var, width=5)
        self.worker_entry.grid(row=0, column=1, padx=5, pady=2, sticky="w")
        plus_button = ttk.Button(worker_frame, text="+", command=self.increase_worker_count)
        plus_button.grid(row=0, column=2, padx=5, pady=2)
        minus_button = ttk.Button(worker_frame, text="-", command=self.decrease_worker_count)
        minus_button.grid(row=0, column=3, padx=5, pady=2)
        
        # Control buttons frame.
        button_frame = ttk.Frame(self.root)
        button_frame.pack(padx=10, pady=5, fill="x")
        self.start_button = ttk.Button(button_frame, text="Start SOLVER", command=self.show_solver_input_popup)
        self.start_button.pack(side="left", padx=5)
        self.load_button = ttk.Button(button_frame, text="Load Save", command=self.load_state)
        self.load_button.pack(side="left", padx=5)
        self.pause_button = ttk.Button(button_frame, text="Pause", command=self.pause_scan, state="disabled")
        self.pause_button.pack(side="left", padx=5)
        self.resume_button = ttk.Button(button_frame, text="Resume", command=self.resume_scan, state="disabled")
        self.resume_button.pack(side="left", padx=5)
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=5)
    
    def increase_worker_count(self):
        current = self.worker_count_var.get()
        self.worker_count_var.set(current + 1)
    
    def decrease_worker_count(self):
        current = self.worker_count_var.get()
        if current > 1:
            self.worker_count_var.set(current - 1)
    
    def update_current_key(self, thread_id, info):
        now = time.time()
        if thread_id not in self.last_update or now - self.last_update[thread_id] > 0.5:
            self.current_keys[thread_id] = info
            self.last_update[thread_id] = now
            out = ""
            for tid in sorted(self.current_keys):
                out += f"Thread {tid}: {self.current_keys[tid]}\n\n"
            self.curr_keys_text.config(state=tk.NORMAL)
            self.curr_keys_text.delete("1.0", tk.END)
            self.curr_keys_text.insert(tk.END, out)
            self.curr_keys_text.config(state=tk.DISABLED)
    
    def append_log(self, msg):
        self.log_text.insert(tk.END, msg)
        self.log_text.see(tk.END)
    
    def append_winning_output(self, msg):
        self.win_text.insert(tk.END, msg)
        self.win_text.see(tk.END)
    
    def increment_winning_count(self):
        self.winning_count += 1
        self.winning_count_label.config(text=f"Winning Count: {self.winning_count}")
    
    def increment_total_keys(self, count=1):
        self.total_keys += count
        self.total_keys_label.config(text=f"Total Keys Checked: {self.total_keys}")
    
    def update_progress(self):
        if self.search_mode.get() in ("Linear", "Hybrid") and self.worker_pairs:
            total_frac = 0
            for wp in self.worker_pairs:
                total_frac += wp.get_progress()
            overall = (total_frac / len(self.worker_pairs)) * 100
            self.progress_label.config(text=f"Progress: {overall:.9f}%")
        else:
            self.progress_label.config(text="Progress: N/A")
        self.root.after(500, self.update_progress)
    
    def show_solver_input_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("Enter Solver Parameters")
        tk.Label(popup, text="Solver Name:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        name_entry = tk.Entry(popup, width=30)
        name_entry.insert(0, self.puzzle_name)
        name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(popup, text="Nonce Range Start (e.g., 0x8000000):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        start_entry = tk.Entry(popup, width=30)
        start_entry.insert(0, hex(self.nonce_range_start))
        start_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(popup, text="Nonce Range End (e.g., 0xfffffff):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        end_entry = tk.Entry(popup, width=30)
        end_entry.insert(0, hex(self.nonce_range_end))
        end_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(popup, text="Target Address(es) (comma separated):").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        address_entry = tk.Entry(popup, width=30)
        address_entry.insert(0, ", ".join(self.target_addresses))
        address_entry.grid(row=3, column=1, padx=5, pady=5)
        
        def ok():
            try:
                self.puzzle_name = name_entry.get().strip() or self.puzzle_name
                s_val = start_entry.get().strip()
                e_val = end_entry.get().strip()
                self.nonce_range_start = int(s_val, 0)
                self.nonce_range_end = int(e_val, 0)
                target_text = address_entry.get().strip().replace('"', '').replace("'", "")
                addresses = [x.strip() for x in target_text.split(",") if x.strip()]
                self.target_addresses = addresses if addresses else [DEFAULT_TARGET_ADDRESS]
                self.info_label.config(text=f"{self.puzzle_name} – Nonce Range: {hex(self.nonce_range_start)} to {hex(self.nonce_range_end)}")
                self.root.title(self.puzzle_name)
            except Exception as ex:
                messagebox.showerror("Input Error", f"Invalid input: {ex}")
                return
            popup.destroy()
            self.start_solver()
        def cancel():
            popup.destroy()
        tk.Button(popup, text="OK", command=ok).grid(row=4, column=0, padx=5, pady=10)
        tk.Button(popup, text="Cancel", command=cancel).grid(row=4, column=1, padx=5, pady=10)
    
    def start_solver(self):
        global winner_found
        winner_found = False
        self.threads = []
        self.worker_pairs = []
        self.start_button.config(state="disabled")
        self.pause_button.config(state="normal")
        self.stop_button.config(state="normal")
        self.total_keys = 0
        self.winning_count = 0
        self.total_keys_label.config(text="Total Keys Checked: 0")
        self.winning_count_label.config(text="Winning Count: 0")
        self.log_text.delete("1.0", tk.END)
        self.win_text.delete("1.0", tk.END)
        self.curr_keys_text.config(state=tk.NORMAL)
        self.curr_keys_text.delete("1.0", tk.END)
        self.curr_keys_text.config(state=tk.DISABLED)
        self.current_keys = {}
        self.last_update = {}
        try:
            num_workers = int(self.worker_entry.get())
        except ValueError:
            num_workers = 1
        start_range = self.nonce_range_start
        end_range = self.nonce_range_end
        total_range = end_range - start_range + 1
        self.append_log(f"Starting {self.puzzle_name}\nNonce Range: {hex(start_range)} to {hex(end_range)}\nMode: {self.search_mode.get()}\n")
        self.threads = []
        self.worker_pairs = []
        thread_id = 1
        mode = self.search_mode.get()
        if mode == "Linear":
            section_size = total_range // num_workers
            for i in range(num_workers):
                sec_start = start_range + i * section_size
                sec_end = end_range if i == num_workers - 1 else sec_start + section_size - 1
                wp = WorkerPair(sec_start, sec_end)
                self.worker_pairs.append(wp)
                ft = LinearForwardScannerThread(self, wp, thread_id)
                self.threads.append(ft)
                ft.start()
                thread_id += 1
                bt = LinearBackwardScannerThread(self, wp, thread_id)
                self.threads.append(bt)
                bt.start()
                thread_id += 1
        elif mode == "Random":
            for i in range(num_workers):
                sec_start = start_range + i * (total_range // num_workers)
                sec_end = end_range if i == num_workers - 1 else sec_start + (total_range // num_workers) - 1
                rt = DividedRandomScannerThread(self, sec_start, sec_end, thread_id)
                self.threads.append(rt)
                rt.start()
                thread_id += 1
        elif mode == "Hybrid":
            for i in range(num_workers):
                sec_start = start_range + i * (total_range // num_workers)
                sec_end = end_range if i == num_workers - 1 else sec_start + (total_range // num_workers) - 1
                wp = WorkerPair(sec_start, sec_end)
                self.worker_pairs.append(wp)
                ft = LinearForwardScannerThread(self, wp, thread_id)
                self.threads.append(ft)
                ft.start()
                thread_id += 1
                bt = LinearBackwardScannerThread(self, wp, thread_id)
                self.threads.append(bt)
                bt.start()
                thread_id += 1
                rt = DividedRandomScannerThread(self, None, None, thread_id, worker_pair=wp)
                self.threads.append(rt)
                rt.start()
                thread_id += 1
        self.append_log(f"Spawned {len(self.threads)} threads in {mode} mode.\n")
    
    def pause_scan(self):
        for t in self.threads:
            t.pause()
        self.append_log("Scan paused.\n")
        self.pause_button.config(state="disabled")
        self.resume_button.config(state="normal")
        self.save_state()
    
    def resume_scan(self):
        for t in self.threads:
            t.resume()
        self.append_log("Scan resumed.\n")
        self.resume_button.config(state="disabled")
        self.pause_button.config(state="normal")
    
    def stop_scan(self):
        for t in self.threads:
            t.stop()
        self.threads = []
        self.worker_pairs = []
        self.append_log("Scan stopped.\n")
        self.start_button.config(state="normal")
        self.pause_button.config(state="disabled")
        self.resume_button.config(state="disabled")
        self.stop_button.config(state="disabled")
    
    def save_state(self):
        ts_filename = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        wc = self.worker_count_var.get()
        filename = f"{self.puzzle_name.replace(' ', '_')}_save_{ts_filename}_wc{wc}.json"
        state = {
            "global": {
                "puzzle_name": self.puzzle_name,
                "total_keys": self.total_keys,
                "winning_count": self.winning_count,
                "worker_count": wc,
                "search_mode": self.search_mode.get(),
                "nonce_range_start": self.nonce_range_start,
                "nonce_range_end": self.nonce_range_end,
                "target_addresses": self.target_addresses,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "threads": []
        }
        for t in self.threads:
            if hasattr(t, "get_state"):
                state["threads"].append(t.get_state())
        try:
            with open(filename, "w") as f:
                json.dump(state, f, indent=4)
            self.append_log(f"State saved to {filename}\n")
        except Exception as e:
            self.append_log(f"Error saving state: {e}\n")
    
    def resume_from_state(self, state):
        global winner_found
        winner_found = False
        self.threads = []
        self.worker_pairs = []
        mode = state["global"].get("search_mode", "Linear")
        thread_states = state.get("threads", [])
        self.puzzle_name = state["global"].get("puzzle_name", self.puzzle_name)
        self.nonce_range_start = state["global"].get("nonce_range_start", self.nonce_range_start)
        self.nonce_range_end = state["global"].get("nonce_range_end", self.nonce_range_end)
        self.target_addresses = state["global"].get("target_addresses", [DEFAULT_TARGET_ADDRESS])
        self.search_mode.set(mode)
        self.info_label.config(text=f"{self.puzzle_name} – Nonce Range: {hex(self.nonce_range_start)} to {hex(self.nonce_range_end)}")
        self.root.title(self.puzzle_name)
        if mode == "Linear":
            for i in range(0, len(thread_states), 2):
                f_state = thread_states[i]
                b_state = thread_states[i+1]
                wp = WorkerPair(f_state["original_start"], f_state["original_end"])
                wp.forward_pos = f_state["current_position"]
                wp.backward_pos = b_state["current_position"]
                self.worker_pairs.append(wp)
                ft = LinearForwardScannerThread(self, wp, f_state["thread_id"])
                bt = LinearBackwardScannerThread(self, wp, b_state["thread_id"])
                self.threads.extend([ft, bt])
        elif mode == "Random":
            for s in thread_states:
                rt = DividedRandomScannerThread(self, s.get("range_start"), s.get("range_end"), s["thread_id"])
                self.threads.append(rt)
        elif mode == "Hybrid":
            for i in range(0, len(thread_states), 3):
                f_state = thread_states[i]
                b_state = thread_states[i+1]
                r_state = thread_states[i+2]
                wp = WorkerPair(f_state["original_start"], f_state["original_end"])
                wp.forward_pos = f_state["current_position"]
                wp.backward_pos = b_state["current_position"]
                self.worker_pairs.append(wp)
                ft = LinearForwardScannerThread(self, wp, f_state["thread_id"])
                bt = LinearBackwardScannerThread(self, wp, b_state["thread_id"])
                rt = DividedRandomScannerThread(self, None, None, r_state["thread_id"], worker_pair=wp)
                self.threads.extend([ft, bt, rt])
        for t in self.threads:
            t.start()
        self.append_log(f"Resumed {len(self.threads)} threads from saved state in {mode} mode.\n")
        self.start_button.config(state="disabled")
        self.pause_button.config(state="normal")
        self.stop_button.config(state="normal")
        self.resume_button.config(state="disabled")
    
    def load_state(self):
        # Updated file types to show all JSON files (and all files) regardless of case.
        file_path = filedialog.askopenfilename(
            title="Select saved state file",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not file_path:
            self.append_log("No file selected.\n")
            return
        try:
            with open(file_path, "r") as f:
                state = json.load(f)
            self.total_keys = state["global"].get("total_keys", 0)
            self.winning_count = state["global"].get("winning_count", 0)
            self.worker_count_var.set(state["global"].get("worker_count", self.worker_count))
            self.search_mode.set(state["global"].get("search_mode", "Linear"))
            self.nonce_range_start = state["global"].get("nonce_range_start", self.nonce_range_start)
            self.nonce_range_end = state["global"].get("nonce_range_end", self.nonce_range_end)
            self.target_addresses = state["global"].get("target_addresses", [DEFAULT_TARGET_ADDRESS])
            self.puzzle_name = state["global"].get("puzzle_name", self.puzzle_name)
            self.total_keys_label.config(text=f"Total Keys Checked: {self.total_keys}")
            self.winning_count_label.config(text=f"Winning Count: {self.winning_count}")
            self.append_log("Loaded saved state.\n")
            self.resume_from_state(state)
        except Exception as e:
            self.append_log(f"Error loading state: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = SolverGUI(root)
    root.mainloop()
