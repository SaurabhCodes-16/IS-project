# demo/two_panel_demo.py
"""
Two-window demo: Sender + Receiver GUIs for stego-encrypted messages.
Run from project root:
    python demo/two_panel_demo.py

Requirements: Pillow, utils.crypto_utils, utils.stego_embed
"""

import sys
from pathlib import Path
import queue
import tempfile
import traceback

# ensure project root is on path so `utils` imports resolve
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk

from utils.crypto_utils import aes_encrypt_file_bytes, rsa_encrypt_key, rsa_load_private, rsa_load_public, aes_decrypt_file_bytes, rsa_decrypt_key
from utils.stego_embed import embed_payload_in_image, extract_payload_from_image

# In-memory queue to pass stego image path / meta from sender -> receiver
MSG_QUEUE = queue.Queue()

# temp dir for generated stego images
TMP_DIR = Path(tempfile.gettempdir()) / "stegodemo_tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------
# Sender UI
# -----------------------
class SenderWindow:
    def __init__(self, master):
        self.master = master
        master.title("Sender")
        master.geometry("420x420")

        self.cover_path = tk.StringVar()
        self.pubkey_path = tk.StringVar()
        self.message = tk.StringVar()
        self.stego_out_path = None

        tk.Label(master, text="Cover image (PNG)").pack(pady=(8,0))
        tk.Entry(master, textvariable=self.cover_path, width=50).pack(padx=8)
        tk.Button(master, text="Browse", command=self.browse_cover).pack(pady=(2,8))

        tk.Label(master, text="Receiver public key (PEM)").pack()
        tk.Entry(master, textvariable=self.pubkey_path, width=50).pack(padx=8)
        tk.Button(master, text="Browse", command=self.browse_pubkey).pack(pady=(2,8))

        tk.Label(master, text="Secret message").pack()
        tk.Entry(master, textvariable=self.message, width=50).pack(padx=8, pady=(2,8))

        tk.Button(master, text="Send", bg="green", fg="white", command=self.send).pack(pady=12)

        self.log = tk.Text(master, height=10, width=52, state="disabled")
        self.log.pack(padx=8, pady=(4,8))

    def browse_cover(self):
        p = filedialog.askopenfilename(filetypes=[("PNG files","*.png"),("All","*.*")])
        if p:
            self.cover_path.set(p)

    def browse_pubkey(self):
        p = filedialog.askopenfilename(filetypes=[("PEM files","*.pem"),("All","*.*")])
        if p:
            self.pubkey_path.set(p)

    def log_msg(self, s):
        self.log.config(state="normal")
        self.log.insert("end", s + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def send(self):
        try:
            cover = Path(self.cover_path.get())
            pubkey_file = Path(self.pubkey_path.get())
            message = self.message.get().strip().encode("utf-8")

            if not cover.exists():
                messagebox.showerror("Error", "Cover image not found")
                return
            if not pubkey_file.exists():
                messagebox.showerror("Error", "Public key file not found")
                return
            if not message:
                messagebox.showerror("Error", "Enter a secret message")
                return

            self.log_msg("Encrypting message with AES key...")
            aes_key, nonce, ct = aes_encrypt_file_bytes(message)
            self.log_msg(f"AES key size: {len(aes_key)} bytes, Ciphertext size: {len(ct)} bytes")

            self.log_msg("Loading receiver public key and wrapping AES key...")
            pub_pem = pubkey_file.read_bytes()
            public_key = rsa_load_public(pub_pem)
            wrapped_key = rsa_encrypt_key(public_key, aes_key)
            payload = wrapped_key + nonce + ct
            self.log_msg(f"Payload size (wrapped_key+nonce+ciphertext): {len(payload)} bytes")

            self.log_msg("Embedding payload into cover image...")
            out_path = TMP_DIR / f"stego_{cover.name}"
            embed_payload_in_image(str(cover), str(out_path), payload)
            MSG_QUEUE.put({
                "stego_path": str(out_path),
                "orig_cover": str(cover),
                "meta": {"sender_note": f"Sent {len(message)} bytes"}
            })
            self.log_msg(f"Stego image ready: {out_path}")
            self.log_msg("Message sent! Waiting for receiver...")

        except Exception as e:
            self.log_msg("Send error: " + str(e))
            traceback.print_exc()
            messagebox.showerror("Send error", str(e))


# -----------------------
# Receiver UI
# -----------------------
class ReceiverWindow:
    def __init__(self, master):
        self.master = master
        master.title("Receiver")
        master.geometry("520x600")

        self.stego_img_path = None
        self.privkey_path = tk.StringVar()
        self.private_key = None

        frame_top = tk.Frame(master)
        frame_top.pack(pady=6)

        tk.Button(frame_top, text="Load Private Key (PEM)", command=self.browse_privkey).pack(side="left", padx=6)
        self.priv_label = tk.Label(frame_top, text="No private key loaded", fg="red")
        self.priv_label.pack(side="left", padx=4)
        tk.Button(frame_top, text="Clear Inbox", bg="orange", fg="black", command=self.clear_inbox).pack(side="left", padx=6)

        tk.Button(master, text="Check Inbox", command=self.check_inbox).pack(pady=(6,4))

        tk.Label(master, text="Incoming Stego Image Preview").pack()
        self.canvas = tk.Canvas(master, width=480, height=320, bg="#ddd")
        self.canvas.pack(padx=8, pady=(4,8))
        self.canvas_image_id = None
        self._preview_image_tk = None

        tk.Button(master, text="Reveal Message (requires private key)", bg="blue", fg="white",
                  command=self.reveal_message).pack(pady=(6,8))

        tk.Label(master, text="Decrypted message:").pack()
        self.msg_box = tk.Text(master, width=64, height=8, state="disabled")
        self.msg_box.pack(padx=8, pady=(4,8))

        self.status_box = tk.Text(master, width=64, height=6, state="disabled")
        self.status_box.pack(padx=8, pady=(4,8))

    def browse_privkey(self):
        p = filedialog.askopenfilename(filetypes=[("PEM files","*.pem"),("All","*.*")])
        if not p:
            return
        try:
            pem = Path(p).read_bytes()
            self.private_key = rsa_load_private(pem)
            self.priv_label.config(text=f"Private key loaded: {Path(p).name}", fg="green")
            self.log_status("Private key loaded.")
        except Exception as e:
            messagebox.showerror("Key load error", str(e))
            self.log_status("Failed to load private key: " + str(e))

    def log_status(self, s):
        self.status_box.config(state="normal")
        self.status_box.insert("end", s + "\n")
        self.status_box.see("end")
        self.status_box.config(state="disabled")

    def check_inbox(self):
        try:
            item = MSG_QUEUE.get_nowait()
        except queue.Empty:
            messagebox.showinfo("Inbox", "No incoming messages.")
            return

        self.stego_img_path = item.get("stego_path")
        self.log_status(f"Received stego image: {self.stego_img_path}")
        self.show_preview(self.stego_img_path)

    def clear_inbox(self):
        while not MSG_QUEUE.empty():
            MSG_QUEUE.get()
        self.stego_img_path = None
        self.canvas.delete("all")
        self.msg_box.config(state="normal")
        self.msg_box.delete("1.0","end")
        self.msg_box.config(state="disabled")
        self.log_status("Inbox cleared.")

    def show_preview(self, img_path):
        try:
            img = Image.open(img_path)
            img.thumbnail((480, 320))
            self._preview_image_tk = ImageTk.PhotoImage(img)
            self.canvas.delete("all")
            self.canvas.create_image(240, 160, image=self._preview_image_tk)
        except Exception as e:
            self.log_status("Preview error: " + str(e))

    def reveal_message(self):
        if not self.stego_img_path:
            messagebox.showwarning("No image", "No stego image in inbox. Click 'Check Inbox' first.")
            return
        if not self.private_key:
            messagebox.showwarning("Private key required", "Please load the receiver's private key to reveal the message.")
            return
        try:
            payload = extract_payload_from_image(self.stego_img_path)
            # split payload
            key_len = (self.private_key.key_size + 7)//8
            wrapped_key = payload[:key_len]
            nonce = payload[key_len:key_len+12]
            ct = payload[key_len+12:]
            aes_key = rsa_decrypt_key(self.private_key, wrapped_key)
            message_bytes = aes_decrypt_file_bytes(aes_key, nonce, ct)
            message_str = message_bytes.decode("utf-8")
            self.msg_box.config(state="normal")
            self.msg_box.delete("1.0","end")
            self.msg_box.insert("1.0", message_str)
            self.msg_box.config(state="disabled")
            self.log_status(f"Message revealed ({len(message_bytes)} bytes).")
        except Exception as e:
            messagebox.showerror("Decryption error", str(e))
            self.log_status("Decryption error: " + str(e))
            traceback.print_exc()


# -----------------------
# Launch both windows
# -----------------------
def main():
    root_s = tk.Tk()
    sender_win = SenderWindow(root_s)

    root_r = tk.Toplevel()
    receiver_win = ReceiverWindow(root_r)

    root_s.mainloop()


if __name__ == "__main__":
    main()
