import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
from backup import run_backup, decrypt_and_extract
from logger import log_message

class BackupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VAULTARCH")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both')

        self.backup_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.backup_frame, text='Backup')
        self.notebook.add(self.decrypt_frame, text='Decrypt')

        self.setup_backup_tab()
        self.setup_decrypt_tab()

    def setup_backup_tab(self):
        ttk.Label(self.backup_frame, text="Source Directory:").grid(row=0, column=0, sticky='w')
        self.src_entry = ttk.Entry(self.backup_frame, width=50)
        self.src_entry.grid(row=0, column=1)
        ttk.Button(self.backup_frame, text="Browse", command=self.browse_src).grid(row=0, column=2)

        ttk.Label(self.backup_frame, text="Destination Directory:").grid(row=1, column=0, sticky='w')
        self.dest_entry = ttk.Entry(self.backup_frame, width=50)
        self.dest_entry.grid(row=1, column=1)
        ttk.Button(self.backup_frame, text="Browse", command=self.browse_dest).grid(row=1, column=2)

        self.compress_var = tk.BooleanVar()
        self.encrypt_var = tk.BooleanVar()
        self.dedupe_var = tk.BooleanVar()
        self.integrity_var = tk.BooleanVar()
        self.report_var = tk.BooleanVar()

        ttk.Checkbutton(self.backup_frame, text="Compress", variable=self.compress_var).grid(row=2, column=0, sticky='w')
        ttk.Checkbutton(self.backup_frame, text="Encrypt (GPG)", variable=self.encrypt_var).grid(row=2, column=1, sticky='w')
        ttk.Checkbutton(self.backup_frame, text="Remove Duplicates", variable=self.dedupe_var).grid(row=2, column=2, sticky='w')
        ttk.Checkbutton(self.backup_frame, text="Integrity Check (SHA-256)", variable=self.integrity_var).grid(row=3, column=0, sticky='w')
        ttk.Checkbutton(self.backup_frame, text="Generate Report", variable=self.report_var).grid(row=3, column=1, sticky='w')

        ttk.Button(self.backup_frame, text="Start Backup", command=self.start_backup_thread).grid(row=4, column=1, pady=10)

        self.progress = ttk.Progressbar(self.backup_frame, length=300)
        self.progress.grid(row=5, column=0, columnspan=3, pady=5)

        self.speed_label = ttk.Label(self.backup_frame, text="Speed: 0 MB/s")
        self.speed_label.grid(row=6, column=0, columnspan=3)
        self.eta_label = ttk.Label(self.backup_frame, text="ETA: -- seconds")
        self.eta_label.grid(row=7, column=0, columnspan=3)

        self.log_text = tk.Text(self.backup_frame, height=10, width=70)
        self.log_text.grid(row=8, column=0, columnspan=3, pady=10)

    def setup_decrypt_tab(self):
        ttk.Label(self.decrypt_frame, text="Encrypted File:").grid(row=0, column=0, sticky='w')
        self.decrypt_entry = ttk.Entry(self.decrypt_frame, width=50)
        self.decrypt_entry.grid(row=0, column=1)
        ttk.Button(self.decrypt_frame, text="Browse", command=self.browse_encrypted).grid(row=0, column=2)

        ttk.Label(self.decrypt_frame, text="Destination Directory:").grid(row=1, column=0, sticky='w')
        self.decrypt_dest_entry = ttk.Entry(self.decrypt_frame, width=50)
        self.decrypt_dest_entry.grid(row=1, column=1)
        ttk.Button(self.decrypt_frame, text="Browse", command=self.browse_decrypt_dest).grid(row=1, column=2)

        ttk.Label(self.decrypt_frame, text="Password:").grid(row=2, column=0, sticky='w')
        self.decrypt_pass_entry = ttk.Entry(self.decrypt_frame, show="*")
        self.decrypt_pass_entry.grid(row=2, column=1)

        ttk.Button(self.decrypt_frame, text="Decrypt & Extract", command=self.start_decrypt_thread).grid(row=3, column=1, pady=10)

        self.decrypt_log = tk.Text(self.decrypt_frame, height=10, width=70)
        self.decrypt_log.grid(row=4, column=0, columnspan=3, pady=10)

    def browse_src(self):
        directory = filedialog.askdirectory()
        if directory:
            self.src_entry.delete(0, tk.END)
            self.src_entry.insert(0, directory)

    def browse_dest(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, directory)

    def browse_encrypted(self):
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.gpg")])
        if file_path:
            self.decrypt_entry.delete(0, tk.END)
            self.decrypt_entry.insert(0, file_path)

    def browse_decrypt_dest(self):
        directory = filedialog.askdirectory()
        if directory:
            self.decrypt_dest_entry.delete(0, tk.END)
            self.decrypt_dest_entry.insert(0, directory)

    def log_callback(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def decrypt_log_callback(self, message):
        self.decrypt_log.insert(tk.END, message + "\n")
        self.decrypt_log.see(tk.END)

    def progress_callback(self, percent, speed, eta):
        self.progress['value'] = percent
        self.speed_label.config(text=f"Speed: {speed:.2f} MB/s")
        self.eta_label.config(text=f"ETA: {int(eta)} seconds")

    def start_backup_thread(self):
        thread = threading.Thread(target=self.perform_backup)
        thread.start()

    def perform_backup(self):
        src = self.src_entry.get()
        dest = self.dest_entry.get()
        compress = self.compress_var.get()
        encrypt = self.encrypt_var.get()
        remove_dupes = self.dedupe_var.get()
        integrity_check = self.integrity_var.get()
        generate_report = self.report_var.get()

        if not os.path.isdir(src) or not os.path.isdir(dest):
            messagebox.showerror("Error", "Please select valid source and destination directories.")
            return

        self.log_text.delete(1.0, tk.END)
        run_backup(
            src, dest, compress, encrypt, remove_dupes,
            self.progress_callback, self.log_callback,
            password="mysecretpassword",
            integrity_check=integrity_check,
            generate_report=generate_report
        )

    def start_decrypt_thread(self):
        thread = threading.Thread(target=self.perform_decrypt)
        thread.start()

    def perform_decrypt(self):
        encrypted_file = self.decrypt_entry.get()
        dest = self.decrypt_dest_entry.get()
        password = self.decrypt_pass_entry.get()

        if not os.path.isfile(encrypted_file) or not os.path.isdir(dest):
            messagebox.showerror("Error", "Please select a valid encrypted file and destination.")
            return

        self.decrypt_log.delete(1.0, tk.END)
        decrypt_and_extract(encrypted_file, dest, self.decrypt_log_callback, self.progress_callback, password)

if __name__ == "__main__":
    root = tk.Tk()
    app = BackupApp(root)
    root.mainloop()
