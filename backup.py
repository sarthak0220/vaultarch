import os
import shutil
import time
import tarfile
import subprocess
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from monitor import TransferMonitor
import dedupe
from logger import log_message

def decrypt_and_extract(encrypted_file, dest, log_callback, progress_callback, password):
    if not shutil.which("gpg"):
        raise RuntimeError("GPG not found. Please install GPG and add it to your system PATH.")

    try:
        decrypted_file_path = os.path.join(dest, "decrypted_backup.tar.gz")

        log_message(f"Decrypting {encrypted_file}...", log_callback)
        subprocess.run(
            ["gpg", "--batch", "--yes", "--passphrase", password, "--output", decrypted_file_path, "--decrypt", encrypted_file],
            check=True
        )
        log_message("Decryption successful.", log_callback)

        log_message(f"Extracting {decrypted_file_path}...", log_callback)
        with tarfile.open(decrypted_file_path, "r:gz") as tar:
            tar.extractall(path=dest)
            log_message(f"Backup extracted to: {dest}", log_callback)

        os.remove(decrypted_file_path)
        log_message("Decrypted file removed.", log_callback)

        progress_callback(100, 0, 0)

    except subprocess.CalledProcessError as e:
        log_message(f"Decryption failed: {e}", log_callback)
    except Exception as e:
        log_message(f"Error during decryption and extraction: {e}", log_callback)


def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def run_backup(src, dest, compress=False, encrypt=False, remove_dupes=False, progress_callback=None,
               log_callback=None, password="mysecretpassword", integrity_check=False, generate_report=False):
    total_files = 0
    file_list = []

    for root, _, files in os.walk(src):
        for file in files:
            full_path = os.path.join(root, file)
            file_list.append(full_path)
            total_files += 1

    if total_files == 0:
        log_message("No files found in source directory.", log_callback)
        return

    start_time = time.time()
    bytes_copied = 0
    total_size = sum(os.path.getsize(f) for f in file_list)

    monitor = TransferMonitor(total_size)

    temp_backup_dir = os.path.join(dest, "linbackup_temp")
    if os.path.exists(temp_backup_dir):
        shutil.rmtree(temp_backup_dir)
    os.makedirs(temp_backup_dir)

    for index, file_path in enumerate(file_list):
        relative_path = os.path.relpath(file_path, src)
        dest_path = os.path.join(temp_backup_dir, relative_path)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        try:
            shutil.copy2(file_path, dest_path)
            bytes_copied += os.path.getsize(file_path)
        except Exception as e:
            log_message(f"[Error copying] {file_path}: {e}", log_callback)

        speed, eta = monitor.update(bytes_copied)
        percent = int((index + 1) / total_files * 100)

        if progress_callback:
            progress_callback(percent, speed, eta)

    if remove_dupes:
        log_message("Removing duplicate files...", log_callback)
        dedupe.remove_duplicates(temp_backup_dir, log_callback)

    # Determine the archive path based on user options
    if compress:
        archive_path = os.path.join(dest, "backup.tar.gz")
    else:
        archive_path = os.path.join(dest, "backup.tar")

# Create a tarball (compressed or uncompressed)
    if compress:
        log_message("Compressing backup...", log_callback)
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(temp_backup_dir, arcname=".")
    else:
        log_message("Creating uncompressed archive for encryption...", log_callback)
        with tarfile.open(archive_path, "w") as tar:
            tar.add(temp_backup_dir, arcname=".")

    # Clean up temporary directory
    shutil.rmtree(temp_backup_dir)


    if integrity_check:
        log_message("Performing integrity check (SHA-256)...", log_callback)
        checksum = calculate_sha256(archive_path)
        with open(archive_path + ".sha256", "w") as f:
            f.write(checksum)
        log_message(f"Checksum saved to: {archive_path}.sha256", log_callback)

    if encrypt:
        log_message("Encrypting backup using GPG...", log_callback)
        try:
            subprocess.run(
                ["gpg", "--batch", "--yes", "--symmetric", "--cipher-algo", "AES256", archive_path],
                check=True
            )
            os.remove(archive_path)
            archive_path += ".gpg"
            log_message(f"Encryption complete: {archive_path}", log_callback)
        except subprocess.CalledProcessError as e:
            log_message(f"Encryption failed: {str(e)}", log_callback)
            return

    if generate_report:
        report_path = os.path.join(dest, "backup_report.txt")
        with open(report_path, "w") as report:
            report.write(f"Backup Report\n")
            report.write(f"Source: {src}\n")
            report.write(f"Destination: {dest}\n")
            report.write(f"Files Backed Up: {total_files}\n")
            report.write(f"Compressed: {compress}\n")
            report.write(f"Encrypted: {encrypt}\n")
            report.write(f"Duplicate Removal: {remove_dupes}\n")
            report.write(f"Time Taken: {time.time() - start_time:.2f} seconds\n")
            report.write(f"Total Size: {total_size / (1024 * 1024):.2f} MB\n")
            if compress:
                report.write(f"Compressed Size: {os.path.getsize(archive_path) / (1024 * 1024):.2f} MB\n")
            else:
                report.write(f"Backup Size: {total_size / (1024 * 1024):.2f} MB\n")
            if integrity_check:
                report.write(f"SHA-256: {checksum}\n")

        log_message(f"Backup summary saved to: {report_path}", log_callback)

    log_message(f"Backup complete. Saved to: {archive_path}", log_callback)
    log_message(f"Original Size: {total_size / (1024 * 1024):.2f} MB", log_callback)
    if compress:
        log_message(f"Compressed Backup Size: {os.path.getsize(archive_path) / (1024 * 1024):.2f} MB", log_callback)
    else:
        log_message(f"Backup Size: {total_size / (1024 * 1024):.2f} MB", log_callback)