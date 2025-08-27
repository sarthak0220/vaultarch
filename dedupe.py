import os
import hashlib
import subprocess
import shutil

def remove_duplicates(path, log_callback=None):
    if shutil.which("fdupes"):
        _remove_with_fdupes(path, log_callback)
    else:
        if log_callback:
            log_callback("fdupes not found. Using slower Python hashing...")
        _remove_with_hashing(path, log_callback)

def _remove_with_fdupes(path, log_callback):
    try:
        # Get duplicate file groups
        result = subprocess.run(["fdupes", "-r", path], capture_output=True, text=True)
        groups = result.stdout.strip().split("\n\n")
        
        for group in groups:
            files = group.strip().split("\n")
            if len(files) <= 1:
                continue
            # Keep the first file, remove the rest
            for dup in files[1:]:
                try:
                    os.remove(dup)
                    if log_callback:
                        log_callback(f"Removed duplicate: {dup}")
                except Exception as e:
                    if log_callback:
                        log_callback(f"[Error] Failed to remove {dup}: {e}")
    except Exception as e:
        if log_callback:
            log_callback(f"[Error running fdupes]: {e}")

def _remove_with_hashing(path, log_callback):
    hashes = {}
    for root, _, files in os.walk(path):
        for name in files:
            file_path = os.path.join(root, name)
            try:
                file_hash = _hash_file(file_path)
                if file_hash in hashes:
                    os.remove(file_path)
                    if log_callback:
                        log_callback(f"Removed duplicate: {file_path}")
                else:
                    hashes[file_hash] = file_path
            except Exception as e:
                if log_callback:
                    log_callback(f"[Error hashing] {file_path}: {e}")

def _hash_file(path, chunk_size=65536):
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()
