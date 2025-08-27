import time

class TransferMonitor:
    def __init__(self, total_size_bytes):
        self.total_size = total_size_bytes
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.bytes_transferred = 0

    def update(self, new_bytes_transferred):
        self.bytes_transferred = new_bytes_transferred
        current_time = time.time()
        elapsed_time = current_time - self.start_time

        speed_mb_per_s = (self.bytes_transferred / (1024 * 1024)) / elapsed_time if elapsed_time > 0 else 0
        remaining_bytes = self.total_size - self.bytes_transferred
        eta_seconds = int(remaining_bytes / (speed_mb_per_s * 1024 * 1024)) if speed_mb_per_s > 0 else -1

        return round(speed_mb_per_s, 2), eta_seconds
