import logging

# Set up logging configuration
log_file = "backup.log"
logging.basicConfig(filename=log_file, level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def log_message(message, log_callback=None):
    """Log message to both file and callback (for GUI)."""
    logging.info(message)
    if log_callback:
        log_callback(message)
