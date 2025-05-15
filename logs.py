
import logging
import os

log_dir = 'data/logs'
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    filename=f'{log_dir}/pentest.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_info(msg):
    logging.info(msg)

def log_warning(msg):
    logging.warning(msg)

def log_error(msg):
    logging.error(msg)
