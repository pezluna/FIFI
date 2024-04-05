import os
import sys

import logging
from lib.log_conf import init_logger

logger = logging.getLogger("logger")

def load_zigbee_files(path):
    files = []
    for file in os.listdir(path):
        if file.endswith(".pcap"):
            files.append(path + file)
    return files
