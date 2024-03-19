import logging
from colorlog import ColoredFormatter

def init_logger():
    # 로그 설정
    logger = logging.getLogger("logger")
    logger.setLevel(logging.DEBUG)

    formatter = ColoredFormatter(
        "%(log_color)s[%(levelname)s] %(asctime)s - %(message)s - (%(filename)s:%(lineno)d)%(reset)s",
        datefmt=None,
        reset=True,
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'green',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'red',
        }
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)