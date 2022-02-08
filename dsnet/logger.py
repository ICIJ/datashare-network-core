import logging
import sys
from syslog import LOG_LOCAL7

from logging.handlers import SysLogHandler

logger = logging.getLogger('dsnet')
logger.setLevel(logging.INFO)


def default_log_formatter() -> logging.Formatter:
    return logging.Formatter('%(asctime)s :: %(name)s :: %(levelname)s :: %(message)s')


def add_syslog_handler(address: str = 'localhost', port: int = 514, facility: int = LOG_LOCAL7) -> None:
    sys_log_formatter = default_log_formatter()
    sys_log_handler = SysLogHandler(address = (address, port), facility = facility)
    sys_log_handler.setLevel(logging.INFO)
    sys_log_handler.setFormatter(sys_log_formatter)
    logger.addHandler(sys_log_handler)


def add_stdout_handler(level: int = logging.ERROR) -> None:
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(default_log_formatter())
    stream_handler.setLevel(level)
    logger.addHandler(stream_handler)
