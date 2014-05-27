'''Docstring to silence pylint; ignores --ignore option for __init__.py'''
import sys
import os
import logging

# Global config dictionary
# Populated by oft.
config = {}

# Global DataPlane instance used by all tests.
# Populated by oft.
dataplane_instance = None


def open_logfile(name):
    """
    (Re)open logfile

    When using a log directory a new logfile is created for each test. The same
    code is used to implement a single logfile in the absence of --log-dir.
    """

    _format = "%(asctime)s.%(msecs)03d  %(name)-10s: %(levelname)-8s: %(message)s"
    _info_format = "%(message)s" # by jungwoo
    _datefmt = "%H:%M:%S"

    if config["log_dir"] != None:
        filename = os.path.join(config["log_dir"], name) + ".log"
        info_filename = os.path.join(config["info_log_dir"], name) + ".info" # by jungwoo
    else:
        filename = config["log_file"]
        info_filename = config["info_log_file"] # by jungwoo

    logger = logging.getLogger()

    # Remove any existing handlers
    for handler in logger.handlers:
        logger.removeHandler(handler)
        handler.close()
    # Add a new handler
    #handler = logging.FileHandler(filename, mode='a')
    #handler.setFormatter(logging.Formatter(_format, _datefmt))
    #logger.addHandler(handler)

    # Add an info handler (by jungwoo)
    handler = logging.FileHandler(filename, mode='a')
    info_handler = logging.FileHandler(info_filename, mode='a')

    handler.setFormatter(logging.Formatter(_format, _datefmt))
    info_handler.setFormatter(logging.Formatter(_info_format, _datefmt))

    logger.addHandler(handler)
    logger.addHandler(info_handler)

    # by jungwoo
    class LevelFilter(logging.Filter):
        def __init__(self, level):
            self.level = level
        def filter(self, record):
            return record.levelno == self.level

    # handler.addFilter(LevelFilter(logging.DEBUG))
    info_handler.addFilter(LevelFilter(logging.INFO))



