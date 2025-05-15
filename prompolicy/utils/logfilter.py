import logging
import os
from collections import defaultdict

LF_BASE, LF_WEB, LF_POLICY, LF_MODEL, LF_RESPONSES = range(5)

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("DEBUG", False) else logging.INFO
)

levels = defaultdict(bool)

try:
    for n in range(int(os.environ.get("DEBUG", 0))):
        levels[n] = True
except:
    pass


class FilteredLogger(object):
    def __init__(self, name, baselevel=logging.INFO, levels=levels, stream=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(baselevel)
        self.levels = levels
        # initialize default level
        self.levels[0] = True

    def info(self, message, level=0):
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.info(message)

    def debug(self, message, level=0):
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.debug(message)

    def warning(self, message, level=0):
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.warning(message)

    def error(self, message, level=0):
        if message is None:
            return
        if self.levels[level] == True:
            self.logger.error(message)
