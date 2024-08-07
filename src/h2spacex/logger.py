"""
logger for managing outputs of library
"""

be_silent_key = False


class Logger:
    def __init__(self):
        pass

    def logger_print(self, text=None):
        if not be_silent_key:
            print(text)
