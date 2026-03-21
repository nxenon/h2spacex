"""
logger for managing outputs of library
"""

be_silent_key = False
debug = False
count = 0
debug_text = """
from h2spacex import logger
logger.debug = True
""".strip()


class Logger:
    def __init__(self):
        pass

    def logger_print(self, text=None, is_msg_debug=False):
        global count
        if is_msg_debug:
            if not debug:
                if be_silent_key:
                    return
                if count == 0:
                    count = -1
                    print('-------------------------------------')
                    print('Some logs are only available in debug mode! for enabling it do this:')
                    print(debug_text)
                    print('-------------------------------------')
                return
        if not be_silent_key or debug:
            print(text)
