"""
general utils
"""

import re


def convert_request_headers_dict_to_string(headers_dict: dict):
    headers_string = ''
    for header_name, header_value in headers_dict.items():
        headers_string += f'{header_name.lower()}: {header_value}\n'

    return headers_string


def make_header_names_small(headers_string: str):
    pattern = r'^(.+?):'
    matches = re.finditer(pattern, headers_string, re.MULTILINE)
    temp_headers_string = headers_string
    for m in matches:
        start_index = m.start()
        end_index = m.end()
        m_str = m.group()
        temp_headers_string = temp_headers_string[:start_index] + m_str.lower() + temp_headers_string[end_index:]

    return temp_headers_string
