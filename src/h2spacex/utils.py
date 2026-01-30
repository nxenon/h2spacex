"""
general utils
"""

from email.parser import Parser


def convert_request_headers_dict_to_string(headers_dict: dict):
    headers_string = ""
    for header_name, header_value in headers_dict.items():
        headers_string += f"{header_name.lower()}: {header_value}\n"

    return headers_string


def make_header_names_small(headers_string: str) -> str:
    """
    Normalize HTTP headers: lowercase header names, preserve values.
    """
    headers_string = headers_string.strip()
    headers = Parser().parsestr(headers_string)
    h = "".join(f"{k.lower()}: {v}\n" for k, v in headers.items())
    return h.strip()
