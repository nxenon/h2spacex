"""
HTTP/2 Connection on TLS Context
"""
from h2spacex.h2_connection import H2Connection
import ssl


class H2OnTlsConnection(H2Connection):
    def __init__(self, hostname, port_number):
        super().__init__(hostname, port_number)
        self.tls_socket = None  # TLS Socket Context

    def setup_connection(self):
        self.create_raw_socket()  # set raw_socket object
        self.create_tls_context_on_raw_socket()  # set tls_socket object
        self.send_h2_connection_preface()  # send HTTP/2 Connection Preface
        self.send_client_initial_settings_frame()  # send client initial settings frame to server

    def create_tls_context_on_raw_socket(self):
        # Create SSL context
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_alpn_protocols(['h2'])

        # Wrap the raw socket with SSL/TLS
        ssl_socket = ssl_context.wrap_socket(self.raw_socket, server_hostname=self.hostname)
        self.tls_socket = ssl_socket
        print('* TLS connection established')

    def get_using_socket(self):
        """
        get using socket. for example return raw_socket
        :return:
        """
        return self.tls_socket
