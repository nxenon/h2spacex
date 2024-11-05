"""
HTTP/2 Connection on TLS Context
"""
from .h2_connection import H2Connection

from . import h2_frames
import ssl
from .logger import Logger
logger = Logger()


class H2OnTlsConnection(H2Connection):
    def __init__(self, hostname, port_number, read_timeout=3,
                 proxy_hostname=None, proxy_port_number=None, ssl_log_file_path=None):
        super().__init__(hostname, port_number, read_timeout=read_timeout, proxy_hostname=proxy_hostname, proxy_port_number=proxy_port_number)
        self.tls_socket = None  # TLS Socket Context
        self.ssl_log_file_path = ssl_log_file_path

    def setup_connection(self):
        try:
            self._create_raw_socket()
            self.__create_tls_context_on_raw_socket()  # set tls_socket object
            self._send_h2_connection_preface()  # send HTTP/2 Connection Preface
            self._send_client_initial_settings_frame()  # send client initial settings frame to server
        except Exception as e:
            t = '# Error in setting the connection up : ' + str(e)
            logger.logger_print(t)
            raise e

        else:
            self.is_connection_closed = False

    def close_connection(self):
        """
        close the connection
        :return:
        """
        go_away_frame = h2_frames.create_go_away_frame(err_code=0)
        self.send_bytes(bytes(go_away_frame))
        self.tls_socket.close()
        self.raw_socket.close()
        self.raw_socket = None
        self.tls_socket = None
        self.is_connection_closed = True
        logger.logger_print('- Connection closed')

    def __create_tls_context_on_raw_socket(self):
        # Create SSL context
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.ssl_log_file_path is not None:
            ssl_context.keylog_filename = self.ssl_log_file_path
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_alpn_protocols(['h2'])

        # Wrap the raw socket with SSL/TLS
        ssl_socket = ssl_context.wrap_socket(self.raw_socket, server_hostname=self.hostname)
        self.tls_socket = ssl_socket
        logger.logger_print('+ TLS connection established')

    def get_using_socket(self):
        """
        get using socket. for example return raw_socket
        :return:
        """
        return self.tls_socket
