"""
HTTP/2 Connection
"""
import socket
import time

from scapy import config
config.conf.logLevel = 40  # Set log level to ERROR to ignore warnings
from threading import Thread
import scapy.contrib.http2 as h2
from scapy.all import hex_bytes
from . import h2_frames, utils
import socks
from .logger import Logger
logger = Logger()


class H2Connection:
    def __init__(self, hostname, port_number, read_timeout=3, proxy_hostname=None, proxy_port_number=None):
        self.hostname = hostname  # e.g http2.github.io
        self.port_number = port_number  # e.g 443
        self.proxy_hostname = proxy_hostname  # proxy hostname e.g 127.0.0.1
        self.proxy_port_number = proxy_port_number  # proxy port e.g 10808
        self.raw_socket = None  # raw socket object
        self.read_timeout = read_timeout  # timeout when reading response from socket
        self.last_used_stream_id = 1  # define last stream ID used to continue stream IDs
        self.is_connection_closed = True  # if connection is not closed, this variable is False
        # if is_threaded_response_finished is true it means that start_thread_response_parsing function is finished
        self.is_threaded_response_finished = None
        self.threaded_frame_parser : h2_frames.FrameParser = None
        # HTTP/2 Connection Preface
        self.H2_PREFACE = hex_bytes('505249202a20485454502f322e300d0a0d0a534d0d0a0d0a')
        self.DEFAULT_SETTINGS = {
            'SETTINGS_HEADER_TABLE_SIZE': {
                'id': 1,
                'value': 4096
            },
            'SETTINGS_ENABLE_PUSH': {
                'id': 2,
                'value': 0
            },
            'SETTINGS_MAX_CONCURRENT_STREAMS': {
                'id': 3,
                'value': 100
            },
            'SETTINGS_INITIAL_WINDOW_SIZE': {
                'id': 4,
                'value': 65535
            },
            'SETTINGS_MAX_FRAME_SIZE': {
                'id': 5,
                'value': 16384
            },
            'SETTINGS_MAX_HEADER_LIST_SIZE': {
                'id': 6,
                'value': None
            },
        }

    def setup_connection(self):
        """
        TODO
        :return:
        """

    def __thread_response_frame_parsing(self, _timeout=0.5, print_responses=False):
        """
        method which is thread oriented for response parsing
        :param _timeout:
        :param print_responses: if this is true, response headers and content, will be printed
        :return:
        """
        try:
            self.read_response_from_socket_with_time(_timeout=_timeout)

        except KeyboardInterrupt:
            return

        self.is_threaded_response_finished = True

    def start_thread_response_parsing(self, _timeout=0.5, print_responses=False):
        """
        method which is thread oriented for response parsing
        :param _timeout:
        :param print_responses: if this is true, response headers and content, will be printed
        :return:
        """
        self.is_threaded_response_finished = False
        try:
            Thread(target=self.__thread_response_frame_parsing, args=(_timeout, print_responses,)).start()
        except KeyboardInterrupt:
            self.is_threaded_response_finished = None
            return

    def _create_socks_socket(self):
        """
        create a SOCKS5 Socket with self.proxy_hostname and self.proxy_port_number
        set the self.raw_socket to created SOCKS5
        :return:
        """

        socks.set_default_proxy(socks.SOCKS5, self.proxy_hostname, self.proxy_port_number)
        socket.socket = socks.socksocket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
        sock.connect((self.hostname, self.port_number))
        self.raw_socket = sock
        sock_addr = sock.getsockname()
        logger.logger_print(f'+ Connected through Proxy: {self.hostname}:{self.port_number} --> {sock_addr[0]}:{sock_addr[1]}')

    def _create_raw_socket(self):
        """
        create raw socket and return it
        :return:
        """

        if self.proxy_hostname:
            self._create_socks_socket()
            return

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Enable Nagle algorithm
        raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
        raw_socket.connect((self.hostname, self.port_number))

        self.raw_socket = raw_socket
        sock_addr = raw_socket.getsockname()
        logger.logger_print(f'+ Connected to: {self.hostname}:{self.port_number} --> {sock_addr[0]}:{sock_addr[1]}')

    def _send_h2_connection_preface(self):
        self.send_bytes(self.H2_PREFACE)
        logger.logger_print('+ H2 connection preface sent')

    def get_using_socket(self):
        """
        get using socket. for example return raw_socket
        :return:
        """
        return self.raw_socket

    def send_bytes(self, bytes_data: bytes):
        """
        send bytes into socket(raw or TLS socket)
        :param bytes_data: bytes data for sending into socket
        :return:
        """
        using_socket = self.get_using_socket()
        try:
            using_socket.send(bytes_data)
        except Exception as e:
            logger.logger_print('# Error in sending bytes: ' + str(e))

    def send_frames(self, frames):
        """
        send frames into socket(raw or TLS socket)
        :param frames: frame for sending into socket
        :return:
        """
        using_socket = self.get_using_socket()
        self.send_bytes(bytes(frames))

    def read_response_from_socket(self, _timeout=None) -> bytes:
        """
        read from socket(raw or TLS socket), and return bytes
        :return:
        """

        if _timeout is None:
            timeout = self.read_timeout
        else:
            timeout = _timeout

        using_socket = self.get_using_socket()
        try:
            using_socket.settimeout(timeout)

        except Exception as e:
            return b''

        response = b''
        while True:
            try:
                data = using_socket.recv(4096)
                if not data:
                    break
            except socket.timeout:
                break
            response += data

        return response

    def read_response_from_socket_with_time(self, _timeout=None) -> None:
        """
        read from socket(raw or TLS socket), and return bytes
        :return:
        """

        if _timeout is None:
            timeout = self.read_timeout
        else:
            timeout = _timeout

        using_socket = self.get_using_socket()
        try:
            using_socket.settimeout(timeout)

        except Exception as e:
            print('Error Occurred in setting timeout: ' + str(e))
            return
        # self.new_parse_frames_bytes(resp)
        while True:
            try:
                data = using_socket.recv(4096)
                if not data:
                    break
            except socket.timeout:
                break

            self.new_parse_frames_bytes(data, resp_ns_time=time.time_ns())

    def old_parse_frames_bytes(self, frame_bytes, is_verbose=False):
        """
        parse frames bytes. for example parse response frames from server
        :param frame_bytes: bytes type of frames
        :param is_verbose: if is_verbose is True, then the method of .show() will be invoked for the frame
        :return:
        """

        h2_frames.parse_response_frames_bytes(frame_bytes, socket_obj=self.get_using_socket(), is_verbose=is_verbose)

    def new_parse_frames_bytes(self, frame_bytes, is_verbose=False, resp_ns_time=None):
        """
        parse frames bytes. for example parse response frames from server
        :param frame_bytes: bytes type of frames
        :param is_verbose: if is_verbose is True, then the method of .show() will be invoked for the frame
        :param resp_ns_time: response time of request in nano seconds
        :return:
        """

        # h2_frames.parse_response_frames_bytes(frame_bytes, socket_obj=self.get_using_socket(), is_verbose=is_verbose)
        if self.threaded_frame_parser is None:
            self.threaded_frame_parser = h2_frames.FrameParser(
                h2_connection=self,
            )
        self.threaded_frame_parser.add_frames(frame_bytes, resp_ns_time=resp_ns_time)

    def send_ping_frame(
            self,
            ping_data=b"12345678"
    ):
        """
        send ping frame to make the idle connection active
        :param ping_data:
        :return:
        """
        ping_frame = h2_frames.create_ping_frame(ping_data=ping_data)
        self.send_bytes(bytes(ping_frame))

    def close_connection(self):
        """
        close the connection
        :return:
        """
        go_away_frame = h2_frames.create_go_away_frame(err_code=0)
        self.send_bytes(bytes(go_away_frame))
        self.raw_socket.close()
        self.raw_socket = None
        self.is_connection_closed = True

    def _send_client_initial_settings_frame(self):
        """
        send client initial settings to the server
        :return:
        """

        settings_list = []
        for s in self.DEFAULT_SETTINGS.keys():
            if self.DEFAULT_SETTINGS[s]['value'] is None:  # if value of the setting is None, then do not send it
                continue
            temp_s = h2.H2Setting(id=self.DEFAULT_SETTINGS[s]['id'], value=self.DEFAULT_SETTINGS[s]['value'])
            settings_list.append(temp_s)

        client_initial_settings_frame = h2_frames.create_settings_frame(settings=settings_list)

        self.send_bytes(bytes(client_initial_settings_frame))
        logger.logger_print('+ Client initial SETTINGS frame sent: ')
        logger.logger_print('// Client SETTINGS //')
        logger.logger_print(self.DEFAULT_SETTINGS)
        logger.logger_print()

    def generate_stream_ids(self, number_of_streams):
        """
        generate stream IDs by checking self.last_used_stream_id (incremental) just odd stream IDs
        :param number_of_streams:
        :return:
        """

        if self.last_used_stream_id % 2 == 0:
            self.last_used_stream_id += 1

        start_stream_id = self.last_used_stream_id + 2
        end_stream_id = (number_of_streams * 2) + start_stream_id
        stream_ids_list = []
        for i in range(start_stream_id, end_stream_id, 2):
            stream_ids_list.append(i)

        self.last_used_stream_id = stream_ids_list[-1]
        return stream_ids_list

    def create_single_packet_http2_post_request_frames(
            self,
            authority,
            scheme,
            path,
            headers_string,
            stream_id,
            body,
            check_headers_lowercase=True,
            method='POST'
    ):
        """
        create simple http/2 POST request(Headers Frame + Data)
        this function returns two variable, the first return variable is the request with body without the last byte,
        and the second return variable is last frame with last byte
        :param method: method of the request. e.g. GET
        :param authority: equivalent of host header in http/1. e.g. google.com
        :param scheme: http or https
        :param path: request path. e.g. /index.html
        :param headers_string: headers in request. split with \n --> user-agent: xxx\n
        :param check_headers_lowercase: if this is True, the headers names will be checked to be lowercase
        :param stream_id: stream id of the request
        :param body: if the request method is not get, then it needs to have body
        :return:
        """
        if body:
            body = bytes(body, 'utf-8')

        if check_headers_lowercase:
            headers_string = utils.make_header_names_small(headers_string)

        post_request_frames = h2_frames.create_headers_frame(
            method=method,
            authority=authority,
            scheme=scheme,
            path=path,
            headers_string=headers_string,
            stream_id=stream_id,
            body=body,
        )
        last_byte = post_request_frames.frames[-1].data[-1:]
        post_request_frames.frames[-1].data = post_request_frames.frames[-1].data[:-1]
        post_request_frames.frames[-1].flags.remove('ES')
        new_data_frame = h2.H2Frame(stream_id=stream_id, flags={'ES'}) / h2.H2DataFrame(data=last_byte)

        return post_request_frames, new_data_frame

    def create_single_packet_http2_get_request_frames(
            self,
            authority,
            scheme,
            path,
            headers_string,
            stream_id,
            check_headers_lowercase=True,
            body=None,
            method='GET',
    ):
        """
        create simple http/2 GET request(Headers Frame + Null Data)
        this function returns two variable, the first return variable is the request with body without the last byte,
        and the second return variable is last frame with last byte
        :param method: method of the request. e.g. GET
        :param authority: equivalent of host header in http/1. e.g. google.com
        :param scheme: http or https
        :param path: request path. e.g. /index.html
        :param headers_string: headers in request. split with \n --> user-agent: xxx\n
        :param check_headers_lowercase: if this is True, the headers names will be checked to be lowercase
        :param stream_id: stream id of the request
        :param body: if the request method is not get, then it needs to have body
        :return:
        """
        if body:
            body = bytes(body, 'utf-8')

        if check_headers_lowercase:
            headers_string = utils.make_header_names_small(headers_string)

        # TODO: implement content-length: 1 method
        # headers_string = headers_string.strip()
        # headers_string += '\ncontent-length: 1\n'

        headers_string = utils.make_header_names_small(headers_string)

        get_request_frames = h2_frames.create_headers_frame(
            method=method,
            authority=authority,
            scheme=scheme,
            path=path,
            headers_string=headers_string,
            stream_id=stream_id,
            body=None,
        )

        # TODO
        get_request_frames.frames[0].flags.remove('ES')
        # continuation_frame = h2.H2Frame(stream_id=stream_id, flags={'EH'}) / h2.H2ContinuationFrame()
        new_data_frame = h2.H2Frame(stream_id=stream_id, flags={'ES'}) / h2.H2DataFrame(data=b'')

        return get_request_frames, new_data_frame

    def create_simple_http2_request(
            self,
            method,
            authority,
            scheme,
            path,
            headers_string,
            stream_id,
            body=None,
            check_headers_lowercase=True,
    ):
        """
        create simple http/2 request(Headers Frame + Data(Optional)) and return the frames
        :param method: method of the request. e.g. GET
        :param authority: equivalent of host header in http/1. e.g. google.com
        :param scheme: http or https
        :param path: request path. e.g. /index.html
        :param headers_string: headers in request. split with \n --> user-agent: xxx\n
        :param stream_id: stream id of the request
        :param body: if the request method is not get, then it needs to have body
        :param check_headers_lowercase:  if this is True, the headers names will be checked to be lowercase
        :return:
        """

        if body:
            body = bytes(body, 'utf-8')

        if check_headers_lowercase:
            headers_string = utils.make_header_names_small(headers_string)

        request_frames = h2_frames.create_headers_frame(
            method=method,
            authority=authority,
            scheme=scheme,
            path=path,
            headers_string=headers_string,
            stream_id=stream_id,
            body=body,
        )

        return request_frames

    def send_simple_http2_request(
            self,
            method,
            authority,
            scheme,
            path,
            headers_string,
            stream_id,
            body=None,
            check_headers_lowercase=True,
    ):
        """
        send simple http/2 request(Headers Frame + Data(Optional))
        :param method: method of the request. e.g. GET
        :param authority: equivalent of host header in http/1. e.g. google.com
        :param scheme: http or https
        :param path: request path. e.g. /index.html
        :param headers_string: headers in request. split with \n --> user-agent: xxx\n
        :param stream_id: stream id of the request
        :param body: if the request method is not get, then it needs to have body
        :param check_headers_lowercase:  if this is True, the headers names will be checked to be lowercase
        :return:
        """

        if body:
            body = bytes(body, 'utf-8')

        if check_headers_lowercase:
            headers_string = utils.make_header_names_small(headers_string)

        request_frames = h2_frames.create_headers_frame(
            method=method,
            authority=authority,
            scheme=scheme,
            path=path,
            headers_string=headers_string,
            stream_id=stream_id,
            body=body,
        )

        self.send_bytes(bytes(request_frames))
        # print('Headers Request Frame Sent: ' + str(request_frames))
        more_info_msg = f"""+----- Start Request Info -----+
Stream ID: {stream_id}
:method: {method}
:authority: {authority}
:scheme: {scheme}
:path: {path}
{headers_string}
body:
{body}
+----- END Request Info -----+
"""
        logger.logger_print(more_info_msg)
