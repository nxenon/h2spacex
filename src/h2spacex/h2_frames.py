import scapy.contrib.http2 as h2
from scapy.packet import NoPayload
import gzip
import brotli
import zlib


def decompress_gzip_data(gzip_data: bytes):
    # decompress gzip
    try:
        decompressed_content = gzip.decompress(gzip_data)
        decoded_content = decompressed_content.decode('utf-8')
    except Exception as e:
        print('# Error in decompressing gzip encoded body : ' + str(e))
        return gzip_data

    return decoded_content


def decompress_br_data(br_data: bytes):
    # Decompress br
    try:
        decompressed_content = brotli.decompress(br_data)
        decoded_content = decompressed_content.decode('utf-8')
    except Exception as e:
        print('# Error in decompressing br encoded body : ' + str(e))
        return br_data

    return decoded_content


def decompress_deflate_data(deflate_data: bytes):
    # Decompress the Deflate-compressed data
    try:
        decompressed_content = zlib.decompress(deflate_data, -zlib.MAX_WBITS)
        decoded_content = decompressed_content.decode('utf-8')
    except Exception as e:
        print('# Error in decompressing deflate encoded body : ' + str(e))
        return deflate_data

    return decoded_content


class FrameParser:
    """
    class for parsing response frames
    it also handles some tasks: for example if server sends settings frame, it send ACK for it
    """
    def __init__(self, h2_connection=None, is_gzipped=False):
        # headers and data frames list
        # format --> {1: {'header': 'response header frame', 'data': b'response data frames'}}
        # format --> {STREAM_ID: {'header': 'response header frame', 'data': b'response data frames'}}
        self.headers_and_data_frames = {}
        # H2 Connection Object (H2Connection OR H2OnTlsConnection)
        self.h2_connection = h2_connection
        self.headers_table = h2.HPackHdrTable()

    def show_response_of_sent_requests(self):
        for s_id in self.headers_and_data_frames.keys():
            headers = self.headers_and_data_frames[s_id]['header']
            print(f'#-    Stream ID: {s_id}   -#')
            print('-Headers-')
            print(headers)
            print('-Body-')
            data = self.headers_and_data_frames[s_id]['data']
            if 'content-encoding: gzip' in headers:
                data = decompress_gzip_data(data)
            elif 'content-encoding: br' in headers:
                data = decompress_br_data(data)
            elif 'content-encoding: deflate' in headers:
                data = decompress_deflate_data(data)

            print(str(data))

    def add_frames(self, frames_bytes: bytes, is_verbose=False):
        if frames_bytes:
            parsed_frames = h2.H2Seq(frames_bytes).frames

            for f in parsed_frames:
                if is_verbose:
                    print(f.show())

                if isinstance(f.payload, h2.H2HeadersFrame):
                    self.parse_header_frame(f)

                elif isinstance(f.payload, h2.H2DataFrame):
                    self.parse_data_frame(f)

                elif isinstance(f.payload, h2.H2SettingsFrame):
                    self.parse_settings_frame(f)

                elif isinstance(f.payload, h2.H2WindowUpdateFrame):
                    self.parse_window_update_frame(f)

                elif isinstance(f.payload, h2.H2PingFrame):
                    self.parse_ping_frame(f)

                elif isinstance(f.payload, NoPayload):
                    if f.type == 4:  # settings frame
                        self.parse_settings_frame(f)

                elif isinstance(f.payload, h2.H2ResetFrame):
                    self.parse_reset_frame(f)

                else:
                    print('--frame--')
                    print('Frame Type: ' + str(type(f.payload)) + ' / Type ID: ' + str(f.type))
                    f.show()
                    print('##frame##')

    def parse_settings_frame(self, settings_frame):
        if 'A' in settings_frame.flags:
            print('* Server sent ACK for client SETTINGS frame')

        else:
            print('* Server sent Settings frame with following values:')
            print('// Server SETTINGS //')
            print(settings_frame.settings)
            print()
            ack_settings_frame = create_settings_frame(is_ack=1)
            self.send_frame(ack_settings_frame)
            print('+ Client sent ACK for server SETTINGS frame')

    def parse_window_update_frame(self, windows_update_frame):
        print('* Server sent WINDOW UPDATE frame with win_increase_size of: ' + str(windows_update_frame.win_size_incr))

    def parse_ping_frame(self, ping_frame):
        if 'A' in ping_frame.flags:
            print('* Server sent ACK for PING frame')

    def parse_reset_frame(self, reset_frame):
        print(f'# Server sent RESET frame for Stream ID: {reset_frame.stream_id}, with Err_Code: {reset_frame.error}')

    def parse_header_frame(self, header_frame):
        headers_string = self.get_headers_string_from_headers_frame(header_frame)
        stream_id = header_frame.stream_id
        if stream_id not in self.headers_and_data_frames:
            self.headers_and_data_frames[stream_id] = {'header': headers_string, 'data': b''}
        else:
            self.headers_and_data_frames[stream_id]['headers'] += headers_string

    def get_headers_string_from_headers_frame(self, headers_frame):
        headers_string = self.headers_table.gen_txt_repr(headers_frame.hdrs)
        return headers_string

    def parse_data_frame(self, data_frame):
        stream_id = data_frame.stream_id
        if stream_id not in self.headers_and_data_frames:
            self.headers_and_data_frames[stream_id] = {'header': '', 'data': data_frame.data}
        else:
            self.headers_and_data_frames[stream_id]['data'] += data_frame.data

    def send_frame(self, frame):
        if frame:
            frame = bytes(frame)
            if not self.h2_connection.is_connection_closed:
                self.h2_connection.send_bytes(frame)


def create_headers_frame(
        method,
        path,
        authority,
        scheme,
        headers_string,
        stream_id,
        body=None,
):
    hpack_header_table = h2.HPackHdrTable()
    pseudo_headers_str = f':method {method}\n:path {path}\n:scheme {scheme}\n:authority {authority}\n'

    all_headers = pseudo_headers_str + headers_string

    parsed_txt_headers = hpack_header_table.parse_txt_hdrs(
        bytes(all_headers.strip(), 'UTF-8'),
        stream_id=stream_id,
        body=body
    )

    return parsed_txt_headers


def create_priority_headers_frame(
        method,
        path,
        authority,
        scheme,
        headers_string,
        stream_dependency,
        weight,
        stream_id,
        body=None,
):
    hpack_header_table = h2.HPackHdrTable()
    pseudo_headers_str = f':method {method}\n:path {path}\n:scheme {scheme}\n:authority {authority}\n'

    all_headers = pseudo_headers_str + headers_string
    parsed_txt_headers = hpack_header_table.parse_txt_hdrs(
        bytes(all_headers.strip(), 'UTF-8'),
        stream_id=stream_id,
        body=body
    )

    header_priority_frame = None
    for f in parsed_txt_headers.frames:
        new_flags = f.flags.copy()
        new_flags.add('+')

        header_priority_frame = h2.H2Frame(
            stream_id=f.stream_id,
            flags=new_flags
        ) / h2.H2PriorityHeadersFrame(
            hdrs=f.hdrs,
            stream_dependency=stream_dependency,
            weight=weight
        )

    return header_priority_frame


def create_settings_frame(
        settings=None,
        is_ack=0
):
    if settings is None:
        settings = []
    if is_ack:
        return h2.H2Frame(flags={'A'}) / h2.H2SettingsFrame()

    return h2.H2Frame() / h2.H2SettingsFrame(
        settings=settings
    )


_old_headers_table = h2.HPackHdrTable()
def _get_headers_string_from_headers_frame(headers_frame):
    """
    this function will be deprecated
    get string of response headers from headers frame
    :param headers_frame:
    :return:
    """
    headers_string = _old_headers_table.gen_txt_repr(headers_frame.hdrs)
    return headers_string


def parse_response_frames_bytes(
        frames_bytes,
        socket_obj=None,
        is_verbose=False
):
    """
    parse frames bytes. for example parse response frames from server
    :param frames_bytes:
    :param socket_obj: object which is tls socket or raw_socket on it
    :param is_verbose: if is_verbose is True, then the method of .show() will be invoked for the frame
    :return:
    """

    raw_frame_bytes = frames_bytes
    if raw_frame_bytes:
        print('+--------- START Response Frames ---------+')
        parsed_frames = h2.H2Seq(raw_frame_bytes).frames
        # print(parsed_frames)

        for f in parsed_frames:
            if is_verbose:
                print(f.show())

            if isinstance(f.payload, h2.H2HeadersFrame):
                headers_string = _get_headers_string_from_headers_frame(f)
                print(f'------ Headers Stream ID: {f.stream_id} ------')
                print(headers_string)

            elif isinstance(f.payload, h2.H2DataFrame):
                print(f'------ Data Stream ID: {f.stream_id} ------')
                with gzip.GzipFile(fileobj=gzip.io.BytesIO(f.data), mode='rb') as decompressed_file:
                    # Read the decompressed data
                    decompressed_content = decompressed_file.read()

                # If the decompressed content is in bytes, you might want to decode it (if it contains text)
                decoded_content = decompressed_content.decode('utf-8')
                print(decoded_content)

                # print(f'------ Data Stream ID: {f.stream_id} ------')
                # print(str(f.data))

            elif isinstance(f.payload, h2.H2SettingsFrame):
                if socket_obj is not None:
                    print('* got a Settings frame from server')
                    settings_frame = create_settings_frame(is_ack=1)
                    socket_obj.send(bytes(settings_frame))
                    print('* client sent ACK for server Settings')

            elif isinstance(f.payload, h2.H2WindowUpdateFrame):
                print('* server sent WindowUpdate Frame with win_increase_size of: ' + str(f.win_size_incr))

            elif isinstance(f.payload, h2.H2PingFrame):
                print('* server sent ACK for PING frame')

            elif isinstance(f.payload, NoPayload):
                if f.type == 4:  # settings frame
                    if 'A' in f.flags:
                        print('* server sent ACK for client Settings')

            else:
                print('--frame--')
                f.show()
                print('##frame##')

        print('+--------- END Response Frames ---------+')


def create_ping_frame(ping_data='12345678', is_ack=0):
    """
    create and return a ping frame
    :return:
    """

    if len(ping_data) != 8:
        print('ping frame payload must be 8 in length! --> ' + ping_data + ' is invalid!')
        exit()

    if is_ack:
        ping_frame = h2.H2Frame(flags={'A'})
    else:
        ping_frame = h2.H2Frame()

    ping_frame = ping_frame / h2.H2PingFrame(ping_data)
    return ping_frame


def create_go_away_frame(err_code=0, _last_stream_id=0, _stream_id=0):
    """
    create H2 GOAWAY frame to shut down the connection gracefully
    :param err_code:
    :param _last_stream_id:
    :param _stream_id:
    :return:
    """
    go_away_frame = h2.H2Frame(stream_id=_stream_id) / h2.H2GoAwayFrame(last_stream_id=_last_stream_id, error=err_code)
    return go_away_frame


def create_reset_stream_frame(stream_id, error_code=0):
    """
    :param stream_id: Stream ID to cancel
    :param error_code: Error Codes. See https://scapy.readthedocs.io/en/latest/api/scapy.contrib.http2.html#scapy.contrib.http2.H2ErrorCodes # noqa: E501
    :return:
    """
    reset_frame = h2.H2Frame(stream_id=stream_id) / h2.H2ResetFrame(error=error_code)
    return reset_frame
