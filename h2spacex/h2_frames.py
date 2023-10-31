import scapy.contrib.http2 as h2
from scapy.packet import NoPayload


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


def get_headers_string_from_headers_frame(headers_frame):
    """
    get string of response headers from headers frame
    :param headers_frame:
    :return:
    """
    headers_table = h2.HPackHdrTable()
    headers_string = headers_table.gen_txt_repr(headers_frame.hdrs)
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
                headers_string = get_headers_string_from_headers_frame(f)
                print(f'------ Headers Stream ID: {f.stream_id} ------')
                print(headers_string)

            elif isinstance(f.payload, h2.H2DataFrame):
                print(f'------ Data Stream ID: {f.stream_id} ------')
                print(str(f.data))

            elif isinstance(f.payload, h2.H2SettingsFrame):
                if socket_obj is not None:
                    print('* got a Settings frame from server')
                    settings_frame = create_settings_frame(is_ack=1)
                    socket_obj.send(bytes(settings_frame))
                    print('* client sent ACK for server Settings')

            elif isinstance(f.payload, h2.H2WindowUpdateFrame):
                pass

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
