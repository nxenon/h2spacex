# <img src="https://github.com/nxenon/h2spacex/assets/61124903/fd6387bf-15e8-4a5d-816b-cf5e079e07cc" width="20%" valign="middle" alt="H2SpaceX" />&nbsp;&nbsp; H2SpaceX

[![pypi: 1.2.0](https://img.shields.io/badge/pypi-1.2.0-8c34eb.svg)](https://pypi.org/project/h2spacex/)
[![Python: 3.8.8](https://img.shields.io/badge/Python->=3.10-blue.svg)](https://www.python.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-006112.svg)](https://github.com/nxenon/h2spacex/blob/main/LICENSE)

HTTP/2 low level library based on Scapy which can be used for Single Packet Attack (Race Condition on H2)

# Dive into Single Packet Attack Article
I wrote an article and published it at InfoSec Write-ups:
- [Dive into Single Packet Attack](https://infosecwriteups.com/dive-into-single-packet-attack-3d3849ffe1d2)

# TODO
- [Single Packet Attack - POST](https://github.com/nxenon/h2spacex/wiki/Quick-Start-Examples)
  - [x] implement
- [Single Packet Attack - GET](https://github.com/nxenon/h2spacex/wiki/GET-SPA-Methods)
  - [x] Content-Length: 1 Method
  - [x] POST Request with x-override-method: GET header
- Response Parsing
  - [x] implement
  - [x] implement threaded response parser
  - [x] add response times in nano seconds for timing attacks
  - [x] Body Decompression
    - [x] gzip
    - [x] br
    - [x] deflate
- [Proxy](https://github.com/nxenon/h2spacex/wiki/Quick-Start-Examples#proxy-example)
  - [x] Socks5 Proxy

# More Research
Some following statements are just ideas and not tested or implemented.

- More Request in a Single Packet
  - Increase MSS (Idea by James Kettle)
  - Out of Order TCP Packets (Idea by James Kettle)
  - IP Fragmentation
- Proxy the Single Packet Request through SOCKS
- Single Packet Attack on GET Requests
  - [Content-Length: 1 Method](https://github.com/nxenon/h2spacex/wiki/GET-SPA-Methods) (Idea by James Kettle)
  - [x-override-method: GET](https://github.com/nxenon/h2spacex/wiki/GET-SPA-Methods) Method (Idea by James Kettle)
  - Index HPACK Headers to Make GET Requests Smaller
  - HEADERS Frame without END_HEADER Flag
  - HEADERS Frame Without Some Pseudo Headers

# Installation
H2SpaceX works with Python 3 (preferred: >=3.10)

    pip install h2spacex


## Error in Installation
if you get errors of scapy:


    pip install --upgrade scapy


# Quick Start
You can import the HTTP/2 TLS Connection and set up the connection. After setting up the connection, you can do other things:

```python
from h2spacex import H2OnTlsConnection

h2_conn = H2OnTlsConnection(
    hostname='http2.github.io',
    port_number=443,
    ssl_log_file_path="PATH_TO_SSL_KEYS.log"  # optional (if you want to log ssl keys to read the http/2 traffic in wireshark)
)

h2_conn.setup_connection()
...
```
see more examples in [Wiki Page](https://github.com/nxenon/h2spacex/wiki/Quick-Start-Examples)

# Examples
See examples which contain some Portswigger race condition examples.

[Examples Page](./examples)

# Enhanced Single Packet Attack Method (Black Hat 2024) for Timing Attacks
James Kettle introduced an improved version of Single Packet Attack in Black Hat 2024 for timing attacks:

![Impvoved Version Image](https://github.com/user-attachments/assets/bf7bf88c-937a-4a95-899b-990bc6fc6a23)

You can implement this method easily using `send_ping_frame()` method.

See this Wiki and `Parse Response (Threaded) + Response Times for Timing Attacks` part:
- [New Method README (WIKI)](https://github.com/nxenon/h2spacex/wiki/SPA-New-Method)

[Improved Version of SPA Sample Exploit](./examples/improved-spa-method.py)
## Reference of Improved Method:
- [Listen to the whispers: web timing attacks that actually work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)

# References & Resources

- [James Kettle DEF CON 31 Presentation](https://youtu.be/tKJzsaB1ZvI?si=6uAuzOt3wjnEGYP6)
- [Portswigger Research Page](https://portswigger.net/research/smashing-the-state-machine#single-packet-attack)
- [HTTP/2 in Action Book](https://www.manning.com/books/http2-in-action)

I also got some ideas from a previous developed library [h2tinker](https://github.com/kspar/h2tinker).

Finally, thanks again to James Kettle for directly helping and pointing some other techniques.
