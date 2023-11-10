# <img src="https://github.com/nxenon/h2spacex/assets/61124903/fd6387bf-15e8-4a5d-816b-cf5e079e07cc" width="20%" valign="middle" alt="H2SpaceX" />&nbsp;&nbsp; H2SpaceX

[![pypi: 0.1.16](https://img.shields.io/badge/pypi-0.1.16-8c34eb.svg)](https://pypi.org/project/h2spacex/)
[![Python: 3.10](https://img.shields.io/badge/Python->=3.10-blue.svg)](https://www.python.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-006112.svg)](https://github.com/nxenon/h2spacex/blob/main/LICENSE)

HTTP/2 low level library based on Scapy which can be used for Single Packet Attack (Race Condition on H2)

# TODO

- Single Packet Attack - POST &...
  - [x] implement
  - [ ] test functionality on different H2 frameworks
- Single Packet Attack - GET
  - [ ] implement
  - [ ] Content-Length: 1 Method
  - [ ] POST Request with x-override-method: GET header
  - [ ] test functionality on different H2 frameworks
- Response Parsing
  - [x] implement
  - [ ] implement threaded response parser
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
  - Content-Length: 1 Method (Idea by James Kettle)
  - x-override-method: GET Method (Idea by James Kettle)
  - Index HPACK Headers to Make GET Requests Smaller
  - HEADERS Frame without END_HEADER Flag
  - HEADERS Frame Without Some Pseudo Headers

# Installation
H2SpaceX works with Python 3 (preferred: >=3.10)

    pip install h2spacex

# Quick Start
You can import the HTTP/2 TLS Connection and set up the connection. After setting up the connection, you can do other things:

```python
from h2spacex import H2OnTlsConnection

h2_conn = H2OnTlsConnection(
    hostname='http2.github.io',
    port_number=443
)

h2_conn.setup_connection()
...
```
see more examples in [Wiki Page](https://github.com/nxenon/h2spacex/wiki/Quick-Start-Examples)

# References & Resources

- [James Kettle DEF CON 31 Presentation](https://youtu.be/tKJzsaB1ZvI?si=6uAuzOt3wjnEGYP6)
- [Portswigger Research Page](https://portswigger.net/research/smashing-the-state-machine#single-packet-attack)
- [HTTP/2 in Action Book](https://www.manning.com/books/http2-in-action)

I also got some ideas from a previous developed library [h2tinker](https://github.com/kspar/h2tinker).

Finally, thanks again to James Kettle for directly helping and pointing some other techniques.
