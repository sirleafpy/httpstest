# -*- coding: utf-8 -*-
import os
import sys
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

certs_dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "certs"))
# 服务端证书和私钥
server_certs = os.path.join(certs_dir_path, "server-cert.cer")
server_key = os.path.join(certs_dir_path, "server-key.key")
# 客户端证书
client_certs = os.path.join(certs_dir_path, "client-cert.cer")

if not os.path.exists(server_certs):
    print(f"File does not exist, {server_certs}")
    sys.exit()

if not os.path.exists(server_key):
    print(f"File does not exist, {server_key}")
    sys.exit()

if not os.path.exists(client_certs):
    print(f"File does not exist, {client_certs}")
    sys.exit()


class RequestHandler(BaseHTTPRequestHandler):
    def _writeheaders(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def do_GET(self):
        self._writeheaders()
        self.wfile.write("OK".encode("utf-8"))


def main():
    if len(sys.argv) != 2:
        port = 443
    else:
        port = sys.argv[1]
    server_address = ("0.0.0.0", int(port))
    server = HTTPServer(server_address, RequestHandler)
    # 双向校验
    server.socket = ssl.wrap_socket(server.socket, certfile=server_certs, server_side=True,
                                    keyfile=server_key,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=client_certs,
                                    do_handshake_on_connect=False
                                    )
    print(f"Starting server, listen at: {server_address[0]}:{server_address[1]}")
    server.serve_forever()


if __name__ == "__main__":
    main()
