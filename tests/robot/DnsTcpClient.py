import socket


class DnsTcpClient:

    ROBOT_LIBRARY_SCOPE = 'GLOBAL'

    google_dns_request_byte_parts = [
        b'\x00\x1C',  # 2 byte: DNS request length: 28 byte
        b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00',  # 12 byte
        b'\x06google\x03com\x00',  # 12 byte
        b'\x00\x01\x00\x01'  # 4 byte
    ]

    def __init__(self):
        self.client_socket = None

    def open_tcp_client_connection(self, host, port):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            self.client_socket.connect((host, int(port)))
            print(f"Successfully connected to {host}:{port}")
        except Exception as e:
            raise Exception(f"Failed to open TCP connection: {e}")

    def send_tcp_request_parts(self, *parts):
        if not self.client_socket:
            raise Exception("No TCP connection open. Call 'Open Tcp Client Connection' first.")
        try:
            msg = b''
            for part in parts:
                msg += DnsTcpClient.google_dns_request_byte_parts[int(part) - 1]
            self.client_socket.sendall(msg)
            print(f"Sent parts {' '.join(parts)}, bytes: {len(msg)}")
        except Exception as e:
            raise Exception(f"Failed to send message: {e}")

    def receive_tcp_response(self):
        if not self.client_socket:
            raise Exception("No TCP connection open. Call 'Open Tcp Client Connection' first.")
        msg = b''
        run = True
        dnslen = 0
        while run:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    raise Exception(f"Connection closed!")
                print(f"Received {len(data)} bytes")
                msg += data
                if not dnslen:
                    dnslen = msg[0] * 256 + msg[1]
                    print(f"DNS response length: {dnslen} bytes")
                if len(msg) == dnslen + 2:
                    run = False
            except Exception as e:
                raise Exception(f"Failed to receive message: {e}") from e
        return msg[2:]

    def close_tcp_client_connection(self):
        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None
            print("TCP connection closed.")
