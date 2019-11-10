import argparse
import socket
import threading
from commons_server import *


def run_server(host, port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        listener.bind((host, port))
        listener.listen(5)
        server_ip = socket.gethostbyname(socket.gethostname())
        print('Lan\'s Server(' + server_ip + ') is listening httpc/httpfs request at port', port)

        server_ip = socket.gethostbyname(socket.gethostname())

        while True:
            conn, addr = listener.accept()
            threading.Thread(target=handle_client, args=(conn, addr, server_ip)).start()
    finally:
        listener.close()


def handle_client(conn, addr, ip):
    """handling httpfs request from port 8080"""
    print('New httpfs client from', addr)
    try:
        client_request = conn.recv(4096)
        if client_request:
            # process the request according to client types
            client_type = get_client_type(client_request)
            if client_type == "httpfs":
                response = get_file_response(client_request, ip)
            elif client_type == "httpc":
                response = get_response(client_request, ip)
            # encode the response
            response = response.encode("utf-8")
    except:
        response = get_error_respose()
        response = response.encode("utf-8")
    finally:
        # send it
        conn.sendall(response)
        conn.close()


parser = argparse.ArgumentParser()
parser.add_argument("--port", help="echo server port", type=int, default=8007)
args = parser.parse_args()
run_server('', args.port)

# port = 8080
# run_server('', port)
