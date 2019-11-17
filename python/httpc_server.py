import argparse
import socket
from packet import Packet

window_start = 0
window_size = 8
window_end = window_start + window_size
delivered = [None] * window_size


def run_udp_server(port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        conn.bind(('', port))
        print('Echo server is listening at', port)
        while True:
            data, sender = conn.recvfrom(1024)
            handle_udp_client(conn, data, sender)
            # threading.Thread(target=handle_udp_client, args=(conn, data, sender)).start()
    finally:
        conn.close()


def handle_udp_client(conn, data, sender):
    try:
        p = Packet.from_bytes(data)
        # print("Router: ", sender)
        # print("Packet: ", p)
        # print("Payload: ", p.payload.decode("utf-8"))

        # re-construct the packet
        global delivered, window_start, window_end
        if p.seq_num == window_start:
            print('Accept packet {}'.format(p.seq_num))
            delivered[p.seq_num] = p

            i = window_start
            while i < len(delivered) and delivered[i] is not None:
                i = i + 1
            shift = i - window_start

            print('Shift the window by {}'.format(shift))
            window_start = window_start + shift
            window_end = window_end + shift

            print('Extend the delivered list by {}'.format(shift))
            extension = [None] * shift
            delivered.extend(extension)

        elif window_start < p.seq_num < window_end:
            print('Accept packet {}'.format(p.seq_num))
            delivered[p.seq_num] = p
        else:
            print('Discard packet {}'.format(p.seq_num))

        # process payload
        # replace the payload in the sent back packet with the new response
        # send the packets back

        # How to send a reply.
        # The peer address of the packet p is the address of the client already.
        # We will send the same payload of p. Thus we can re-use either `data` or `p`.
        conn.sendto(p.to_bytes(), sender)

    except Exception as e:
        print("Error: ", e)


def print_delivered():
    for packet in delivered:
        print(packet.seq_num, end=' ')


# def run_server(host, port):
#     listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
#     try:
#         listener.bind((host, port))
#         listener.listen(5)
#         server_ip = socket.gethostbyname(socket.gethostname())
#         print('Lan\'s Server(' + server_ip + ') is listening httpc/httpfs request at port', port)
#
#         server_ip = socket.gethostbyname(socket.gethostname())
#
#         while True:
#             conn, addr = listener.accept()
#             threading.Thread(target=handle_client, args=(conn, addr, server_ip)).start()
#     finally:
#         listener.close()
#
#
# def handle_client(conn, addr, ip):
#     """handling httpfs request from port 8080"""
#     print('New httpfs client from', addr)
#     try:
#         client_request = conn.recv(4096)
#         if client_request:
#             # process the request according to client types
#             client_type = get_client_type(client_request)
#             if client_type == "httpfs":
#                 response = get_file_response(client_request, ip)
#             elif client_type == "httpc":
#                 response = get_response(client_request, ip)
#             # encode the response
#             response = response.encode("utf-8")
#     except:
#         response = get_error_respose()
#         response = response.encode("utf-8")
#     finally:
#         # send it
#         conn.sendall(response)
#         conn.close()


parser = argparse.ArgumentParser()
parser.add_argument("--port", help="echo server port", type=int, default=8007)
args = parser.parse_args()
run_udp_server(args.port)

# port = 8080
# run_server('', port)
