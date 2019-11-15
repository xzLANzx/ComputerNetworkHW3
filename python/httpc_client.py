import argparse
import ipaddress
import socket
import sys
from commons_client import *
from packet import Packet


# def send_request(host, port, request):
#     try:
#         conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         conn.connect((host, port))
#         conn.sendall(request)
#
#         # MSG_WAITALL waits for full request or error
#         response = conn.recv(4096, socket.MSG_WAITALL)
#         response = response.decode("utf-8")
#         return response
#     finally:
#         conn.close()

# packet_type = 0, SYN
# packet_type = 1, SYN-ACK
# packet_type = 2, DATA
def send_udp_request(router_addr, router_port, packet_list):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 10
    try:
        # 0, 1, 2 three-way handshake
        window_start = 3
        window_sent = window_start
        window_size = 8


        # send everything in the window
        for i in range(len(packet_list)):
            conn.sendto(packet_list[i].to_bytes(), (router_addr, router_port))
            print('Send "{}" to router'.format(packet_list[i].payload.decode("utf-8")))

        # Try to receive a response within timeout
        conn.settimeout(timeout)
        print('Waiting for a response')
        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Router: ', sender)
        print('Packet: ', p)
        print('Payload: ' + p.payload.decode("utf-8"))
        return p.payload.decode("utf-8")
    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        conn.close()


def http_command_loop(routerhost, routerport, serverhost, serverport):
    while True:
        print("Type your httpc/httpfs command then ENTER. Press Ctrl+C to terminate")

        # get the httpc command line
        command_line = sys.stdin.readline(1024)

        # parse the command line
        client_type = get_client_type(command_line)
        output_file_name = ""
        if client_type == "httpc":
            request_type, verbosity, header, data, output_file_name, url = parse_httpc_command(command_line)

            # parse url
            host, port, path, query = parse_url(url)

            # construct request
            encoded_request = construct_request(request_type, header, data, host, path, query)

            # get server IP
            server_ip = ipaddress.ip_address(socket.gethostbyname(serverhost))

            # split encoded request to packets ready to be sent
            packet_list = data_to_packets(encoded_request, server_ip, serverport)

            # send all the packets to server
            send_udp_request(routerhost, routerport, packet_list)

        elif client_type == "httpfs":
            # default local host
            host = "localhost"
            request_type, verbosity, header, port, path = parse_httpfs_command(command_line)
            # construct request
            encoded_request = construct_file_request(request_type, header, path)

        # # get and process response
        # decoded_response = send_udp_request(routerhost, routerport, serverhost, serverport, encoded_request)
        # status_code = get_status_code(decoded_response)
        # print_to_console(decoded_response, verbosity)
        # print_to_file(output_file_name, decoded_response)
        #
        # # process redirection
        # while status_code == "301" or status_code == "302":
        #     redirect_path = get_redirect_path(decoded_response)
        #     encoded_request = construct_request(request_type, header, data, host, redirect_path, query)
        #     decoded_response = send_udp_request(routerhost, routerport, serverhost, serverport, encoded_request)
        #     status_code = get_status_code(decoded_response)
        #     print_to_console(decoded_response, verbosity)
        #     print_to_file(output_file_name, decoded_response)


# def http_command_loop():
#     while True:
#         print("Type your httpc/httpfs command then ENTER. Press Ctrl+C to terminate")
#
#         # get the httpc command line
#         command_line = sys.stdin.readline(1024)
#
#         # parse the command line
#         client_type = get_client_type(command_line)
#         output_file_name = ""
#         if client_type == "httpc":
#             request_type, verbosity, header, data, output_file_name, url = parse_httpc_command(command_line)
#             # parse url
#             host, port, path, query = parse_url(url)
#             # construct request
#             request = construct_request(request_type, header, data, host, path, query)
#         elif client_type == "httpfs":
#             # default local host
#             host = "localhost"
#             request_type, verbosity, header, port, path = parse_httpfs_command(command_line)
#             # construct request
#             request = construct_file_request(request_type, header, path)
#
#         # get and process response
#         response = send_request(host, port, request)
#         status_code = get_status_code(response)
#         print_to_console(response, verbosity)
#         print_to_file(output_file_name, response)
#
#         # process redirection
#         while status_code == "301" or status_code == "302":
#             redirect_path = get_redirect_path(response)
#             request = construct_request(request_type, header, data, host, redirect_path, query)
#             response = send_request(host, port, request)
#             status_code = get_status_code(response)
#             print_to_console(response, verbosity)
#             print_to_file(output_file_name, response)


# if __name__ == '__main__':
#     http_command_loop()
# Usage:
# python echoclient.py --routerhost localhost --routerport 3000 --serverhost localhost --serverport 8007

parser = argparse.ArgumentParser()
parser.add_argument("--routerhost", help="router host", default="localhost")
parser.add_argument("--routerport", help="router port", type=int, default=3000)

parser.add_argument("--serverhost", help="server host", default="localhost")
parser.add_argument("--serverport", help="server port", type=int, default=8007)
args = parser.parse_args()

http_command_loop(args.routerhost, args.routerport, args.serverhost, args.serverport)

# run_client(args.routerhost, args.routerport, args.serverhost, args.serverport)
