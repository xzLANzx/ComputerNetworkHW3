import argparse
import ipaddress
import socket
import sys
from commons_client import *
from packet import Packet


def sender(routerhost, routerport, packet_list):
    window_start = 0
    window_sent = window_start - 1
    window_size = 8
    window_end = window_start + window_size

    # send all the unsent packets in window
    i = window_sent + 1
    while i < window_end:
        send_udp_request(routerhost, routerport, packet_list[i])
        i = i + 1


def send_udp_request(router_addr, router_port, packet):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 5
    try:
        conn.sendto(packet.to_bytes(), (router_addr, router_port))
        print('Send packet "{}" to router'.format(packet.seq_num))

        # Try to receive a response within timeout
        conn.settimeout(timeout)
        print('Waiting for packet {} ack'.format(packet.seq_num))

        # get response, process response
        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print('Packet {} correctly acked.'.format(p.seq_num))

    except socket.timeout:
        print('No response after {}s'.format(timeout))
        # resend the request
        print('Re-send packet {}'.format(packet.seq_num))
        send_udp_request(router_addr, router_port, packet)
    finally:
        print('Packet {} connection closed.\n'.format(packet.seq_num))
        return packet.seq_num
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
            sender(routerhost, routerport, packet_list)

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
