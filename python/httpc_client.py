import argparse
import ipaddress
import sys
from commons_client import *


def http_command_loop(routerhost, routerport, serverhost, serverport):
    while True:
        print("Type your httpc/httpfs command then ENTER. Press Ctrl+C to terminate")

        # get the httpc command line
        command_line = sys.stdin.readline(1024)

        # parse the command line
        client_type = get_client_type(command_line)
        output_file_name = ""

        # get server IP
        server_ip = ipaddress.ip_address(socket.gethostbyname(serverhost))
        if client_type == "httpc":
            request_type, verbosity, header, data, output_file_name, url = parse_httpc_command(command_line)

            # parse url
            host, port, path, query = parse_url(url)

            # construct request
            encoded_request = construct_request(request_type, header, data, host, path, query)

        elif client_type == "httpfs":
            # default local host
            host = "localhost"
            request_type, verbosity, header, port, path = parse_httpfs_command(command_line)

            # construct request
            encoded_request = construct_file_request(request_type, header, path)

        # split encoded request to packets ready to be sent
        packet_list = data_to_packets(encoded_request, server_ip, serverport)

        # send all the packets to server
        send_to_server(routerhost, routerport, server_ip, serverport, packet_list)

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
