import argparse
import ipaddress
import sys
import threading

from commons_client import *
from packet import Packet

# global vars for receiving
rcv_window_start = 0
rcv_window_size = 8
rcv_window_end = rcv_window_start + rcv_window_size
delivered = [None] * rcv_window_size
expected_data_packets_num = 0
received_pkt_count = 0
received_all = False

# global vars for sending
expected_acks_list = []
un_acked_packets_list = []
send_window_size = 8
send_window_start = 0
window_sent = send_window_start - 1
send_window_end = send_window_start + send_window_size


def send_to_server(router_addr, router_port, server_ip, server_port, packet_list):
    # three-way handshake
    data_packet_num = len(packet_list)
    three_way_handshake(router_addr, router_port, server_ip, server_port, data_packet_num)

    # send ack together with the first data packet
    send_ack_packet(router_addr, router_port, server_ip, server_port)
    # send all un-send packets in window
    global window_sent
    packets_num = len(packet_list)
    while window_sent < len(packet_list) - 1:
        i = window_sent + 1
        while i < send_window_end:
            global expected_acks_list, un_acked_packets_list
            expected_acks_list.append(packet_list[i].seq_num)
            un_acked_packets_list.append(packet_list[i])
            threading.Thread(target=send_single_udp_packet, args=(router_addr, router_port, packet_list[i], packets_num)).start()
            i = i + 1
            window_sent = window_sent + 1

    receive_from_server()


def receive_from_server():
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn.bind(('', 41830))
    try:
        while True:
            data, sender = conn.recvfrom(1024)
            handle_udp_server(conn, data, sender)
    finally:
        conn.close()


# handling the udp packets from server
def handle_udp_server(conn, data, sender):
    try:
        p = Packet.from_bytes(data)

        global delivered, expected_data_packets_num, received_pkt_count, received_all
        if p.packet_type == 3:
            if p.seq_num == 0:
                expected_data_packets_num = int(p.payload.decode('utf-8'))

            # receiving data, # re-construct the packet
            global rcv_window_start, rcv_window_end
            if p.seq_num - 1 == rcv_window_start:
                print('Accept packet {}'.format(p.seq_num))
                if delivered[p.seq_num - 1] is None:
                    received_pkt_count = received_pkt_count + 1
                delivered[p.seq_num - 1] = p

                i = rcv_window_start
                while i < len(delivered) and delivered[i] is not None:
                    i = i + 1
                shift = i - rcv_window_start

                print('Shift the window by {}'.format(shift))
                rcv_window_start = rcv_window_start + shift
                rcv_window_end = rcv_window_end + shift

                print('Extend the delivered list by {}'.format(shift))
                extension = [None] * shift
                delivered.extend(extension)

            elif rcv_window_start < p.seq_num - 1 < rcv_window_end:
                print('Accept packet {}'.format(p.seq_num))
                if delivered[p.seq_num - 1] is None:
                    received_pkt_count = received_pkt_count + 1
                delivered[p.seq_num - 1] = p
            else:
                print('Discard packet {}'.format(p.seq_num))

            # send ACK
            p.packet_type = 2
            conn.sendto(p.to_bytes(), sender)

            if received_pkt_count == expected_data_packets_num and received_all is False:
                received_all = True
                # concatenate the data of all received packets
                i = 0
                decoded_response = ''
                while i < expected_data_packets_num:
                    decoded_response = decoded_response + delivered[i].payload.decode('utf-8')
                    i = i + 1
                print(decoded_response)

    except Exception as e:
        print("Error: ", e)


def send_single_udp_packet(router_addr, router_port, packet, packets_num):
    try:
        timeout = 2
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.sendto(packet.to_bytes(), (router_addr, router_port))
        print('Send packet "{}" to router.'.format(packet.seq_num))

        conn.settimeout(timeout)
        print('Waiting for packet {} ack.'.format(packet.seq_num))

        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)

        if p.seq_num == un_acked_packets_list[0].seq_num:
            expected_acks_list[0] = -1

            # count the num of acked packets
            acked_count = 0
            while acked_count < len(expected_acks_list) and expected_acks_list[acked_count] == -1:
                acked_count = acked_count + 1

            # update the expected_acks_list and unacked_packets_list
            counter = acked_count
            while counter > 0:
                expected_acks_list.pop(0)
                un_acked_packets_list.pop(0)
                counter = counter - 1
            print('Packet {} ~ {} correctly acked.'.format(p.seq_num, (p.seq_num + acked_count - 1) % send_window_size))

            # shift window
            global send_window_start, send_window_end
            send_window_start = send_window_start + acked_count
            send_window_end = min(send_window_end + acked_count, packets_num)
            print('Sending window shifts to [{}, {})'.format(send_window_start, send_window_end))

        elif p.seq_num != un_acked_packets_list[0].seq_num:
            # update the un_acked
            pos = expected_acks_list.index(p.seq_num)
            expected_acks_list[pos] = -1
            # print('Packet {} acked'.format(p.seq_num))

    except socket.timeout:
        print('Packet {} no response after {}s.'.format(packet.seq_num, timeout))
        send_single_udp_packet(router_addr, router_port, packet, packets_num)
    finally:
        print('Packet {} Connection closed.\n'.format(packet.seq_num))
        conn.close()


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

        print('send_to_server() called.')

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
